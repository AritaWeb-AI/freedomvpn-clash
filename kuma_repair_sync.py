#!/usr/bin/env python3
"""Sync Freedom VPN nodes into Uptime Kuma.

Goal
----
You created many new VPN VMs, but they are not added to Uptime Kuma.
This script reads node IPs (and optional names) and ensures Kuma has TCP monitors
for ports 10101 and 10105 for each node.

Inputs (choose one)
-------------------
1) Read from Clash YAML (recommended):
   python kuma_repair_sync.py --yaml .\\www\\freedom.yaml

2) Provide IPs directly:
   python kuma_repair_sync.py --ips 1.2.3.4,5.6.7.8

3) Provide a text file with one IP per line:
   python kuma_repair_sync.py --ip-file ips.txt

Environment (.env)
------------------
Required:
  KUMA_URL=https://status.freedomvpn.app
  KUMA_USER=...
  KUMA_PASS=...

Optional:
  KUMA_ENABLED=1            (default 1)
  KUMA_SSL_VERIFY=1         (default 1)
  KUMA_NOTIFICATION_IDS=1,2 (attach notifications to new/updated monitors)

Behavior
--------
- Detects existing monitors and will NOT create duplicates.
- If a monitor exists but has a different name, it will update it.
- Creates/ensures two TCP monitors per node:
    <NAME>-10101  (hostname=<IP>, port=10101)
    <NAME>-10105  (hostname=<IP>, port=10105)

"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# -----------------------------
# Minimal .env loader (no deps)
# -----------------------------

def load_dotenv_minimal(dotenv_path: Path) -> Dict[str, str]:
    """Load KEY=VALUE lines from a .env file. Returns a dict."""
    env: Dict[str, str] = {}
    if not dotenv_path.exists():
        return env

    for raw in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k:
            env[k] = v
    return env


def env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def parse_int_list(csv: Optional[str]) -> Optional[List[int]]:
    if not csv:
        return None
    out: List[int] = []
    for part in csv.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(part))
        except ValueError:
            pass
    return out or None


# -----------------------------
# Parse nodes from YAML
# -----------------------------

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_nodes_from_yaml(yaml_path: Path) -> List[Tuple[str, str]]:
    """Return list of (node_name, ip). Best-effort.

    We look for proxy blocks like:
      - name: "SG-03 SS"
        server: 154.26.134.142

    We collapse names to the base node (e.g., SG-03).
    """
    text = yaml_path.read_text(encoding="utf-8", errors="ignore")

    nodes: Dict[str, str] = {}

    # Match name + server within a small window.
    # We intentionally keep this permissive to survive formatting changes.
    pattern = re.compile(
        r"-\s*name:\s*(?:\"|')?(?P<name>[^\n\"']+)(?:\"|')?\s*\n(?:(?:.|\n){0,200}?)\s*server:\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    )

    for m in pattern.finditer(text):
        raw_name = m.group("name").strip()
        ip = m.group("ip").strip()
        # Normalize name: "SG-03 SS" -> "SG-03"
        base = raw_name
        base = re.sub(r"\s+(SS|VMESS)\b.*$", "", base, flags=re.IGNORECASE).strip()
        base = base.strip('"').strip("'")
        if base and ip:
            # Prefer stable base name; keep first IP seen for that base.
            nodes.setdefault(base, ip)

    # Fallback: if pattern fails, just extract IPs and name them by IP
    if not nodes:
        for ip in sorted(set(_IP_RE.findall(text))):
            nodes[ip] = ip

    # Return sorted for stable output
    return sorted(nodes.items(), key=lambda t: t[0])


# -----------------------------
# Kuma sync
# -----------------------------

def ensure_kuma_monitors(nodes: List[Tuple[str, str]], dry_run: bool = False) -> None:
    try:
        from uptime_kuma_api import UptimeKumaApi
    except Exception as e:
        raise RuntimeError(
            "Missing dependency uptime-kuma-api. Install with: pip install uptime-kuma-api"
        ) from e

    enabled = env_bool("KUMA_ENABLED", True)
    if not enabled:
        print("[kuma] KUMA_ENABLED=0 -> skipping")
        return

    url = (os.getenv("KUMA_URL") or "").strip()
    user = (os.getenv("KUMA_USER") or "").strip()
    pw = (os.getenv("KUMA_PASS") or "").strip()
    ssl_verify = env_bool("KUMA_SSL_VERIFY", True)
    notif_ids = parse_int_list(os.getenv("KUMA_NOTIFICATION_IDS"))

    if not url or not user or not pw:
        raise RuntimeError("KUMA_URL/KUMA_USER/KUMA_PASS are not set (or not loaded from .env).")

    print(f"[kuma] URL={url} ssl_verify={ssl_verify} nodes={len(nodes)} dry_run={dry_run}")

    with UptimeKumaApi(url, ssl_verify=ssl_verify) as api:
        api.login(user, pw)
        monitors = api.get_monitors()

        # Index existing TCP monitors by (hostname, port)
        by_host_port: Dict[Tuple[str, int], dict] = {}
        by_name: Dict[str, dict] = {}

        for m in monitors:
            by_name[str(m.get("name"))] = m
            # Different Kuma/API versions label the TCP connect monitor as
            # "port" (Kuma UI: Port) or sometimes "tcp".
            m_type = str(m.get("type", "")).lower()
            if m_type in ("port", "tcp"):
                host = str(m.get("hostname") or "").strip()
                port = int(m.get("port") or 0)
                if host and port:
                    by_host_port[(host, port)] = m

        def _ensure_one(mon_name: str, ip: str, port: int) -> None:
            payload = dict(
                # IMPORTANT: uptime-kuma-api v1.2.1 expects the TCP connect
                # monitor type to be "port" (NOT "tcp").
                type="port",
                name=mon_name,
                hostname=ip,
                port=int(port),
                interval=60,
                retryInterval=60,
            )
            if notif_ids:
                payload["notificationIDList"] = notif_ids

            existing = by_host_port.get((ip, int(port)))
            if existing is None:
                # fallback by name
                existing = by_name.get(mon_name)

            if existing is None:
                print(f"[add] {mon_name} -> {ip}:{port}")
                if not dry_run:
                    res = api.add_monitor(**payload)
                    mid = res.get("monitorId") or res.get("monitorID") or res.get("id")
                    if mid is None:
                        raise RuntimeError(f"Kuma add_monitor returned no id for {mon_name}: {res}")
                    mid = int(mid)
                    # update indices
                    by_name[mon_name] = {"id": mid, **payload, "type": "port"}
                    by_host_port[(ip, int(port))] = by_name[mon_name]
            else:
                mid = int(existing["id"])
                # Update if name mismatch or host/port mismatch
                needs_update = False
                if str(existing.get("name")) != mon_name:
                    needs_update = True
                if str(existing.get("hostname") or "").strip() != ip:
                    needs_update = True
                if int(existing.get("port") or 0) != int(port):
                    needs_update = True

                if needs_update:
                    print(f"[edit] {mid} {existing.get('name')} -> {mon_name} ({ip}:{port})")
                    if not dry_run:
                        api.edit_monitor(mid, **payload)
                else:
                    print(f"[ok]  {mon_name} ({ip}:{port})")

        for node_name, ip in nodes:
            _ensure_one(f"{node_name}-10101", ip, 10101)
            _ensure_one(f"{node_name}-10105", ip, 10105)


# -----------------------------
# CLI
# -----------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Repair/sync Uptime Kuma monitors for Freedom VPN nodes")
    p.add_argument("--yaml", type=str, default="", help="Path to freedom.yaml to extract nodes")
    p.add_argument("--ips", type=str, default="", help="Comma-separated IP list")
    p.add_argument("--ip-file", type=str, default="", help="Text file with one IP per line")
    p.add_argument("--dotenv", type=str, default=".env", help="Path to .env (default: .env in CWD)")
    p.add_argument("--dry-run", action="store_true", help="Print actions without calling Kuma")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    # Load .env into os.environ (needed on Windows)
    dotenv_path = Path(args.dotenv).expanduser().resolve()
    env = load_dotenv_minimal(dotenv_path)
    for k, v in env.items():
        os.environ.setdefault(k, v)

    nodes: List[Tuple[str, str]] = []

    if args.yaml:
        ypath = Path(args.yaml).expanduser().resolve()
        if not ypath.exists():
            print(f"[error] YAML not found: {ypath}", file=sys.stderr)
            return 2
        nodes = parse_nodes_from_yaml(ypath)

    elif args.ips:
        ips = [x.strip() for x in args.ips.split(",") if x.strip()]
        nodes = [(ip, ip) for ip in ips]

    elif args.ip_file:
        fpath = Path(args.ip_file).expanduser().resolve()
        if not fpath.exists():
            print(f"[error] IP file not found: {fpath}", file=sys.stderr)
            return 2
        ips: List[str] = []
        for line in fpath.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips.extend(_IP_RE.findall(line) or [])
        ips = sorted(set(ips))
        nodes = [(ip, ip) for ip in ips]

    else:
        print("[error] Provide one of: --yaml, --ips, --ip-file", file=sys.stderr)
        return 2

    if not nodes:
        print("[warn] No nodes found")
        return 0

    print("[nodes]")
    for n, ip in nodes:
        print(f"  - {n} -> {ip}")

    ensure_kuma_monitors(nodes, dry_run=bool(args.dry_run))
    print("[done]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
