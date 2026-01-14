#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import uuid
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import re
import secrets
import string
import socket

from .bootstrap import bootstrap_xray
from .contabo_api import ContaboClient
from .env import load_settings_from_env
from .errors import FVPNError
from .log import Logger
from .models import Node
from .ssh_utils import ensure_authorized_keys_has, set_hostname
from .yaml_clash import write_yaml, scan_last_numbers_from_yaml


def tcp_check(ip: str, port: int, timeout: int = 5) -> None:
    with socket.create_connection((ip, port), timeout=timeout):
        return


REGIONS = ["EU", "UK", "JPN", "SIN", "US-central", "US-east", "US-west", "AUS", "IND"]

COMMON_PRODUCTS = [
    ("V91", "VPS 10 NVMe (75GB)"),
    ("V92", "VPS 10 SSD (150GB)"),
    ("V94", "VPS 20 NVMe (100GB)"),
    ("V95", "VPS 20 SSD (200GB)"),
    ("V97", "VPS 30 NVMe (200GB)"),
    ("V98", "VPS 30 SSD (400GB)"),
]

STATE_PATH = Path(".fvpn/state.json")

REGION_PREFIX = {
    "SIN": "SG",
    "UK": "UK",
    "EU": "EU",
    "JPN": "JP",
    "US-central": "USC",
    "US-east": "USE",
    "US-west": "USW",
    "AUS": "AU",
    "IND": "IN",
}


# OS / Image presets (no typing needed)
IMAGE_PRESETS: List[Tuple[str, str]] = [
    ("Ubuntu 22.04 (Jammy)", "ubuntu-22.04"),
    ("Ubuntu (all)", "Ubuntu"),
    ("Debian", "Debian"),
    ("Windows Server", "Windows"),
    ("AlmaLinux", "AlmaLinux"),
    ("Rocky", "Rocky"),
    ("CentOS", "CentOS"),
    ("Show ALL images", ""),
    ("Custom search term (type)", "__CUSTOM__"),
]


def _preset_map() -> Dict[str, str]:
    return {k: v for k, v in IMAGE_PRESETS}


def _load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {"last": {}}


def _save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _merge_last_numbers_from_yaml(state: dict, yaml_path: str) -> None:
    p = Path(yaml_path)
    if not p.exists():
        return
    txt = p.read_text(encoding="utf-8", errors="replace")
    last = scan_last_numbers_from_yaml(txt)
    state.setdefault("last", {})
    for k, v in last.items():
        state["last"][k] = max(int(state["last"].get(k, 0)), int(v))


def _next_name(region: str, state: dict) -> str:
    pfx = REGION_PREFIX.get(region, region[:2].upper())
    state.setdefault("last_used", {})
    n = int(state["last_used"].get(pfx, 0)) + 1
    state["last_used"][pfx] = n
    return f"{pfx}-{n:02d}"



def _choose(prompt: str, options: List[str], default_idx: int = 0) -> str:
    print(f"\n{prompt}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    s = input(f"Select (default {default_idx + 1}): ").strip()
    if not s:
        return options[default_idx]
    return options[int(s) - 1]


def _ask_int(prompt: str, default: int) -> int:
    s = input(f"{prompt} (default: {default}): ").strip()
    return int(s) if s else default


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Create Contabo VPS + bootstrap FreedomVPN + update freedom.yaml (overwrite + backups)")
    p.add_argument("--count", type=int, default=int(os.getenv("FVPN_COUNT", "1")), help="How many VMs to create")
    p.add_argument("--region", default=os.getenv("FVPN_REGION", ""), choices=REGIONS, help="Contabo region")
    p.add_argument("--product-id", default=os.getenv("FVPN_PRODUCT_ID", "V94"), help="Contabo productId (e.g., V94)")
    p.add_argument("--image-search", default=os.getenv("FVPN_IMAGE_SEARCH", "Ubuntu 22.04"), help="OS search term")
    p.add_argument("--image-id", default=os.getenv("FVPN_IMAGE_ID", ""), help="Exact imageId (skips search/pick)")
    p.add_argument("--period", type=int, default=int(os.getenv("FVPN_PERIOD", "1")), help="Contract period months")

    # VPN creds
    p.add_argument("--ss-password", default=os.getenv("SS_PASSWORD", ""), help="Shadowsocks password (required)")
    p.add_argument("--vmess-uuid", default=os.getenv("VMESS_UUID", ""), help="VMess UUID (if blank, generate per-VM)")

    # Output / behavior
    p.add_argument("--installer-url", default=os.getenv("FVPN_INSTALLER_URL", ""), help="Bootstrap installer URL")
    p.add_argument("--quiet", action="store_true", help="Reduce console output")
    p.add_argument("--debug", action="store_true", help="Debug output")

    # YAML overwrite path (default: freedom.yaml)
    p.add_argument("--yaml-out", default=os.getenv("FVPN_YAML_OUT", "freedom.yaml"), help="YAML path (will be overwritten; backups kept)")
    p.add_argument("--yaml-template", default=os.getenv("FVPN_YAML_TEMPLATE", ""), help="Optional template YAML path")
    p.add_argument("--group-name", default=os.getenv("FVPN_GROUP_NAME", "Freedom VPN"), help="Proxy group name")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    log = Logger(quiet=args.quiet, debug=args.debug)

    try:
        st = load_settings_from_env()
        c = ContaboClient(log=log)

        token = c.get_access_token(st.contabo_client_id, st.contabo_client_secret, st.contabo_api_user, st.contabo_api_password)
        log.ok("Auth OK")

        # Ensure Shadowsocks password:
        # - If SS_PASSWORD (or --ss-password) is missing, generate a strong one
        # - Save it into .env for future runs (stable)
        ss_password = (getattr(args, "ss_password", "") or os.getenv("SS_PASSWORD", "")).strip()

        def _upsert_env(env_path: str, key: str, value: str) -> None:
            p = Path(env_path)
            lines: list[str] = []
            if p.exists():
                lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()

            # replace existing KEY=... (ignore commented lines)
            pat = re.compile(rf"^\s*{re.escape(key)}\s*=")
            replaced = False
            for i, line in enumerate(lines):
                if line.lstrip().startswith("#"):
                    continue
                if pat.match(line):
                    lines[i] = f"{key}={value}"
                    replaced = True
                    break

            if not replaced:
                if lines and lines[-1].strip() != "":
                    lines.append("")
                lines.append(f"{key}={value}")

            p.write_text("\n".join(lines) + "\n", encoding="utf-8")

        if not ss_password:
            alphabet = string.ascii_letters + string.digits
            ss_password = "".join(secrets.choice(alphabet) for _ in range(24))
            _upsert_env(".env", "SS_PASSWORD", ss_password)
            log.info("SS_PASSWORD was missing → generated and saved into .env ✅")

        # Propagate the final password back to args so downstream code uses the correct value.
        args.ss_password = ss_password




        installer_url = (args.installer_url.strip() or st.installer_url).strip()

        # Interactive UX (menu) when you run with no args
        interactive = (len(sys.argv) == 1)
        if interactive:
            args.region = _choose("Region?", REGIONS, default_idx=REGIONS.index("SIN"))

            prod_options = [f"{pid} — {label}" for pid, label in COMMON_PRODUCTS]
            pick = _choose("Product?", prod_options, default_idx=2)  # V94
            args.product_id = pick.split(" — ", 1)[0]

            args.count = _ask_int("How many VMs to create?", 1)

            default_yaml = "freedom.yaml"
            y = input(f"YAML file to update (overwrite) (default: {default_yaml}): ").strip()
            args.yaml_out = y or default_yaml
            args.yaml_template = args.yaml_out  # keep style

        # Ensure SSH secrets once
        sid1 = c.ensure_ssh_secret(token, st.ssh_secret1_name, st.ssh_key1_pub)
        sid2 = c.ensure_ssh_secret(token, st.ssh_secret2_name, st.ssh_key2_pub)

        # Resolve image (interactive picker)
        image_id = args.image_id.strip()


        def _try_default_ubuntu_22() -> tuple[str, str] | tuple[None, None]:
            """
            Try a few Contabo image search terms that commonly represent Ubuntu 22.04.
            Returns (image_id, image_name) if found, else (None, None).
            """
            candidates = [
                "ubuntu-22.04",
                "Ubuntu 22.04",
                "Ubuntu",
                "ubuntu",
            ]
            for term in candidates:
                imgs = c.list_images(token, term, size=50, page=1)
                if imgs:
                    return str(imgs[0].get("imageId")), str(imgs[0].get("name", ""))
            return None, None

        def _browse_images(term: str) -> str:
            """Paged image browser. Numeric navigation only (no typing required)."""
            preset = _preset_map()
            page = 1

            while True:
                imgs = c.list_images(token, term, size=50, page=page)

                # If search yields nothing, fall back to full list automatically.
                if not imgs and page == 1 and term:
                    print("No results for this search. Switching to the full image list...")
                    term = ""
                    page = 1
                    continue

                if not imgs:
                    print("No more results on this page.")
                    page = max(1, page - 1)
                    continue

                title = term if term else "ALL standard images"
                print(f"\nImages ({title}) — page {page}")
                for i, im in enumerate(imgs, 1):
                    name = im.get("name", "")
                    iid = im.get("imageId", "")
                    print(f"  {i}) {name}  (id={iid})")

                print("\n  0) Next page   9) Prev page   7) Change filter")
                s = input("Select image (Enter=1): ").strip()

                if s == "":
                    return str(imgs[0].get("imageId"))
                if s == "0":
                    page += 1
                    continue
                if s == "9":
                    page = max(1, page - 1)
                    continue
                if s == "7":
                    label = _choose("Filter preset?", [k for k, _ in IMAGE_PRESETS], default_idx=0)
                    new_term = preset[label]
                    if new_term == "__CUSTOM__":
                        new_term = input("Search term: ").strip()
                    term = new_term
                    page = 1
                    continue
                if s.isdigit():
                    idx = int(s)
                    if 1 <= idx <= len(imgs):
                        return str(imgs[idx - 1].get("imageId"))
                print("Invalid selection. Try again.")


        if not image_id:
            if interactive:
                # No typing required: choose how you want to pick the OS image.
                mode = _choose(
                    "OS image selection?",
                    [
                        "Default (Ubuntu 22.04 first result)",
                        "Browse Ubuntu 22.04 (paged)",
                        "Browse ALL images (paged)",
                        "Pick from presets (paged)",
                    ],
                    default_idx=0,
                )

                if mode.startswith("Default"):
                    image_id, image_name = _try_default_ubuntu_22()
                    if image_id:
                        log.info(f"Using image: {image_name} (id={image_id})")
                    else:
                        log.info("No direct match for Ubuntu 22.04 found. Opening paged browser (Ubuntu) …")
                        image_id = _browse_images("Ubuntu")
                elif mode.startswith("Browse Ubuntu"):
                    # Contabo naming is often ubuntu-22.04; browsing Ubuntu is more reliable than an exact phrase.
                    image_id = _browse_images("Ubuntu")
                elif mode.startswith("Browse ALL"):
                    image_id = _browse_images("")
                else:
                    label = _choose("Preset?", [k for k, _ in IMAGE_PRESETS], default_idx=0)
                    term = _preset_map()[label]
                    if term == "__CUSTOM__":
                        term = input("Search term: ").strip()
                    image_id = _browse_images(term)

                if not image_id:
                    raise FVPNError("No image selected.")
            else:
                # non-interactive: keep simple behavior
                imgs = c.list_images(token, args.image_search, size=50, page=1)
                if not imgs and args.image_search.strip().lower() == "ubuntu 22.04":
                    imgs = c.list_images(token, "ubuntu-22.04", size=50, page=1) or c.list_images(token, "Ubuntu", size=50, page=1)
                if not imgs:
                    raise FVPNError(
                        f"No images found for '{args.image_search}'. Run without args (menu), set FVPN_IMAGE_SEARCH (e.g. ubuntu-22.04), or pass --image-id."
                    )
                image_id = str(imgs[0].get("imageId"))
                log.info(f"Using image: {imgs[0].get('name')} (id={image_id})")


        # Naming state: merge from YAML + local state
        state = _load_state()
        yaml_source = (args.yaml_template.strip() or args.yaml_out).strip()
        _merge_last_numbers_from_yaml(state, yaml_source)

        created_nodes: List[Node] = []
        created_summary: List[Tuple[str, str]] = []

        for _ in range(args.count):
            display_name = _next_name(args.region, state)

            instance_id = c.create_instance(
                token,
                region=args.region,
                product_id=args.product_id,
                image_id=image_id,
                ssh_secret_ids=[sid1, sid2],
                display_name=display_name,
                period_months=args.period,
            )
            log.ok(f"Created {display_name} (instanceId={instance_id})")

            ip = c.wait_for_ipv4(token, instance_id)
            log.ok(f"{display_name} IP: {ip}")

            # ensure both keys exist
            ensure_authorized_keys_has(ip, [st.ssh_key1_pub, st.ssh_key2_pub])

            # show root@SG-03 in prompt
            set_hostname(ip, display_name)

            vmess_uuid = args.vmess_uuid.strip() or str(uuid.uuid4())
            bootstrap_xray(ip, args.ss_password.strip(), vmess_uuid, installer_url)

            try:
                tcp_check(ip, 10101)
            except Exception as e:
                raise RuntimeError(f"{display_name} TCP 10101 failed from outside: {ip}:10101 ({e})")

            try:
                tcp_check(ip, 10105)
            except Exception as e:
                raise RuntimeError(f"{display_name} TCP 10105 failed from outside: {ip}:10105 ({e})")


            created_nodes.append(Node(
                name=display_name,
                region=args.region,
                ip=ip,
                ss_password=args.ss_password.strip(),
                vmess_uuid=vmess_uuid,
            ))
            created_summary.append((display_name, ip))
            _save_state(state)

        # YAML overwrite + backups
        template_path = (args.yaml_template.strip() or args.yaml_out).strip()
        write_yaml(created_nodes, out_path=args.yaml_out, template_path=template_path, group_name=args.group_name)
        log.ok(f"YAML updated (overwrite + backups): {args.yaml_out}")

        if not args.quiet:
            print("\n🎉 Done. Created VMs:")
            for name, ip in created_summary:
                print(f"  - {name} => {ip}")

    except FVPNError as e:
        raise SystemExit(f"\n❌ {e}\n")


if __name__ == "__main__":
    main()
