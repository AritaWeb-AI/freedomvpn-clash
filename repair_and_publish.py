# repair_and_publish.py
# English-only comments (per your preference style)

# python .\repair_and_publish.py --name SG-03 --ip 154.26.134.142


from __future__ import annotations
import argparse
import datetime as _dt
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Tuple


def _load_dotenv(dotenv_path: Path) -> Dict[str, str]:
    """
    Minimal .env loader (no dependency). Supports KEY=VALUE, ignores comments.
    """
    env: Dict[str, str] = {}
    if not dotenv_path.exists():
        return env
    for line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        env[k] = v
    return env


def _run(cmd: list[str], timeout: int = 900) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _ssh(root_at_ip: str, remote_cmd: str, timeout: int = 1800) -> Tuple[int, str, str]:
    """
    Uses system ssh. Assumes your SSH key auth is already working.
    """
    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        root_at_ip,
        remote_cmd
    ]
    return _run(cmd, timeout=timeout)


def _scp(local_path: Path, remote: str, remote_path: str, timeout: int = 900) -> Tuple[int, str, str]:
    cmd = [
        "scp",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        str(local_path),
        f"{remote}:{remote_path}",
    ]
    return _run(cmd, timeout=timeout)



def _region_from_name(node_name: str) -> str:
    m = re.match(r"^([A-Z]{2})-(\d{2})$", node_name.strip())
    if not m:
        raise ValueError("node name must look like SG-03 / EU-04 / UK-02 / JP-01")
    return m.group(1)


def _ensure_backups_dir(yaml_path: Path) -> Path:
    backups = yaml_path.parent / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    return backups


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _insert_proxy_blocks(yaml_text: str, node_name: str, ip: str, ss_password: str, vmess_uuid: str) -> str:
    """
    Inserts two proxies:
      - "XX-YY SS"
      - "XX-YY VMess"
    And appends them into proxy-group named "Freedom VPN" (type select).
    """
    if f"\"{node_name} SS\"" in yaml_text or f"\"{node_name} VMess\"" in yaml_text:
        raise RuntimeError(f"{node_name} already exists in YAML")

    block = (
        f"  - name: \"{node_name} SS\"\n"
        f"    type: ss\n"
        f"    server: {ip}\n"
        f"    port: 10105\n"
        f"    cipher: aes-256-gcm\n"
        f"    password: \"{ss_password}\"\n"
        f"    udp: true\n\n"
        f"  - name: \"{node_name} VMess\"\n"
        f"    type: vmess\n"
        f"    server: {ip}\n"
        f"    port: 10101\n"
        f"    uuid: {vmess_uuid}\n"
        f"    alterId: 0\n"
        f"    cipher: auto\n"
        f"    udp: true\n"
    )

    region = _region_from_name(node_name)

    # 1) Insert into proxies section:
    # Best effort: insert after last "<region>-NN VMess" proxy block that ends with "udp: true"
    # Fallback: insert right after "proxies:" line.
    txt = yaml_text

    last_vm = None
    for m in re.finditer(rf"(?s)(- name:\s+\"{region}-\d{{2}}\s+VMess\".*?\n\s*udp:\s*true\s*\n)", txt):
        last_vm = m

    if last_vm:
        insert_at = last_vm.end(1)
        txt = txt[:insert_at] + "\n" + block + "\n" + txt[insert_at:]
    else:
        m2 = re.search(r"(?m)^proxies:\s*$", txt)
        if not m2:
            raise RuntimeError("Could not find 'proxies:' in YAML")
        insert_at = m2.end(0)
        txt = txt[:insert_at] + "\n" + block + "\n" + txt[insert_at:]

    # 2) Append names into proxy-group "Freedom VPN" -> proxies:
    def add_to_group(text: str, entry: str) -> str:
        if f"      - \"{entry}\"" in text:
            return text
        g = re.search(
            r"(?s)(- name:\s+\"Freedom VPN\"\s*\n\s*type:\s*select\s*\n\s*proxies:\s*\n)(.*?)(\n\S)",
            text
        )
        if not g:
            raise RuntimeError("Could not find proxy-group named 'Freedom VPN'")
        head = g.group(1)
        body = g.group(2)
        tail_marker = g.group(3)  # keep structure
        body2 = body + f"      - \"{entry}\"\n"
        return text[:g.start(2)] + body2 + text[g.end(2):]

    txt = add_to_group(txt, f"{node_name} SS")
    txt = add_to_group(txt, f"{node_name} VMess")
    return txt


def repair_server(ip: str, ss_password: str, vmess_uuid: str) -> None:
    root_at_ip = f"root@{ip}"

    remote = r"""
set -e

# Sync time (helps apt + TLS)
timedatectl set-ntp true || true
systemctl restart systemd-timesyncd || true
sleep 2
date || true

# Wait apt/dpkg locks
for i in $(seq 1 120); do
  if fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
     fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
     fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
    echo "apt locked... waiting"
    sleep 5
  else
    break
  fi
done

dpkg --configure -a || true
apt-get update -y
apt-get install -y curl python3

curl -fsSL "https://raw.githubusercontent.com/AritaWeb-AI/freedomvpn-clash/main/setup_freedomvpn_xray.py" -o /root/setup_freedomvpn_xray.py

SS_PASSWORD="__SS_PASSWORD__" VMESS_UUID="__VMESS_UUID__" python3 /root/setup_freedomvpn_xray.py

# Fix systemd user if needed
sed -i 's/^User=nobody/User=root/' /etc/systemd/system/xray.service || true
systemctl daemon-reload
systemctl restart xray

# Ensure UFW rules (safe order)
ufw allow OpenSSH || true
ufw allow 10101/tcp || true
ufw allow 10105/tcp || true
ufw allow 10105/udp || true
ufw --force enable || true

# Hard checks: ports must be listening
ss -lntuup | grep -q ":10101"
ss -lntuup | grep -q ":10105"

echo "OK_PORTS"
ss -lntuup | grep -E ":10101|:10105" || true
ufw status || true
""".strip()

    remote = remote.replace("__SS_PASSWORD__", ss_password).replace("__VMESS_UUID__", vmess_uuid)
    code, out, err = _ssh(root_at_ip, remote, timeout=2400)

    if code != 0:
        raise RuntimeError(f"SSH repair failed (exit {code})\nstdout:\n{out}\nstderr:\n{err}")

    if "OK_PORTS" not in out:
        raise RuntimeError(f"Repair ran but port-check marker missing.\nstdout:\n{out}")

    print(out.strip())


def update_yaml(yaml_path: Path, node_name: str, ip: str, ss_password: str, vmess_uuid: str) -> Path:
    yaml_text = yaml_path.read_text(encoding="utf-8", errors="ignore")

    backups_dir = _ensure_backups_dir(yaml_path)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = backups_dir / f"{yaml_path.stem}.{ts}{yaml_path.suffix}"
    shutil.copy2(yaml_path, backup_path)

    new_text = _insert_proxy_blocks(yaml_text, node_name=node_name, ip=ip, ss_password=ss_password, vmess_uuid=vmess_uuid)
    _atomic_write(yaml_path, new_text)

    return backup_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Repair incomplete VM (bootstrap xray+ufw) then publish into freedom.yaml.")
    ap.add_argument("--name", help="Node name like SG-03 / EU-04", default=None)
    ap.add_argument("--ip", help="Public IP", default=None)
    ap.add_argument("--yaml", help="Path to freedom.yaml", default=r"H:\Projects\FreedomeVPN\www\freedom.yaml")
    ap.add_argument("--dotenv", help="Path to .env", default=r".\.env")
    ap.add_argument("--ss-password", help="Override SS_PASSWORD (else from .env)", default=None)
    ap.add_argument("--vmess-uuid", help="Override VMESS_UUID (else from .env)", default=None)
    ap.add_argument("--publish-only", action="store_true", help="Only upload local YAML to subscription server (no repair, no YAML edits).")
    ap.add_argument("--skip-yaml", action="store_true", help="Do not modify YAML (repair + publish only).")
    ap.add_argument("--force", action="store_true", help="If node already exists in YAML, continue (no edit) and still publish.")

    args = ap.parse_args()

    node_name = args.name or input("Node name (e.g. SG-03): ").strip()
    ip = args.ip or input("Node IP (e.g. 154.26.134.142): ").strip()
    yaml_path = Path(args.yaml)

    env_file = Path(args.dotenv)
    env = _load_dotenv(env_file)

    ss_password = args.ss_password or env.get("SS_PASSWORD")
    vmess_uuid = args.vmess_uuid or env.get("VMESS_UUID")

    if not ss_password:
        print("ERROR: SS_PASSWORD not found. Put it into .env as SS_PASSWORD=... or pass --ss-password")
        return 2
    if not vmess_uuid:
        print("ERROR: VMESS_UUID not found. Put it into .env as VMESS_UUID=... or pass --vmess-uuid")
        return 2
    if not yaml_path.exists():
        print(f"ERROR: YAML not found: {yaml_path}")
        return 2


    if not args.publish_only:
        print(f"== Repairing server {ip} ...")
        repair_server(ip=ip, ss_password=ss_password, vmess_uuid=vmess_uuid)


    backup = None
    if not args.publish_only and not args.skip_yaml:
        print(f"== Updating YAML: {yaml_path}")
        try:
            backup = update_yaml(yaml_path=yaml_path, node_name=node_name, ip=ip, ss_password=ss_password, vmess_uuid=vmess_uuid)
        except RuntimeError as e:
            if ("already exists in YAML" in str(e)) and args.force:
                print(f"NOTE: {e} (continuing because --force)")
            else:
                raise


    # Optional publish to subscription server (SG)
    sub_host = env.get("SUB_SERVER_HOST")  # e.g. 194.233.73.138
    sub_path = env.get("SUB_SERVER_PATH", "/var/www/html/freedom.yaml")
    if sub_host:
        remote = f"root@{sub_host}"
        print(f"== Uploading YAML to {remote}:{sub_path}")
        code, out, err = _scp(yaml_path, remote, sub_path, timeout=900)
        if code != 0:
            raise RuntimeError(f"SCP upload failed (exit {code})\nstdout:\n{out}\nstderr:\n{err}")
        print("UPLOAD_OK ✅")


    print("DONE ✅")

    if backup:
        print(f"Backup saved: {backup}")

    if (not args.publish_only) and (not args.skip_yaml):
        print(f"Added: {node_name} SS / {node_name} VMess -> {ip}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
