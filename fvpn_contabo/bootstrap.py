from __future__ import annotations

from .ssh_utils import run_ssh


def bootstrap_xray(host: str, ss_password: str, vmess_uuid: str, installer_url: str) -> None:
    cmd = (
        "set -e; "
        # Wait for cloud-init / unattended upgrades to release apt/dpkg locks
        "for i in $(seq 1 60); do "
        "  if fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || "
        "     fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || "
        "     fuser /var/lib/dpkg/lock >/dev/null 2>&1; then "
        "    echo 'apt locked... waiting'; sleep 5; "
        "  else "
        "    break; "
        "  fi; "
        "done; "
        "dpkg --configure -a || true; "
        "apt-get update -y; "
        "apt-get install -y curl python3; "
        f"curl -fsSL '{installer_url}' -o /root/setup_freedomvpn_xray.py; "
        f"SS_PASSWORD='{ss_password}' VMESS_UUID='{vmess_uuid}' python3 /root/setup_freedomvpn_xray.py; "
        "sed -i 's/^User=nobody/User=root/' /etc/systemd/system/xray.service || true; "
        "systemctl daemon-reload; systemctl restart xray; "
        "ss -lntuup | grep -q ':10101'; "
        "ss -lntuup | grep -q ':10105'; "
    )
    run_ssh(host, cmd)
