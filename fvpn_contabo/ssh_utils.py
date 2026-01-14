from __future__ import annotations

import subprocess
from typing import List

from .errors import FVPNError

import socket
import time


def wait_for_tcp(host: str, port: int, timeout_sec: int = 600, interval_sec: int = 5) -> None:
    start = time.time()
    while True:
        try:
            with socket.create_connection((host, port), timeout=3):
                return
        except OSError:
            if time.time() - start > timeout_sec:
                raise FVPNError(f"Timeout waiting for TCP {host}:{port}")
            time.sleep(interval_sec)

def wait_for_ssh(host: str, timeout_sec: int = 600) -> None:
    wait_for_tcp(host, 22, timeout_sec=timeout_sec, interval_sec=5)


def run_ssh(host: str, cmd: str) -> str:
    """Run a single SSH command as root on the target host. Returns stdout."""
    ssh_cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"root@{host}",
        cmd,
    ]
    r = subprocess.run(ssh_cmd, capture_output=True, text=True)

    if r.returncode != 0:
        stderr = (r.stderr or "").strip()
        stdout = (r.stdout or "").strip()
        hint = " (exit 255 معمولاً یعنی SSH هنوز آماده نیست/کلید/شبکه)" if r.returncode == 255 else ""
        raise FVPNError(
            f"SSH failed{hint} (exit {r.returncode})\n"
            f"host: {host}\n"
            f"cmd: {cmd}\n"
            f"stdout: {stdout}\n"
            f"stderr: {stderr}"
        )

    return (r.stdout or "").strip()


def ensure_authorized_keys_has(host: str, pubkeys: List[str]) -> None:
    wait_for_ssh(host, timeout_sec=600)

    """Ensure the given public keys exist in /root/.ssh/authorized_keys.

    Uses a heredoc to avoid brittle shell quoting.
    """
    payload = "\n".join(k.strip() for k in pubkeys if k and k.strip()) + "\n"
    cmd = (
        "set -e; "
        "mkdir -p /root/.ssh; chmod 700 /root/.ssh; "
        "touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; "
        "tmp=/root/.ssh/authorized_keys.fvpn_tmp; "
        "cat > $tmp <<'EOF'\n"
        + payload
        + "EOF\n"
        "while IFS= read -r k; do "
        "  [ -z \"$k\" ] && continue; "
        "  grep -qxF \"$k\" /root/.ssh/authorized_keys || echo \"$k\" >> /root/.ssh/authorized_keys; "
        "done < $tmp; "
        "rm -f $tmp; "
        "wc -l /root/.ssh/authorized_keys || true"
    )
    run_ssh(host, cmd)


def set_hostname(host: str, hostname: str) -> None:
    """Set the machine hostname (shows as root@HOSTNAME in prompt)."""
    hn = hostname.strip()
    if not hn:
        return
    cmd = (
        "set -e; "
        f"hostnamectl set-hostname {hn}; "
        "(grep -q '^127\\.0\\.1\\.1' /etc/hosts && "
        f" sed -i 's/^127\\.0\\.1\\.1\\s\\+.*$/127.0.1.1\\t{hn}/' /etc/hosts) "
        "|| true; "
        f"grep -q '^127\\.0\\.1\\.1' /etc/hosts || echo '127.0.1.1\t{hn}' >> /etc/hosts; "
        "hostname"
    )
    run_ssh(host, cmd)
