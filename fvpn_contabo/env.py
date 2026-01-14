from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv

from .errors import FVPNError


def clean_env_key(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    v = v.strip()
    # handle .env values like "ssh-ed25519 AAAA..."
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        v = v[1:-1].strip()
    return v or None


def require_env(name: str, val: Optional[str]) -> str:
    if val is None or str(val).strip() == "":
        raise FVPNError(f"Missing required value: {name}")
    return str(val).strip()


@dataclass
class Settings:
    contabo_client_id: str
    contabo_client_secret: str
    contabo_api_user: str
    contabo_api_password: str

    ssh_key1_pub: str
    ssh_key2_pub: str
    ssh_secret1_name: str = "freedomvpn-sshkey-1"
    ssh_secret2_name: str = "freedomvpn-sshkey-2"

    installer_url: str = "https://raw.githubusercontent.com/AritaWeb-AI/freedomvpn-clash/main/setup_freedomvpn_xray.py"


def load_settings_from_env() -> Settings:
    load_dotenv()

    k1 = clean_env_key(os.getenv("SSH_KEY1_PUB_VALUE"))
    k2 = clean_env_key(os.getenv("SSH_KEY2_PUB_VALUE"))

    # optional fallback: read from file paths if provided
    # (still supported, but not required)
    if not k1:
        p1 = os.getenv("SSH_KEY1_PUB")
        if p1:
            k1 = _read_file(p1)
    if not k2:
        p2 = os.getenv("SSH_KEY2_PUB")
        if p2:
            k2 = _read_file(p2)

    return Settings(
        contabo_client_id=require_env("CONTABO_CLIENT_ID", os.getenv("CONTABO_CLIENT_ID")),
        contabo_client_secret=require_env("CONTABO_CLIENT_SECRET", os.getenv("CONTABO_CLIENT_SECRET")),
        contabo_api_user=require_env("CONTABO_API_USER", os.getenv("CONTABO_API_USER")),
        contabo_api_password=require_env("CONTABO_API_PASSWORD", os.getenv("CONTABO_API_PASSWORD")),

        ssh_key1_pub=require_env("SSH_KEY1_PUB_VALUE or SSH_KEY1_PUB", k1),
        ssh_key2_pub=require_env("SSH_KEY2_PUB_VALUE or SSH_KEY2_PUB", k2),

        ssh_secret1_name=(os.getenv("CONTABO_SSH_SECRET1") or "freedomvpn-sshkey-1").strip(),
        ssh_secret2_name=(os.getenv("CONTABO_SSH_SECRET2") or "freedomvpn-sshkey-2").strip(),

        installer_url=(os.getenv("FVPN_INSTALLER_URL") or Settings.installer_url).strip(),
    )


def _read_file(path: str) -> str:
    import os
    p = os.path.expanduser(path)
    if not os.path.exists(p):
        raise FVPNError(f"File not found: {p}")
    with open(p, "r", encoding="utf-8") as f:
        return f.read().strip()
