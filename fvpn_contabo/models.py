from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

Region = Literal["EU", "UK", "JPN", "SIN", "US-central", "US-east", "US-west", "AUS", "IND"]

@dataclass
class Node:
    name: str
    region: str
    ip: str
    ss_port: int = 10105
    ss_cipher: str = "aes-256-gcm"
    ss_password: str = ""
    vmess_port: int = 10101
    vmess_uuid: str = ""
    vmess_alter_id: int = 0
    vmess_tls: bool = False
