from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional

import requests

from .errors import FVPNError
from .log import Logger

AUTH_URL = "https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token"
API_BASE = "https://api.contabo.com/v1"


class ContaboClient:
    def __init__(self, log: Logger):
        self.log = log
        self.s = requests.Session()
        # Critical for Windows proxy env weirdness:
        self.s.trust_env = False

    def _headers(self, token: str) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-request-id": str(uuid.uuid4()),
        }

    def get_access_token(self, client_id: str, client_secret: str, api_user: str, api_password: str) -> str:
        r = self.s.post(
            AUTH_URL,
            data={
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": client_secret,
                "username": api_user,
                "password": api_password,
            },
            timeout=30,
        )
        if r.status_code != 200:
            raise FVPNError(f"Auth failed ({r.status_code}): {r.text}")
        tok = r.json().get("access_token")
        if not tok:
            raise FVPNError("Auth ok but no access_token returned.")
        return tok

    def list_images(self, token: str, search: str = "", size: int = 50, page: int = 1) -> List[Dict[str, Any]]:
        params = {
            "standardImage": "true",
            "size": str(size),
            "page": str(page),
            "orderBy": "name:asc",
        }
        if search and search.strip():
            params["search"] = search.strip()

        r = self.s.get(
            f"{API_BASE}/compute/images",
            headers=self._headers(token),
            params=params,
            timeout=30,
        )
        if r.status_code != 200:
            raise FVPNError(f"List images failed ({r.status_code}): {r.text}")
        return r.json().get("data", [])


    def list_secrets(self, token: str, type_filter: str = "ssh", name: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"size": "200", "page": "1", "orderBy": "name:asc", "type": type_filter}
        if name:
            params["name"] = name
        r = self.s.get(f"{API_BASE}/secrets", headers=self._headers(token), params=params, timeout=30)
        if r.status_code != 200:
            raise FVPNError(f"List secrets failed ({r.status_code}): {r.text}")
        return r.json().get("data", [])

    def ensure_ssh_secret(self, token: str, secret_name: str, public_key: str) -> int:
        existing = self.list_secrets(token, type_filter="ssh", name=secret_name)
        if existing:
            return int(existing[0]["secretId"])
        payload = {"name": secret_name, "value": public_key, "type": "ssh"}
        r = self.s.post(f"{API_BASE}/secrets", headers=self._headers(token), data=json.dumps(payload), timeout=30)
        if r.status_code != 201:
            raise FVPNError(f"Create SSH secret failed ({r.status_code}): {r.text}")
        return int(r.json()["data"][0]["secretId"])

    def create_instance(
        self,
        token: str,
        *,
        region: str,
        product_id: str,
        image_id: str,
        ssh_secret_ids: List[int],
        display_name: str,
        period_months: int = 1,
    ) -> int:
        payload = {
            "imageId": image_id,
            "productId": product_id,
            "region": region,
            "period": period_months,
            "displayName": display_name,
            "defaultUser": "root",
            "sshKeys": ssh_secret_ids,
        }
        r = self.s.post(f"{API_BASE}/compute/instances", headers=self._headers(token), data=json.dumps(payload), timeout=60)
        if r.status_code != 201:
            raise FVPNError(f"Create instance failed ({r.status_code}): {r.text}")
        return int(r.json()["data"][0]["instanceId"])

    def get_instance(self, token: str, instance_id: int) -> Dict[str, Any]:
        r = self.s.get(f"{API_BASE}/compute/instances/{instance_id}", headers=self._headers(token), timeout=30)
        if r.status_code != 200:
            raise FVPNError(f"Get instance failed ({r.status_code}): {r.text}")
        return r.json()["data"][0]

    def wait_for_ipv4(self, token: str, instance_id: int, timeout_sec: int = 1200) -> str:
        start = time.time()
        while True:
            inst = self.get_instance(token, instance_id)
            ipcfg = inst.get("ipConfig") or {}
            v4 = ipcfg.get("v4") or {}
            ip = v4.get("ip")
            status = inst.get("status")
            if ip:
                return ip
            if time.time() - start > timeout_sec:
                raise FVPNError(f"Timeout waiting for IPv4. Last status={status}")
            self.log.info(f"⏳ Waiting for IP... status={status}")
            time.sleep(10)
