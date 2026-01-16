import os
from typing import Optional, List

from uptime_kuma_api import UptimeKumaApi
from uptime_kuma_api.model import MonitorType


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


def _parse_int_list(csv: Optional[str]) -> Optional[List[int]]:
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


def _kuma_cfg():
    url = _env("KUMA_URL")
    user = _env("KUMA_USER")
    pw = _env("KUMA_PASS")
    enabled = _env("KUMA_ENABLED", "1") == "1"

    # Optional: attach notifications automatically (e.g. Telegram)
    notif_ids = _parse_int_list(_env("KUMA_NOTIFICATION_IDS"))

    # Optional: SSL verify toggle (default True)
    ssl_verify = _env("KUMA_SSL_VERIFY", "1") == "1"

    return enabled, url, user, pw, notif_ids, ssl_verify


def ensure_tcp_monitor(name: str, host: str, port: int, interval: int = 60, retry_interval: int = 60) -> int:
    enabled, url, user, pw, notif_ids, ssl_verify = _kuma_cfg()
    if not enabled or not url or not user or not pw:
        return -1  # Kuma not configured

    with UptimeKumaApi(url, ssl_verify=ssl_verify) as api:
        api.login(user, pw)

        monitors = api.get_monitors()
        existing = None

        # Prefer exact match by (type=tcp, hostname, port). Fallback by name.
        for m in monitors:
            m_type = str(m.get("type", "")).lower()
            if m_type == "tcp" and str(m.get("hostname")) == str(host) and int(m.get("port") or 0) == int(port):
                existing = m
                break

        if existing is None:
            for m in monitors:
                if str(m.get("name")) == name:
                    existing = m
                    break

        payload = dict(
            type=MonitorType.TCP,
            name=name,
            hostname=host,
            port=int(port),
            interval=int(interval),
            retryInterval=int(retry_interval),
        )
        if notif_ids:
            payload["notificationIDList"] = notif_ids

        if existing is None:
            res = api.add_monitor(**payload)  # returns monitorId/monitorID depending on version
            mid = res.get("monitorId") or res.get("monitorID")
            return int(mid)
        else:
            mid = int(existing["id"])
            api.edit_monitor(mid, **payload)
            return mid


def ensure_vm_monitors(vm_name: str, ip: str) -> None:
    # Consistent naming with your current style in Kuma
    ensure_tcp_monitor(f"{vm_name}-10101", ip, 10101)
    ensure_tcp_monitor(f"{vm_name}-10105", ip, 10105)
