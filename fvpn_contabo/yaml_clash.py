from __future__ import annotations

import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Node


REGION_TO_PREFIX = {
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

PREFIX_TO_REGION_HEADER = {
    "SG": "Singapore",
    "UK": "UK",
    "EU": "EU",
    "JP": "Japan",
    "USC": "US Central",
    "USE": "US East",
    "USW": "US West",
    "AU": "Australia",
    "IN": "India",
}


def scan_last_numbers_from_yaml(yaml_text: str) -> Dict[str, int]:
    """Return last used index per prefix from existing freedom.yaml.
    Matches: "SG-01 SS" / "SG-01 VMess"
    """
    last: Dict[str, int] = {}
    for m in re.finditer(r'"([A-Z]{2,3})-(\d{2})\s+(SS|VMess)"', yaml_text):
        pfx = m.group(1)
        n = int(m.group(2))
        last[pfx] = max(last.get(pfx, 0), n)
    return last


def write_yaml_with_backup(out_path: str, new_text: str) -> None:
    """Overwrite out_path, but keep timestamped backups in ./backups next to it."""
    outp = Path(out_path)
    outp.parent.mkdir(parents=True, exist_ok=True)

    if outp.exists():
        backup_dir = outp.parent / "backups"
        backup_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = backup_dir / f"{outp.name}.{ts}.bak"
        shutil.copy2(outp, backup_path)

    tmp = outp.with_suffix(outp.suffix + ".tmp")
    tmp.write_text(new_text, encoding="utf-8")
    os.replace(tmp, outp)


def _render_proxy_pair(prefix: str, idx: int, ip: str, ss_password: str, vmess_uuid: str) -> str:
    name_base = f"{prefix}-{idx:02d}"
    return (
        f"  - name: \"{name_base} SS\"\n"
        f"    type: ss\n"
        f"    server: {ip}\n"
        f"    port: 10105\n"
        f"    cipher: aes-256-gcm\n"
        f"    password: \"{ss_password}\"\n"
        f"    udp: true\n\n"
        f"  - name: \"{name_base} VMess\"\n"
        f"    type: vmess\n"
        f"    server: {ip}\n"
        f"    port: 10101\n"
        f"    uuid: \"{vmess_uuid}\"\n"
        f"    alterId: 0\n"
        f"    cipher: auto\n"
        f"    udp: true\n"
        f"    tls: false\n"
        f"    network: tcp\n"
    )


def _split_sections(yaml_text: str) -> Tuple[str, str, str]:
    m1 = re.search(r"^proxies:\s*$", yaml_text, flags=re.MULTILINE)
    m2 = re.search(r"^proxy-groups:\s*$", yaml_text, flags=re.MULTILINE)
    if not m1 or not m2 or m2.start() <= m1.end():
        raise ValueError("YAML must contain 'proxies:' and 'proxy-groups:' blocks")
    before = yaml_text[: m1.start()]
    proxies = yaml_text[m1.start() : m2.start()]
    after = yaml_text[m2.start() :]
    return before, proxies, after


def _find_region_in_proxies(proxies_block: str, header: str) -> Tuple[int, int]:
    pattern = rf"^\s*#\s*=========\s*{re.escape(header)}\s*=========\s*$"
    m = re.search(pattern, proxies_block, flags=re.MULTILINE)
    if not m:
        return (len(proxies_block), len(proxies_block))

    start = m.end()
    m_next = re.search(r"^\s*#\s*=========.*=========\s*$", proxies_block[start:], flags=re.MULTILINE)
    end = start + (m_next.start() if m_next else len(proxies_block[start:]))
    return (end, end)


def _inject_into_proxies(template_proxies: str, region_header: str, insert_text: str) -> str:
    if not template_proxies.endswith("\n"):
        template_proxies += "\n"

    pos, _ = _find_region_in_proxies(template_proxies, region_header)
    if pos == len(template_proxies):
        if not template_proxies.endswith("\n\n"):
            template_proxies += "\n"
        template_proxies += f"  # ========= {region_header} =========\n"
        template_proxies += insert_text
        return template_proxies

    left = template_proxies[:pos]
    right = template_proxies[pos:]
    if not left.endswith("\n\n"):
        left += "\n"
    return left + insert_text + "\n" + right


def _remove_group(after_block: str, name: str) -> str:
    """Remove a proxy-group by exact name from the proxy-groups section text."""
    pat = rf'^\s*-\s*name:\s*\"{re.escape(name)}\"\s*$'
    m = re.search(pat, after_block, flags=re.MULTILINE)
    if not m:
        return after_block

    start = m.start()
    m2 = re.search(r"^\s*-\s*name:\s*\".*\"\s*$", after_block[m.end():], flags=re.MULTILINE)
    end = m.end() + (m2.start() if m2 else len(after_block[m.end():]))
    return after_block[:start] + after_block[end:]


def _remove_proxy_entries_from_group(group_block: str, remove_names: List[str]) -> str:
    """Remove specific proxy entries (e.g., 'Auto') from a group's proxies list."""
    lines = group_block.splitlines(True)
    out: List[str] = []
    in_list = False
    for ln in lines:
        if re.match(r"^\s*proxies:\s*$", ln):
            in_list = True
            out.append(ln)
            continue
        if in_list:
            m = re.match(r'^\s*-\s*\"?(.*?)\"?\s*$', ln)
            if m:
                name = m.group(1)
                if name in remove_names:
                    continue
                out.append(ln)
                continue
            in_list = False
            out.append(ln)
            continue
        out.append(ln)
    return "".join(out)


def _add_to_group_list(group_block: str, new_names: List[str]) -> str:
    lines = group_block.splitlines(True)
    out: List[str] = []
    in_list = False
    existing = set()
    indent = ""
    for ln in lines:
        if re.match(r"^\s*proxies:\s*$", ln):
            in_list = True
            out.append(ln)
            continue
        if in_list:
            m = re.match(r"^(\s*)-\s*\"?(.*?)\"?\s*$", ln)
            if m:
                indent = m.group(1)
                existing.add(m.group(2))
                out.append(ln)
                continue
            for name in new_names:
                if name not in existing:
                    out.append(f"{indent}- \"{name}\"\n")
                    existing.add(name)
            in_list = False
            out.append(ln)
            continue
        out.append(ln)
    if in_list:
        for name in new_names:
            if name not in existing:
                out.append(f"{indent}- \"{name}\"\n")
    return "".join(out)


def _update_proxy_groups(after_block: str, new_names: List[str], group_name: str) -> str:
    def extract_group(text: str, name: str):
        pat = rf'^\s*-\s*name:\s*\"{re.escape(name)}\"\s*$'
        m = re.search(pat, text, flags=re.MULTILINE)
        if not m:
            return None, None
        start = m.start()
        m2 = re.search(r"^\s*-\s*name:\s*\".*\"\s*$", text[m.end():], flags=re.MULTILINE)
        end = m.end() + (m2.start() if m2 else len(text[m.end():]))
        return (start, end), text[start:end]

    span, block = extract_group(after_block, group_name)
    if span and block:
        # Ensure the main group does not reference Auto groups.
        block = _remove_proxy_entries_from_group(block, ["Auto", "Auto (Latency Test)"])
        updated = _add_to_group_list(block, new_names)
        after_block = after_block[: span[0]] + updated + after_block[span[1] :]
    # Drop Auto groups entirely (we want everything under the main select group).
    after_block = _remove_group(after_block, "Auto")
    after_block = _remove_group(after_block, "Auto (Latency Test)")

    return after_block



def update_freedom_yaml(template_text: str, nodes: List[Node], group_name: str = "Freedom VPN") -> str:
    before, proxies_block, after = _split_sections(template_text)
    last = scan_last_numbers_from_yaml(template_text)

    all_new_proxy_names: List[str] = []

    # group inserts per prefix so they go under the right header
    inserts_by_prefix: Dict[str, str] = {}

    for n in nodes:
        prefix = REGION_TO_PREFIX.get(n.region, n.region[:2].upper())
        idx = last.get(prefix, 0) + 1
        last[prefix] = idx

        insert_text = _render_proxy_pair(prefix, idx, n.ip, n.ss_password, n.vmess_uuid)
        inserts_by_prefix.setdefault(prefix, "")
        if inserts_by_prefix[prefix] and not inserts_by_prefix[prefix].endswith("\n\n"):
            inserts_by_prefix[prefix] += "\n"
        inserts_by_prefix[prefix] += insert_text + "\n"

        base = f"{prefix}-{idx:02d}"
        all_new_proxy_names.extend([f"{base} SS", f"{base} VMess"])

    for prefix, insert_text in inserts_by_prefix.items():
        header = PREFIX_TO_REGION_HEADER.get(prefix, prefix)
        proxies_block = _inject_into_proxies(proxies_block, header, insert_text.rstrip("\n") + "\n")

    after = _update_proxy_groups(after, all_new_proxy_names, group_name=group_name)
    return before + proxies_block + after


def write_yaml(nodes: List[Node], out_path: str, template_path: Optional[str] = None, group_name: str = "Freedom VPN") -> None:
    """Overwrite out_path (same name), but keep backups/ next to it."""
    if template_path:
        tmpl = Path(template_path).read_text(encoding="utf-8", errors="replace")
        out = update_freedom_yaml(tmpl, nodes, group_name=group_name)
    else:
        outp = Path(out_path)
        if not outp.exists():
            raise ValueError("No template provided and output YAML does not exist.")
        tmpl = outp.read_text(encoding="utf-8", errors="replace")
        out = update_freedom_yaml(tmpl, nodes, group_name=group_name)

    write_yaml_with_backup(out_path, out)
