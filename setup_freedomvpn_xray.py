#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
from pathlib import Path

XRAY_INSTALL_URL = "https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"

DEFAULT_SS_PORT = 10105
DEFAULT_VMESS_PORT = 10101
DEFAULT_SS_METHOD = "aes-256-gcm"

def sh(cmd: str) -> None:
    print(f"+ {cmd}")
    subprocess.run(["bash", "-lc", cmd], check=True)

def must_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        print(f"ERROR: missing env var {name}")
        sys.exit(2)
    return v

def write_file(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")

def xray_config(ss_port: int, ss_method: str, ss_password: str, vmess_port: int, vmess_uuid: str) -> str:
    # Same layout you already used: /usr/local/etc/xray/config.json
    return f"""{{
  "log": {{
    "loglevel": "warning"
  }},
  "inbounds": [
    {{
      "listen": "0.0.0.0",
      "port": {ss_port},
      "protocol": "shadowsocks",
      "settings": {{
        "method": "{ss_method}",
        "password": "{ss_password}",
        "network": "tcp,udp"
      }}
    }},
    {{
      "listen": "0.0.0.0",
      "port": {vmess_port},
      "protocol": "vmess",
      "settings": {{
        "clients": [
          {{
            "id": "{vmess_uuid}",
            "alterId": 0
          }}
        ]
      }}
    }}
  ],
  "outbounds": [
    {{
      "protocol": "freedom",
      "settings": {{}}
    }}
  ]
}}
"""

def clash_yaml(domain: str, nodes: list[str], ss_port: int, ss_method: str, ss_password: str, vmess_port: int, vmess_uuid: str) -> str:
    # Nice clean names, English-only
    proxies = []
    group_list = ['"Auto (Latency Test)"']
    urltest_list = []

    def add_node(tag: str):
        host = f"{tag}.{domain}"
        proxies.append(f"""  - name: "{tag.upper()} SS"
    type: ss
    server: {host}
    port: {ss_port}
    cipher: {ss_method}
    password: "{ss_password}"
    udp: true
""")
        proxies.append(f"""  - name: "{tag.upper()} VMess"
    type: vmess
    server: {host}
    port: {vmess_port}
    uuid: "{vmess_uuid}"
    alterId: 0
    cipher: auto
    udp: true
    tls: false
    network: tcp
""")
        group_list.extend([f'"{tag.upper()} SS"', f'"{tag.upper()} VMess"'])
        urltest_list.extend([f'"{tag.upper()} SS"', f'"{tag.upper()} VMess"'])

    for n in nodes:
        add_node(n)

    proxies_block = "proxies:\n" + "".join(proxies) if proxies else "proxies: []\n"

    return f"""port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info

dns:
  enable: true
  listen: 0.0.0.0:7874
  ipv6: false
  enhanced-mode: fake-ip
  nameserver:
    - 1.1.1.1
    - 8.8.8.8

{proxies_block}

proxy-groups:
  - name: "Freedom VPN"
    type: select
    proxies:
      - {group_list[0]}
{chr(10).join([f"      - {x}" for x in group_list[1:]])}
      - DIRECT

  - name: "Auto (Latency Test)"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
{chr(10).join([f"      - {x}" for x in urltest_list])}

rules:
  - GEOIP,LAN,DIRECT
  - MATCH,Freedom VPN
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", choices=["edge", "sub"], default="edge",
                    help="edge=only Xray+UFW, sub=Xray+UFW+nginx+freedom.yaml")
    ap.add_argument("--domain", default="freedomvpn.app")
    ap.add_argument("--nodes", default="sg1,uk1,eu1,jp1",
                    help="comma-separated node hostnames WITHOUT domain (e.g. sg1,uk1,eu1,jp1)")
    ap.add_argument("--ss-port", type=int, default=DEFAULT_SS_PORT)
    ap.add_argument("--ss-method", default=DEFAULT_SS_METHOD)
    ap.add_argument("--vmess-port", type=int, default=DEFAULT_VMESS_PORT)
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("ERROR: run as root (use sudo).")
        sys.exit(1)

    ss_password = must_env("SS_PASSWORD")
    vmess_uuid = must_env("VMESS_UUID")

    # Base packages
    sh("apt-get update -y")
    sh("apt-get install -y curl ca-certificates ufw")

    # Install Xray via the widely used XTLS installer script :contentReference[oaicite:1]{index=1}
    sh(f"bash <(curl -Ls {XRAY_INSTALL_URL})")

    # Write Xray config + start
    write_file("/usr/local/etc/xray/config.json",
               xray_config(args.ss_port, args.ss_method, ss_password, args.vmess_port, vmess_uuid))
    sh("systemctl daemon-reload || true")
    sh("systemctl enable --now xray")

    # Firewall (safe order: allow ssh first, then enable)
    sh("ufw allow OpenSSH")
    sh(f"ufw allow {args.vmess_port}/tcp")
    sh(f"ufw allow {args.ss_port}/tcp")
    sh(f"ufw allow {args.ss_port}/udp")
    sh("ufw --force enable")
    sh("ufw status")

    if args.role == "sub":
        sh("apt-get install -y nginx")
        sh("systemctl enable --now nginx")

        nodes = [x.strip() for x in args.nodes.split(",") if x.strip()]
        yaml = clash_yaml(args.domain, nodes, args.ss_port, args.ss_method, ss_password, args.vmess_port, vmess_uuid)
        write_file("/var/www/html/freedom.yaml", yaml)

        print("\nDONE. Subscription URL should be:")
        print(f"  http://sub.{args.domain}/freedom.yaml")
        print("Make sure Cloudflare record sub is DNS-only (gray cloud).")

if __name__ == "__main__":
    main()
