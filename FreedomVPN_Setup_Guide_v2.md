# Freedom VPN — Multi-VM Setup Guide (SSH + Xray + Clash Subscription)

This guide sets up:
- Cloudflare DNS for `freedomvpn.app`
- SSH key access (Windows) to each VM
- Xray (Shadowsocks + VMess) on multiple VMs
- A central Clash subscription file hosted on one VM (via nginx)

✅ Rules we follow:
- Cloudflare records for VPN endpoints must be **DNS only** (gray cloud).
- YAML and all names are **English only**.
- **Do NOT commit secrets** (SS password / VMess UUID) into a public repo.

---

## 0) Your current environment snapshot

Domain: `freedomvpn.app` (GoDaddy registrar, Cloudflare DNS)

Hostnames (A records, DNS only):
- `sub.freedomvpn.app` → **subscription VM** (example: Singapore)
- `sg1.freedomvpn.app` → Singapore VM
- `uk1.freedomvpn.app` → UK VM
- `eu1.freedomvpn.app` → EU VM
- `jp1.freedomvpn.app` → Japan VM

Xray ports (each VPN VM):
- VMess: `10101/tcp`
- Shadowsocks: `10105/tcp` and `10105/udp`

---

## 1) Cloudflare DNS records

Cloudflare → **DNS** → **Add record**:

Create **A** records (all **DNS only / gray cloud**):
- `sub` → IP of the subscription host VM
- `sg1` → IP of SG VM
- `uk1` → IP of UK VM
- `eu1` → IP of EU VM
- `jp1` → IP of JP VM

Verify from any Linux box:
```bash
getent hosts sub.freedomvpn.app sg1.freedomvpn.app uk1.freedomvpn.app eu1.freedomvpn.app jp1.freedomvpn.app
```

---

## 2) Create or locate your SSH key (Windows / Linux / macOS)

You can either **generate a new key** or **use an existing key**.

---

### 2.1 Generate a NEW key (recommended on a new PC)

**Windows (PowerShell):**
```powershell
ssh-keygen -t ed25519 -a 64
```

This will ask:
- **File to save the key** (press Enter to accept default)
- **Passphrase** (optional but recommended)

Default location is usually:
- Private key: `C:\Users\<You>\.ssh\id_ed25519`
- Public key:  `C:\Users\<You>\.ssh\id_ed25519.pub`

**Linux/macOS:**
```bash
ssh-keygen -t ed25519 -a 64
```
Default location is usually `~/.ssh/id_ed25519` and `~/.ssh/id_ed25519.pub`.

---

### 2.2 Find your public key file (universal)

**Windows (PowerShell): list public keys**
```powershell
Get-ChildItem $env:USERPROFILE\.ssh\*.pub | Select-Object FullName
```

**Linux/macOS: list public keys**
```bash
ls -1 ~/.ssh/*.pub 2>/dev/null
```

Pick the `.pub` file you want to use (usually `id_ed25519.pub`).

---

### 2.3 Print (copy) your public key

**Windows (PowerShell):**
```powershell
Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub"
```

**Linux/macOS:**
```bash
cat ~/.ssh/id_ed25519.pub
```

Copy the full line that starts with `ssh-ed25519 ...`.

---

### 2.4 If you only have the PRIVATE key and no `.pub` file

You can regenerate the public key from the private key:

**Windows (PowerShell) / Linux / macOS:**
```bash
ssh-keygen -y -f ~/.ssh/id_ed25519
```

Copy the output and paste it into the VM’s `authorized_keys`.

### 2.5 Fix SSH key error

**Windows (PowerShell):**
```powershell
Test-Path "$env:USERPROFILE\.ssh\id_ed25519"
```

**Windows (PowerShell):**
```powershell
icacls "$env:USERPROFILE\.ssh\id_ed25519" /inheritance:r
icacls "$env:USERPROFILE\.ssh\id_ed25519" /grant:r "$env:USERNAME:RX" "Administrators:F" "SYSTEM:F"
icacls "$env:USERPROFILE\.ssh\id_ed25519" /remove:g Everyone
```

**Windows (PowerShell):**
```powershell
Test-Path "$env:USERPROFILE\.ssh\id_ed25519"
```

**Windows (PowerShell):**
```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" root@84.247.155.221
```

---

## 3) Add your SSH public key to each VM (via Contabo Web Console)

Use this when you **don’t** have the old SSH key on your new PC.

For each VM (UK/EU/JP/SG):
1) Open Contabo → VPS list → choose VM → **Console/VNC**
2) Log in as `root` (or your admin user)
3) Run:

```bash
mkdir -p /root/.ssh
chmod 700 /root/.ssh
nano /root/.ssh/authorized_keys
```

Paste the public key line, then:
- Save: `Ctrl+O` → Enter
- Exit: `Ctrl+X`

Set permissions:
```bash
chmod 600 /root/.ssh/authorized_keys
```

---

## 4) SSH into a VM from Windows using the new key

Example (UK):
```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" root@<IP Address>
```

You should see:
```
root@<hostname>:~#
```

---

## 5) Install Xray on each VPN VM using your GitHub script

Repo file:
- `setup_freedomvpn_xray.py`

### 5.1 Download the script (raw GitHub)
On the target VM:
```bash
curl -fsSL -o setup_freedomvpn_xray.py https://raw.githubusercontent.com/AritaWeb-AI/freedomvpn-clash/main/setup_freedomvpn_xray.py
ls -la setup_freedomvpn_xray.py
```

### 5.2 Run it (EDGE role) with secrets passed to sudo
Do this on **UK/EU/JP** nodes:

```bash
sudo SS_PASSWORD='/1EkYmmah9R8Jl8aRUbEU8BsN0N7ge/O' \
     VMESS_UUID='41389cdd-c7c8-4202-8cf6-f99887664046' \
     python3 setup_freedomvpn_xray.py --role edge
```

### 5.3 Confirm Xray is running
```bash
systemctl status xray --no-pager
```

### 5.4 Confirm ports are listening
```bash
sudo ss -lntu | grep -E ':10101|:10105' || true
```

Expected:
- TCP listen on `10101`
- TCP listen on `10105`
- UDP on `10105`

---

## 6) Fix: Xray shows “active” but ports are NOT listening

Sometimes Xray runs as `nobody` and does not bind correctly on some hosts.

On that VM:
```bash
sudo sed -i 's/^User=nobody/User=root/' /etc/systemd/system/xray.service
sudo systemctl daemon-reload
sudo systemctl restart xray
```

Re-check:
```bash
sudo ss -lntu | grep -E ':10101|:10105' || true
```

---

## 7) Validate connectivity (from subscription host VM)

From the subscription VM (example SG), test another node:

```bash
nc -vz uk1.freedomvpn.app 10105
nc -vz uk1.freedomvpn.app 10101
```

If `nc` is missing:
```bash
sudo apt-get update && sudo apt-get install -y netcat-openbsd
```

---

## 8) Host the Clash subscription file (central “sub” VM)

### 8.1 Install + enable nginx
On the subscription VM:
```bash
sudo apt-get update && sudo apt-get install -y nginx
sudo systemctl enable --now nginx
systemctl status nginx --no-pager
```

### 8.2 Put the YAML file in nginx web root
Nginx default web root on Ubuntu:
- `/var/www/html`

Place your YAML at:
```bash
sudo nano /var/www/html/freedom.yaml
```

Verify permissions:
```bash
ls -la /var/www/html/freedom.yaml
```

### 8.3 Test the URL
```bash
curl -fsSL http://sub.freedomvpn.app/freedom.yaml | head -n 20
```

---

## 9) Clash for Windows import + refresh

1) **Profiles** → Add/Download from URL  
2) URL:
   - `http://sub.freedomvpn.app/freedom.yaml`
3) Save → Select profile → **Update**

### 9.1 Fix: “Could not switch this profile”
Ensure the rules line is:
```yaml
- MATCH,Freedom VPN
```
(not `MATCH,"Freedom VPN"`)

---

## 10) Quick rollout checklist (per new VM)

- [ ] Add Cloudflare A record (DNS only): `xx1.freedomvpn.app → VM IP`
- [ ] Add SSH public key via console (`/root/.ssh/authorized_keys`)
- [ ] SSH in using your new key
- [ ] Download setup script
- [ ] Run script `--role edge` with sudo env vars
- [ ] Confirm ports listening `10101/10105`
- [ ] If not listening: set xray service User to root, restart, re-check
- [ ] `nc -vz xx1.freedomvpn.app 10101` and `10105` from subscription host
- [ ] Refresh Clash profile and verify latency shows

---
