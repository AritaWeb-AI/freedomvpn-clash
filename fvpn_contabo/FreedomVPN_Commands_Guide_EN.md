# Freedom VPN — Command & Workflow Quick Guide (Windows PowerShell)

> Notes:
> - All explanations are **English-only** (project standard).
> - All commands are inside code blocks to avoid RTL/LTR issues.
> - Adjust paths if your local folders differ.

---

## 0) Paths and prerequisites

### Go to project root
```powershell
cd H:\Projects\FreedomeVPN\cantabo
```

### Activate venv (if your venv is named `fvpn`)
```powershell
.\fvpn\Scripts\Activate.ps1
```

### Key files / paths
- VM numbering state:
```text
H:\Projects\FreedomeVPN\cantabo\.fvpn\state.json
```
- Local Clash YAML (source of truth):
```text
H:\Projects\FreedomeVPN\www\freedom.yaml
```
- Subscription server destination path:
```text
root@194.233.73.138:/var/www/html/freedom.yaml
```

---

## 1) Create new VMs (Create + Bootstrap + Update YAML)

This uses:
- `fvpn_contabo/main.py` for VM creation + bootstrap
- It updates the local YAML with timestamped backups + atomic write (per your implementation)

### Example: create 1 EU VM (Ubuntu 22.04) and update local YAML
```powershell
python .\fvpn_contabo\main.py `
  --count 1 `
  --region EU `
  --product-id V94 `
  --image-search "Ubuntu 22.04" `
  --period 1 `
  --ss-password "$env:SS_PASSWORD" `
  --vmess-uuid "$env:VMESS_UUID" `
  --yaml-out H:\Projects\FreedomeVPN\www\freedom.yaml `
  --group-name "Freedom VPN"
```

**Notes**
- VM names are derived from `.fvpn/state.json` (e.g., EU-04 / SG-03 / UK-03 / JP-02 based on last_used).
- If `--vmess-uuid` is empty, the script may generate a UUID (depending on your logic).
- If you pass `--image-id`, the image selection step is skipped.

---

## 2) Repair an incomplete/failed VM (Repair + Verify ports + Optional YAML update + Optional publish)

This uses `repair_and_publish.py` for:
- NTP fixes
- apt/dpkg lock waiting + recovery
- package installs
- running `setup_freedomvpn_xray.py`
- fixing systemd `User=root` when needed
- verifying ports 10101/10105
- applying UFW rules
- optional YAML update (backup + atomic write)
- optional SCP upload to subscription server

### 2.1 Repair + Update local YAML + Publish (recommended when a new VM was created but is incomplete)
```powershell
python .\repair_and_publish.py `
  --name EU-04 `
  --ip 167.86.113.194 `
  --yaml H:\Projects\FreedomeVPN\www\freedom.yaml `
  --dotenv .\.env
```

### 2.2 Repair only (do not touch YAML)
```powershell
python .\repair_and_publish.py `
  --name EU-04 `
  --ip 167.86.113.194 `
  --yaml H:\Projects\FreedomeVPN\www\freedom.yaml `
  --dotenv .\.env `
  --skip-yaml `
  --force
```

**Flag notes**
- `--skip-yaml` = do not update local YAML.
- `--force` = avoid failing on “already exists” situations (as implemented in your script).

---

## 3) Update the local YAML

### Option A: Update during VM creation (automatic)
When you run `fvpn_contabo/main.py` to create VMs, it updates:
```text
H:\Projects\FreedomeVPN\www\freedom.yaml
```
and creates timestamped backups, then writes atomically.

### Option B: Update via `repair_and_publish.py`
If you have a node (name + IP) and want to ensure it’s repaired/verified and then added to YAML:
```powershell
python .\repair_and_publish.py `
  --name SG-03 `
  --ip 154.26.134.142 `
  --yaml H:\Projects\FreedomeVPN\www\freedom.yaml `
  --dotenv .\.env `
  --force
```

---

## 4) Publish (upload) the YAML to the subscription server (SCP only)

Use this when local YAML is already correct and you only want to upload it:
```powershell
python .\repair_and_publish.py `
  --name ANY `
  --ip 0.0.0.0 `
  --yaml H:\Projects\FreedomeVPN\www\freedom.yaml `
  --dotenv .\.env `
  --publish-only `
  --force
```

Expected success output typically includes:
- `UPLOAD_OK ✅`
- `DONE ✅`

---

## 5) Verification commands

### 5.1 Check ports from Windows (each VM)
```powershell
Test-NetConnection 167.86.113.194 -Port 10101
Test-NetConnection 167.86.113.194 -Port 10105
```

### 5.2 Fetch remote YAML and search reliably (avoid encoding/pipe issues)
```powershell
$tmp = "$env:TEMP\freedom_remote.yaml"
curl.exe -s "https://sub.freedomvpn.app/freedom.yaml" -o $tmp
Get-Content $tmp | Select-String -Pattern "SG-03|EU-04|server:"
```

---

## 6) Replace `rg` on PowerShell (search helpers)

### Search in one file
```powershell
Select-String -Path .\fvpn_contabo\main.py -Pattern "bootstrap_xray\("
```

### Search across all Python files
```powershell
Get-ChildItem .\fvpn_contabo -Recurse -Filter *.py | `
  Select-String -Pattern "bootstrap_xray\(|ensure_authorized_keys_has|state.json"
```

---

## 7) Cheat sheet

### Create a new VM + auto bootstrap + auto YAML update
```powershell
python .\fvpn_contabo\main.py --count 1 --region EU --product-id V94 --image-search "Ubuntu 22.04" --period 1 --yaml-out H:\Projects\FreedomeVPN\www\freedom.yaml --group-name "Freedom VPN"
```

### Repair a half-configured VM + update YAML + publish
```powershell
python .\repair_and_publish.py --name EU-04 --ip <IP> --yaml H:\Projects\FreedomeVPN\www\freedom.yaml --dotenv .\.env --force
```

### Publish only (upload YAML without changes)
```powershell
python .\repair_and_publish.py --name ANY --ip 0.0.0.0 --yaml H:\Projects\FreedomeVPN\www\freedom.yaml --dotenv .\.env --publish-only --force
```

---

## 8) Important reminders

- `--skip-yaml` = repair/verify only; no YAML update.
- `--publish-only` = SCP upload only; no repair; no YAML update.
- If piping remote YAML into `Select-String` returns nothing, always download to a temp file first and search locally.

