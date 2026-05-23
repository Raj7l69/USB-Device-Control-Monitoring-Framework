# 🛡 SentinelUSB v2.0 — Endpoint Security Framework

A Blue Team USB Device Control & Monitoring Framework built for insider threat prevention and data exfiltration detection.

---

## Features

- **Hardware Fingerprinting** — Identifies devices via VID/PID/Serial (not just volume labels)
- **Allowlist/Blocklist Enforcement** — Policy-based device authorization
- **Label Spoof Detection** — Detects renamed USB drives impersonating trusted devices
- **Real-time File Auditing** — Monitors file transfers with risk assessment (HIGH/MEDIUM/LOW)
- **Auto Block Enforcement** — Automatically ejects blocked devices
- **Audit Report Generation** — Generates structured security reports on session end

---

## Project Structure

```
usb_security_framework/
├── usb_monitor.py       # Main orchestrator — entry point
├── authorization.py     # Hardware fingerprinting + policy engine
├── file_auditor.py      # Real-time file transfer monitoring
├── logger.py            # Structured event/alert/transfer logging
├── reporter.py          # Audit report generation
├── allowlist.json       # Authorized devices policy
├── blocklist.json       # Blocked devices policy
└── logs/                # Generated at runtime
    ├── usb_events.log
    ├── alerts.log
    └── transfer_audit.log
```

---

## Requirements

```bash
pip install wmi
```

> Requires **Windows OS** and **Python 3.10+**

---

## Usage

```bash
# Start monitoring
python usb_monitor.py

# Generate report from existing logs
python usb_monitor.py --report
```

---

## Policy Configuration

### allowlist.json
```json
{
  "devices": [
    {
      "vendor_id": "SANDISK",
      "product_id": "CRUZER_BLADE",
      "serial_number": "XXXXXXXXXXXX",
      "hardware_fingerprint": "YOUR_64_CHAR_SHA256_HASH",
      "volume_name": "MY_USB",
      "description": "My authorized USB drive"
    }
  ]
}
```

### blocklist.json
```json
{
  "devices": [
    {
      "vendor_id": "HAKTOOL",
      "product_id": "RUBBER_DUCKY",
      "hardware_fingerprint": "",
      "description": "Known HID Attack Tool"
    }
  ]
}
```

> **Tip:** Run the tool once with an unknown device to get its full hardware fingerprint, then add it to the allowlist.

---

## Authorization Decision Flow

```
USB Connected
     │
     ▼
Blocklist Check ──── MATCH ──► 🚫 BLOCKED (drive ejected)
     │
     ▼
Allowlist Check ──── MATCH ──► ✅ ALLOWED (file audit starts)
     │
     ▼
Spoof Detection ─── MATCH ──► ⚠️  SUSPICIOUS
     │
     ▼
                            ❓ UNKNOWN (flagged, audited)
```

---

## Threat Model

| Threat | Detection Method |
|--------|-----------------|
| Unauthorized USB | Default-deny + allowlist |
| Renamed/Spoofed USB | Hardware fingerprint mismatch |
| Known malicious device | Blocklist match |
| Data exfiltration | File transfer auditor |

---

## Context

Built as part of a Blue Team / Endpoint Security internship project.  
Focuses on: Insider Threat Prevention · DLP · USB Device Control
