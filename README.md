<div align="center">

# 🛡️ SentinelUSB v2.0

### USB Device Control & Monitoring Framework
**Blue Team · Endpoint Security · Insider Threat Prevention · DLP**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Category](https://img.shields.io/badge/Category-Blue%20Team-1e90ff?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

</div>

---

## 📌 What is SentinelUSB?

**SentinelUSB** is a Windows-based endpoint security tool that monitors and controls USB device connections in real time. It is designed to detect and prevent **insider threats**, **data exfiltration**, and **USB-based attacks** by using **hardware-level device fingerprinting** — not just volume labels, which can be easily spoofed.

> Built as part of a Blue Team / Endpoint Security internship project.

---

## 🚨 The Problem It Solves

Most organizations rely on drive letters or volume names to identify USB devices. This is **insecure** because:

- An attacker can rename any USB drive to `CORP_BACKUP` or `IT_TOOLS`
- A terminated employee can bring in a personal drive and bypass label-based controls
- Standard Windows logging doesn't detect what files were copied to USB

**SentinelUSB** solves this by fingerprinting devices at the **hardware level** using Vendor ID, Product ID, Serial Number, and PNP Device ID — identifiers that come directly from the USB controller and are significantly harder to spoof.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Hardware Fingerprinting** | Identifies devices via VID / PID / Serial Number — not volume labels |
| ✅ **Allowlist Enforcement** | Only pre-approved devices are authorized |
| 🚫 **Blocklist Enforcement** | Known malicious devices are auto-ejected |
| ⚠️ **Label Spoof Detection** | Detects USB drives renamed to impersonate trusted devices |
| 📁 **File Transfer Auditing** | Monitors every file written/modified on USB in real time |
| 🔴 **Risk Assessment** | Flags HIGH / MEDIUM / LOW risk transfers by file type, size, keywords |
| 🔒 **Auto Block Enforcement** | Automatically ejects blocked devices using `mountvol /D` |
| 📊 **Audit Report Generation** | Generates a full security report on session end |

---

## 🗂️ Project Structure

```
usb_security_framework/
│
├── usb_monitor.py        ← Entry point — main monitoring loop
├── authorization.py      ← Hardware fingerprinting + policy engine
├── file_auditor.py       ← Real-time file transfer monitoring
├── logger.py             ← Structured logging (events / alerts / transfers)
├── reporter.py           ← Audit report generator
│
├── allowlist.json        ← Authorized devices policy
├── blocklist.json        ← Blocked devices policy
│
└── logs/                 ← Auto-created at runtime
    ├── usb_events.log        (connect / disconnect / auth events)
    ├── alerts.log            (blocked / unknown / spoof alerts)
    └── transfer_audit.log    (file transfer records)
```

---

## ⚙️ Requirements

**Python 3.10+** and **Windows OS** required.

```bash
pip install wmi
```

---

## 🚀 Usage

```bash
# Start real-time USB monitoring
python usb_monitor.py

# Generate audit report from existing logs (without monitoring)
python usb_monitor.py --report
```

Press `Ctrl+C` to stop monitoring — a full security report is automatically generated on exit.

---

## 🔐 How Authorization Works

Every time a USB device is connected, SentinelUSB runs it through this decision pipeline:

```
USB Device Connected
        │
        ▼
┌─────────────────────┐
│   Blocklist Check   │──── MATCH ──► 🚫 BLOCKED  (drive auto-ejected)
└─────────────────────┘
        │ no match
        ▼
┌─────────────────────┐
│   Allowlist Check   │──── MATCH ──► ✅ ALLOWED  (file auditing starts)
└─────────────────────┘
        │ no match
        ▼
┌─────────────────────┐
│  Spoof Detection    │──── MATCH ──► ⚠️  SUSPICIOUS  (HIGH threat alert)
└─────────────────────┘
        │ no match
        ▼
                             ❓ UNKNOWN  (MEDIUM threat, audited for evidence)
```

---

## 🛠️ Policy Configuration

### Adding an Authorized Device — `allowlist.json`

Run the tool once with your USB plugged in. It will show:
```
Fingerprint : 00da70f76ec0c89a62ad188033e8c6ed...
```
Copy the **full 64-character fingerprint** and add it to `allowlist.json`:

```json
{
  "devices": [
    {
      "vendor_id": "SANDISK",
      "product_id": "CRUZER_BLADE",
      "serial_number": "03028801060222235121",
      "hardware_fingerprint": "00da70f76ec0c89a62ad188033e8c6ed5ca74c602a415033d7e5c8b1b4d4a1d9",
      "volume_name": "MY_USB",
      "description": "My SanDisk Cruzer Blade — Authorized"
    }
  ]
}
```

### Blocking a Device — `blocklist.json`

```json
{
  "devices": [
    {
      "vendor_id": "HAKTOOL",
      "product_id": "RUBBER_DUCKY",
      "description": "Known HID Attack Tool — Hak5 Rubber Ducky"
    }
  ]
}
```

> Policy entries support partial matching — you only need to specify the fields you care about. All specified fields must match (AND logic).

---

## 📁 File Risk Assessment

The file auditor classifies every transfer into one of three risk levels:

| Risk | Triggers |
|---|---|
| 🔴 **HIGH** | High-risk extensions (`.pdf`, `.xlsx`, `.py`, `.env`, `.zip`, `.db` ...) · Files > 50MB · Sensitive keywords (`password`, `secret`, `key`, `token` ...) |
| 🟡 **MEDIUM** | Files between 10MB – 50MB |
| 🟢 **LOW** | Small files with non-sensitive extensions |

---

## 🧠 Threat Model

| Attack Scenario | How SentinelUSB Detects It |
|---|---|
| Employee brings personal USB | Default-deny — unknown devices flagged |
| Attacker renames USB as `CORP_BACKUP` | Label spoof detection via fingerprint mismatch |
| Known attack tool (Rubber Ducky) | Blocklist match — auto ejected |
| Bulk file copy to USB | File auditor — HIGH risk transfer alert |
| Terminated employee's old USB | Blocklist by serial/fingerprint |

---

## 📋 Sample Output

```
══════════════════════════════════════════════════════════
  ✅  AUTHORIZATION DECISION: ALLOWED  │  Threat: LOW
══════════════════════════════════════════════════════════
  Drive         : F:
  Volume Label  : MY_USB  (untrusted — display only)
  Vendor ID     : SANDISK
  Product ID    : CRUZER_BLADE
  Serial Number : 03028801060222235121
  Fingerprint   : 00da70f76ec0c89a62ad188033e8c6ed...
  Decision      : Device matches ALLOWLIST entry: My SanDisk Cruzer Blade

  [🔴 FILE WRITE] passwords.txt
    Path   : F:\passwords.txt
    Size   : 1.2 KB
    Risk   : HIGH — Sensitive filename keyword detected
```

---

## 👤 Author

**Rajen** — Blue Team / Endpoint Security Internship Project  
Focus Areas: Insider Threat Prevention · Data Loss Prevention (DLP) · USB Device Control
