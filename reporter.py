"""
================================================================================
  SentinelUSB — Security Report Generator
  Module  : reporter.py
  Purpose : Aggregate USB security events, authorization decisions, and file
            transfer logs into human-readable and structured audit reports.
            Supports plaintext reports suitable for internship submissions and
            incident documentation.
  Author  : SentinelUSB Framework
  Context : Blue Team / Audit / Compliance / Incident Response
================================================================================
"""

import re
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from logger import log_event


# ─── Configuration ─────────────────────────────────────────────────────────────

REPORTS_DIR        = Path("reports")
LOGS_DIR           = Path("logs")
USB_EVENTS_LOG     = LOGS_DIR / "usb_events.log"
ALERTS_LOG         = LOGS_DIR / "alerts.log"
TRANSFER_AUDIT_LOG = LOGS_DIR / "transfer_audit.log"
FINAL_REPORT_PATH  = REPORTS_DIR / "final_usb_report.txt"


# ─── Log Parsing Utilities ─────────────────────────────────────────────────────

def _read_log(path: Path) -> list[str]:
    """Read all lines from a log file. Returns empty list if file not found."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        return []


def _count_events_by_tag(lines: list[str], tag: str) -> int:
    """Count how many log lines contain a specific event tag."""
    return sum(1 for line in lines if f"[{tag}]" in line)


def _extract_alert_payloads(lines: list[str]) -> list[dict]:
    """
    Parse JSON payloads from alert log lines.
    Returns list of alert dicts for structured report sections.
    """
    alerts = []
    for line in lines:
        # Alert lines contain a JSON payload after the event tag
        json_match = re.search(r'\{.*\}', line)
        if json_match:
            try:
                payload = json.loads(json_match.group())
                alerts.append(payload)
            except json.JSONDecodeError:
                continue
    return alerts


# ─── Report Sections ───────────────────────────────────────────────────────────

def _section_header(title: str) -> str:
    width = 62
    bar   = "═" * width
    return f"\n{bar}\n  {title}\n{bar}"


def _build_executive_summary(event_lines, alert_lines, transfer_lines) -> str:
    """High-level summary — designed to be readable by non-technical stakeholders."""

    total_events    = len([l for l in event_lines if "|" in l])
    total_alerts    = len([l for l in alert_lines  if "WARNING" in l])
    total_transfers = len([l for l in transfer_lines if "|" in l])

    blocked_count    = _count_events_by_tag(alert_lines,  "BLOCKED_DEVICE")
    unknown_count    = _count_events_by_tag(alert_lines,  "UNKNOWN_DEVICE")
    spoof_count      = _count_events_by_tag(alert_lines,  "SPOOF_DETECTED")
    connected_count  = _count_events_by_tag(event_lines,  "USB_CONNECTED")
    authorized_count = _count_events_by_tag(event_lines,  "DEVICE_AUTHORIZED")
    high_risk_count  = _count_events_by_tag(event_lines,  "HIGH_RISK_TRANSFER")

    threat_posture = (
        "CRITICAL" if (blocked_count > 0 or spoof_count > 0) else
        "HIGH"     if unknown_count > 2 else
        "MEDIUM"   if unknown_count > 0 else
        "LOW"
    )

    lines = [
        _section_header("EXECUTIVE SUMMARY"),
        f"\n  Monitoring Period     : {datetime.now().strftime('%Y-%m-%d')}",
        f"  Report Generated At   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Overall Threat Level  : {threat_posture}",
        f"\n  ── Activity Overview ────────────────────────────────",
        f"  USB Connect Events    : {connected_count}",
        f"  Authorized Devices    : {authorized_count}",
        f"  Unknown Devices       : {unknown_count}",
        f"  Blocked Devices       : {blocked_count}",
        f"  Spoofing Attempts     : {spoof_count}",
        f"  File Transfer Events  : {total_transfers}",
        f"  High-Risk Transfers   : {high_risk_count}",
        f"  Total Security Alerts : {total_alerts}",
    ]
    return "\n".join(lines)


def _build_alert_section(alert_lines: list[str]) -> str:
    """Detailed breakdown of all security alerts raised during the session."""
    alerts = _extract_alert_payloads(alert_lines)

    if not alerts:
        return _section_header("SECURITY ALERTS") + "\n\n  No security alerts recorded.\n"

    output = [_section_header("SECURITY ALERTS")]

    for i, alert in enumerate(alerts, 1):
        output.append(f"\n  Alert #{i}")
        output.append(f"  {'─' * 40}")
        output.append(f"  Type        : {alert.get('alert_type', 'N/A')}")
        output.append(f"  Drive       : {alert.get('drive', 'N/A')}")
        output.append(f"  Fingerprint : {alert.get('fingerprint', 'N/A')}")
        output.append(f"  Timestamp   : {alert.get('timestamp', 'N/A')}")
        output.append(f"  Reason      : {alert.get('reason', 'N/A')}")

    return "\n".join(output)


def _build_transfer_section(transfer_lines: list[str]) -> str:
    """Summarize file transfer audit entries from the transfer audit log."""
    data_lines = [l for l in transfer_lines if "FILE_" in l]

    if not data_lines:
        return _section_header("FILE TRANSFER AUDIT") + "\n\n  No file transfers recorded.\n"

    output = [_section_header("FILE TRANSFER AUDIT")]
    output.append(f"\n  Total Transfer Events : {len(data_lines)}\n")

    high_risk = []
    for line in data_lines:
        json_match = re.search(r'\{.*\}', line)
        if not json_match:
            continue
        try:
            entry = json.loads(json_match.group())
            action   = entry.get("action", "?")
            drive    = entry.get("drive", "?")
            file_    = entry.get("file", "?")
            size_kb  = entry.get("size_kb", 0)
            ts       = entry.get("timestamp", "?")

            output.append(f"  [{action}] {Path(file_).name}")
            output.append(f"    Drive   : {drive}")
            output.append(f"    Size    : {size_kb} KB")
            output.append(f"    Time    : {ts}")
            output.append("")

            if size_kb > (50 * 1024):  # 50 MB
                high_risk.append(file_)
        except json.JSONDecodeError:
            continue

    if high_risk:
        output.append("  ⚠  HIGH-RISK TRANSFERS DETECTED:")
        for f in high_risk:
            output.append(f"    → {f}")

    return "\n".join(output)


def _build_recommendations(alert_lines: list[str]) -> str:
    """
    Generate context-aware security recommendations based on observed events.
    Mirrors the advisory output style of enterprise DLP and EDR tools.
    """
    blocked_count = _count_events_by_tag(alert_lines, "BLOCKED_DEVICE")
    unknown_count = _count_events_by_tag(alert_lines, "UNKNOWN_DEVICE")
    spoof_count   = _count_events_by_tag(alert_lines, "SPOOF_DETECTED")

    recs = [_section_header("SECURITY RECOMMENDATIONS")]

    if spoof_count > 0:
        recs.append("\n  🔴 CRITICAL — Label Spoofing Detected")
        recs.append("     Initiate an immediate incident response investigation.")
        recs.append("     Review physical access logs for the affected endpoint.")
        recs.append("     Consider deploying auto-block enforcement (see usb_blocker.py).")

    if blocked_count > 0:
        recs.append("\n  🔴 HIGH — Blocked Device Connection Attempt(s)")
        recs.append("     Review which user attempted to connect the blocked device.")
        recs.append("     Correlate with HR records if a terminated employee is suspected.")
        recs.append("     Escalate to CISO if device is a known attack tool (e.g. Rubber Ducky).")

    if unknown_count > 0:
        recs.append(f"\n  🟡 MEDIUM — {unknown_count} Unknown Device(s) Detected")
        recs.append("     Identify device owners and request authorization approval.")
        recs.append("     Add approved devices to allowlist.json with full fingerprint data.")
        recs.append("     Enforce a USB registration process for all removable media.")

    if not any([spoof_count, blocked_count, unknown_count]):
        recs.append("\n  🟢 LOW — No Threat Indicators Detected")
        recs.append("     Continue monitoring. Review logs weekly for anomalies.")
        recs.append("     Ensure allowlist and blocklist policies are kept up to date.")

    recs.append("\n  General Best Practices:")
    recs.append("     • Enable auto-block for BLOCKED and UNKNOWN status devices.")
    recs.append("     • Integrate alert logs with your SIEM (Splunk, Elastic, etc.).")
    recs.append("     • Schedule monthly USB inventory reviews.")
    recs.append("     • Train employees on acceptable use policy for removable media.")

    return "\n".join(recs)


# ─── Report Generator ──────────────────────────────────────────────────────────

def generate_report(output_path: Optional[Path] = None) -> str:
    """
    Generate a comprehensive USB security audit report.

    Aggregates data from all three log channels:
        - usb_events.log     → lifecycle and authorization events
        - alerts.log         → security alerts and threat detections
        - transfer_audit.log → file transfer records

    Returns the report as a string and writes it to disk.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    save_path = output_path or FINAL_REPORT_PATH

    event_lines    = _read_log(USB_EVENTS_LOG)
    alert_lines    = _read_log(ALERTS_LOG)
    transfer_lines = _read_log(TRANSFER_AUDIT_LOG)

    report_parts = [
        "=" * 62,
        "  SENTINELUSB — USB SECURITY AUDIT REPORT",
        "  Enterprise Endpoint Security Framework",
        "=" * 62,
        _build_executive_summary(event_lines, alert_lines, transfer_lines),
        _build_alert_section(alert_lines),
        _build_transfer_section(transfer_lines),
        _build_recommendations(alert_lines),
        _section_header("RAW EVENT LOG TAIL (Last 20 Entries)"),
        "",
    ]

    # Append last 20 lines of the event log for quick reference
    recent_events = [l for l in event_lines if "|" in l][-20:]
    for line in recent_events:
        report_parts.append(f"  {line}")

    report_parts += [
        "",
        "=" * 62,
        f"  END OF REPORT — Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 62,
    ]

    report_text = "\n".join(report_parts)

    with open(save_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    log_event("REPORT_GENERATED", f"Security report written to: {save_path}")
    return report_text


def print_report_summary() -> None:
    """Print report to console and save to disk."""
    print("\n  Generating security audit report...")
    report = generate_report()
    print(report)
    print(f"\n  Report saved to: {FINAL_REPORT_PATH}")