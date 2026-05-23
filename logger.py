"""
================================================================================
  SentinelUSB — Security Event Logger
  Module  : logger.py
  Purpose : Structured logging for USB security events, alerts, and audit
            trails. Provides separate log channels for events, alerts, and
            transfer activity — mirroring enterprise SIEM log architecture.
  Author  : SentinelUSB Framework
  Context : Blue Team / Endpoint Security / Audit Trail / Forensics
================================================================================
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path


# ─── Log File Paths ────────────────────────────────────────────────────────────

LOGS_DIR           = Path("logs")
USB_EVENTS_LOG     = LOGS_DIR / "usb_events.log"
ALERTS_LOG         = LOGS_DIR / "alerts.log"
TRANSFER_AUDIT_LOG = LOGS_DIR / "transfer_audit.log"


# ─── Initialization ────────────────────────────────────────────────────────────

def _ensure_log_dirs() -> None:
    """Ensure the logs/ directory exists before writing any log files."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _build_logger(name: str, filepath: Path, level=logging.INFO) -> logging.Logger:
    """
    Factory for creating a named file logger with structured formatting.
    Each logger writes to its own dedicated file, providing clean separation
    between event types — consistent with enterprise SIEM design patterns.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers if module is reloaded
    if logger.handlers:
        return logger

    handler = logging.FileHandler(filepath, encoding="utf-8")
    handler.setLevel(level)

    # Format: ISO timestamp | LEVEL | message
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


# ─── Logger Instances ──────────────────────────────────────────────────────────

_ensure_log_dirs()

_event_logger    = _build_logger("usb.events",   USB_EVENTS_LOG)
_alert_logger    = _build_logger("usb.alerts",   ALERTS_LOG,   level=logging.WARNING)
_transfer_logger = _build_logger("usb.transfer", TRANSFER_AUDIT_LOG)


# ─── Public Logging API ────────────────────────────────────────────────────────

def log_event(event_type: str, message: str, level: str = "INFO") -> None:
    """
    Log a general USB lifecycle event (connect, disconnect, authorization, etc.)

    Parameters:
        event_type : Category tag (e.g. "USB_CONNECTED", "DEVICE_AUTHORIZED")
        message    : Human-readable description of the event
        level      : Severity level string — "INFO", "WARNING", "ERROR"

    Output file: logs/usb_events.log
    """
    formatted = f"[{event_type}] {message}"
    level_upper = level.upper()

    if level_upper == "WARNING":
        _event_logger.warning(formatted)
    elif level_upper == "ERROR":
        _event_logger.error(formatted)
    else:
        _event_logger.info(formatted)


def log_alert(alert_type: str,
              drive_letter: str,
              fingerprint: str,
              reason: str) -> None:
    """
    Log a security alert. Called when a device is blocked, unknown, or
    shows signs of spoofing. These entries are high-priority and should
    be forwarded to a SIEM or analyst queue in a production deployment.

    Parameters:
        alert_type   : e.g. "BLOCKED_DEVICE", "SPOOF_DETECTED", "UNKNOWN_DEVICE"
        drive_letter : e.g. "E:"
        fingerprint  : SHA-256 hardware fingerprint (first 32 chars for readability)
        reason       : Detailed explanation of the alert trigger

    Output file: logs/alerts.log
    """
    payload = {
        "alert_type":  alert_type,
        "drive":       drive_letter,
        "fingerprint": fingerprint[:32] + "...",
        "reason":      reason,
        "timestamp":   datetime.now().isoformat(),
    }
    _alert_logger.warning(f"[{alert_type}] {json.dumps(payload)}")


def log_transfer_event(drive_letter: str,
                       file_path: str,
                       file_size_bytes: int,
                       action: str,
                       fingerprint: str = "N/A") -> None:
    """
    Log a file transfer event to or from a USB device.
    Used by file_auditor.py to create an immutable audit trail of data
    movement — critical for detecting data exfiltration by insider threats.

    Parameters:
        drive_letter     : USB drive letter (e.g. "E:")
        file_path        : Full path of the file being transferred
        file_size_bytes  : Size of file in bytes
        action           : "READ", "WRITE", "COPY", "DELETE"
        fingerprint      : Hardware fingerprint of the device (optional)

    Output file: logs/transfer_audit.log
    """
    size_kb = round(file_size_bytes / 1024, 2)
    payload = {
        "action":      action,
        "drive":       drive_letter,
        "file":        file_path,
        "size_kb":     size_kb,
        "fingerprint": fingerprint[:24] + "..." if fingerprint != "N/A" else "N/A",
        "timestamp":   datetime.now().isoformat(),
    }
    _transfer_logger.info(f"[FILE_{action}] {json.dumps(payload)}")


def log_session_start() -> None:
    """Log a monitoring session start marker across all log files."""
    marker = f"{'─' * 60}"
    session_tag = f"SESSION START — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    for logger in [_event_logger, _alert_logger, _transfer_logger]:
        logger.info(marker)
        logger.info(session_tag)
        logger.info(marker)


def log_session_end() -> None:
    """Log a monitoring session end marker across all log files."""
    marker = f"{'─' * 60}"
    session_tag = f"SESSION END   — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    for logger in [_event_logger, _alert_logger, _transfer_logger]:
        logger.info(session_tag)
        logger.info(marker)