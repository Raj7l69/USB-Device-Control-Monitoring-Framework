"""
================================================================================
  SentinelUSB — File Transfer Auditor
  Module  : file_auditor.py
  Purpose : Monitor file system activity on authorized USB drives to detect
            potential data exfiltration, large transfers, or sensitive file
            access. Provides a real-time audit trail for insider threat
            investigations and DLP compliance.
  Author  : SentinelUSB Framework
  Context : Blue Team / DLP / Insider Threat / Data Exfiltration Prevention
================================================================================
"""

import os
import time
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional

from logger import log_event, log_transfer_event


# ─── Configuration ─────────────────────────────────────────────────────────────

# File extensions considered high-risk for exfiltration
HIGH_RISK_EXTENSIONS = {
    # Documents & Data
    ".docx", ".doc", ".xlsx", ".xls", ".pdf", ".pptx", ".csv",
    # Source Code
    ".py", ".js", ".ts", ".java", ".cpp", ".cs", ".go", ".rs",
    # Config & Secrets
    ".env", ".pem", ".key", ".pfx", ".config", ".json", ".yaml", ".yml",
    # Archives (potential data bundles)
    ".zip", ".tar", ".gz", ".7z", ".rar",
    # Databases
    ".db", ".sqlite", ".sql", ".mdb",
}

# Alert threshold — files larger than this are flagged regardless of type
LARGE_FILE_THRESHOLD_MB = 50

# Polling interval for directory snapshot comparison (seconds)
AUDIT_POLL_INTERVAL = 3


# ─── File Snapshot Engine ──────────────────────────────────────────────────────

def _snapshot_directory(root_path: str) -> dict[str, dict]:
    """
    Recursively snapshot all files in a directory.

    Returns:
        dict mapping file_path → {size, mtime, extension}

    Used to compute deltas between polling cycles to detect new or
    modified files without relying on OS-level file system hooks
    (which require elevated privileges on many enterprise systems).
    """
    snapshot = {}
    try:
        for dirpath, _, filenames in os.walk(root_path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                try:
                    stat = os.stat(full_path)
                    snapshot[full_path] = {
                        "size":      stat.st_size,
                        "mtime":     stat.st_mtime,
                        "extension": Path(filename).suffix.lower(),
                    }
                except (PermissionError, FileNotFoundError):
                    # File may be locked or deleted mid-scan
                    continue
    except PermissionError:
        log_event("AUDIT_ERROR", f"Permission denied scanning: {root_path}", level="WARNING")

    return snapshot


def _compute_file_hash(file_path: str, chunk_size: int = 65536) -> Optional[str]:
    """
    Compute SHA-256 hash of a file for integrity verification.
    Used in forensic-grade auditing to provide tamper-evident file records.
    Large files are read in chunks to avoid memory pressure.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


# ─── Risk Assessment ───────────────────────────────────────────────────────────

def assess_transfer_risk(file_path: str, size_bytes: int) -> tuple[str, str]:
    """
    Evaluate the risk level of a detected file transfer.

    Risk Scoring:
        HIGH    — High-risk extension OR large file (>50 MB)
        MEDIUM  — Moderate file size or potentially sensitive path
        LOW     — Small file with non-sensitive extension

    Returns:
        (risk_level, reason) tuple
    """
    ext     = Path(file_path).suffix.lower()
    size_mb = size_bytes / (1024 * 1024)
    name    = Path(file_path).name.lower()

    # ── HIGH risk triggers ───────────────────────────────────────────────────
    if ext in HIGH_RISK_EXTENSIONS:
        return "HIGH", f"High-risk file type: {ext}"

    if size_mb >= LARGE_FILE_THRESHOLD_MB:
        return "HIGH", f"Large file transfer: {size_mb:.1f} MB (threshold: {LARGE_FILE_THRESHOLD_MB} MB)"

    # Check for sensitive filename keywords
    sensitive_keywords = ["password", "secret", "credential", "private", "key", "token", "config"]
    if any(kw in name for kw in sensitive_keywords):
        return "HIGH", f"Sensitive filename keyword detected: {name}"

    # ── MEDIUM risk triggers ─────────────────────────────────────────────────
    if size_mb >= 10:
        return "MEDIUM", f"Moderate file size: {size_mb:.1f} MB"

    # ── LOW risk ─────────────────────────────────────────────────────────────
    return "LOW", "Standard file transfer"


# ─── Audit Monitor ─────────────────────────────────────────────────────────────

class USBTransferAuditor:
    """
    Real-time file transfer auditor for a mounted USB drive.

    Operates in a background thread, polling the USB drive for new or
    modified files. Compares snapshots between cycles to detect transfers
    and logs them with risk assessments.

    Design Note:
        This class intentionally uses snapshot diffing (not OS file watchers)
        to remain portable across Windows environments without requiring
        administrator-level API access for FileSystemWatcher setup.
    """

    def __init__(self,
                 drive_letter: str,
                 device_fingerprint: str,
                 alert_callback: Optional[Callable[[str, str, str], None]] = None):
        """
        Initialize the auditor for a specific drive.

        Parameters:
            drive_letter       : e.g. "E:"
            device_fingerprint : Hardware fingerprint of the USB device
            alert_callback     : Optional function(drive, file_path, risk_level)
                                 called when a high-risk transfer is detected
        """
        self.drive_letter        = drive_letter
        self.device_fingerprint  = device_fingerprint
        self.alert_callback      = alert_callback
        self._running            = False
        self._thread: Optional[threading.Thread] = None
        self._previous_snapshot: dict = {}

    def start(self) -> None:
        """Start the background audit monitoring thread."""
        self._running = True
        self._previous_snapshot = _snapshot_directory(self.drive_letter + "\\")
        self._thread = threading.Thread(
            target=self._audit_loop,
            name=f"USBAuditor-{self.drive_letter}",
            daemon=True
        )
        self._thread.start()
        log_event("AUDIT_START", f"File transfer auditing started on {self.drive_letter}")
        print(f"\n  [AUDITOR] Monitoring file activity on {self.drive_letter}...")

    def stop(self) -> None:
        """Gracefully stop the audit monitoring thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        log_event("AUDIT_STOP", f"File transfer auditing stopped on {self.drive_letter}")
        print(f"\n  [AUDITOR] Stopped monitoring {self.drive_letter}.")

    def _audit_loop(self) -> None:
        """
        Core polling loop: compare file snapshots each cycle and log
        any newly created or modified files as transfer events.
        """
        while self._running:
            time.sleep(AUDIT_POLL_INTERVAL)

            try:
                current_snapshot = _snapshot_directory(self.drive_letter + "\\")
            except Exception:
                continue

            # Detect new files
            new_files = set(current_snapshot) - set(self._previous_snapshot)
            for file_path in new_files:
                self._process_transfer(file_path, current_snapshot[file_path], action="WRITE")

            # Detect modified files (same path, different mtime or size)
            for file_path, meta in current_snapshot.items():
                if file_path in self._previous_snapshot:
                    prev = self._previous_snapshot[file_path]
                    if meta["mtime"] != prev["mtime"] or meta["size"] != prev["size"]:
                        self._process_transfer(file_path, meta, action="MODIFY")

            self._previous_snapshot = current_snapshot

    def _process_transfer(self, file_path: str, meta: dict, action: str) -> None:
        """
        Evaluate and log a single detected file transfer event.
        Triggers alert callback for high-risk transfers.
        """
        size_bytes = meta["size"]
        risk_level, risk_reason = assess_transfer_risk(file_path, size_bytes)

        log_transfer_event(
            drive_letter     = self.drive_letter,
            file_path        = file_path,
            file_size_bytes  = size_bytes,
            action           = action,
            fingerprint      = self.device_fingerprint,
        )

        size_kb = round(size_bytes / 1024, 2)
        risk_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk_level, "⚪")

        print(f"\n  [{risk_icon} FILE {action}] {Path(file_path).name}")
        print(f"    Path       : {file_path}")
        print(f"    Size       : {size_kb} KB")
        print(f"    Risk       : {risk_level} — {risk_reason}")
        print(f"    Time       : {datetime.now().strftime('%H:%M:%S')}")

        if risk_level == "HIGH":
            log_event(
                "HIGH_RISK_TRANSFER",
                f"Drive={self.drive_letter} | File={file_path} | "
                f"Size={size_kb}KB | Reason={risk_reason}",
                level="WARNING"
            )
            if self.alert_callback:
                self.alert_callback(self.drive_letter, file_path, risk_level)


# ─── Auditor Registry ──────────────────────────────────────────────────────────
# Track active auditors per drive so they can be stopped on USB removal.

_active_auditors: dict[str, USBTransferAuditor] = {}


def start_auditing(drive_letter: str,
                   device_fingerprint: str,
                   alert_callback: Optional[Callable] = None) -> None:
    """
    Start a transfer auditor for the given drive (if not already running).
    Called by usb_monitor.py after a device is authorized.
    """
    if drive_letter in _active_auditors:
        return  # Already auditing this drive

    auditor = USBTransferAuditor(drive_letter, device_fingerprint, alert_callback)
    auditor.start()
    _active_auditors[drive_letter] = auditor


def stop_auditing(drive_letter: str) -> None:
    """
    Stop the transfer auditor for a drive that has been removed.
    Called by usb_monitor.py on USB disconnect events.
    """
    auditor = _active_auditors.pop(drive_letter, None)
    if auditor:
        auditor.stop()