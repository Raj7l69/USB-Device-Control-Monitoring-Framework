"""
================================================================================
  SentinelUSB — USB Monitor (Main Orchestrator)
  Module  : usb_monitor.py
  Purpose : Entry point for the SentinelUSB framework. Detects USB device
            connection and removal events, triggers the authorization engine,
            starts file auditing on authorized drives, and logs all activity.
  Author  : SentinelUSB Framework
  Context : Blue Team / Endpoint Security / DLP / Insider Threat Prevention

  Architecture:
      usb_monitor.py          ← You are here (main loop)
          ├── authorization.py    Device fingerprinting + policy engine
          ├── file_auditor.py     Real-time file transfer monitoring
          ├── logger.py           Structured event/alert/transfer logging
          └── reporter.py         Audit report generation

  Usage:
      python usb_monitor.py
      python usb_monitor.py --report   (generate report and exit)
================================================================================
"""

import sys
import time
import argparse
import subprocess
import wmi
from datetime import datetime

from logger        import log_event, log_session_start, log_session_end
from authorization import build_device_profile, authorize_device, AuthorizationResult, print_authorization_report
from file_auditor  import start_auditing, stop_auditing
from reporter      import print_report_summary


# ─── Configuration ─────────────────────────────────────────────────────────────

POLL_INTERVAL        = 2     # Seconds between USB device scans
ENABLE_FILE_AUDITING = True  # Set False to disable file transfer monitoring

# FIX #5: Enable/disable actual drive ejection on BLOCKED devices
# Set True in production, False for demo/testing mode
ENFORCE_BLOCK = True


# ─── Console Display ───────────────────────────────────────────────────────────

def print_banner() -> None:
    print("""
╔══════════════════════════════════════════════════════════╗
║            SentinelUSB v2.0 — Endpoint Security          ║
║   USB Device Control & Monitoring Framework              ║
║                                                          ║
║   Modules: Monitor | Auth | File Auditor | Reporter      ║
╚══════════════════════════════════════════════════════════╝
    """)
    print("  [*] Threat Model  : Insider Threat / Data Exfiltration")
    print("  [*] Policy Mode   : Allowlist + Blocklist Enforcement")
    print("  [*] Auth Method   : Hardware Fingerprinting (VID/PID/Serial)")
    print("  [*] File Audit    :", "Enabled" if ENABLE_FILE_AUDITING else "Disabled")
    print("  [*] Block Enforce :", "ACTIVE" if ENFORCE_BLOCK else "MONITOR ONLY")
    print()


def print_usb_connected(drive_letter: str, volume_name: str,
                         total_gb: float, free_gb: float) -> None:
    volume = volume_name or "No Label"
    print(f"\n{'─' * 60}")
    print(f"  ⬆  USB DEVICE CONNECTED")
    print(f"{'─' * 60}")
    print(f"  Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Drive        : {drive_letter}")
    print(f"  Volume Label : {volume}  (unverified)")
    print(f"  Total Space  : {total_gb} GB")
    print(f"  Free Space   : {free_gb} GB")
    print(f"  Status       : Querying hardware fingerprint...")


def print_usb_removed(drive_letter: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  ⬇  USB DEVICE REMOVED")
    print(f"{'─' * 60}")
    print(f"  Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Drive : {drive_letter}")


# ─── Drive Data Extraction ─────────────────────────────────────────────────────

def get_removable_drives(c) -> dict:
    """
    Poll WMI for all currently connected removable drives.
    Returns: dict of DeviceID → Win32_LogicalDisk object
    """
    drives = {}
    for disk in c.Win32_LogicalDisk():
        if disk.DriveType == 2:  # DriveType 2 = Removable (USB)
            drives[disk.DeviceID] = disk
    return drives


def parse_disk_sizes(disk) -> tuple[float, float]:
    """Extract total and free space in GB from a Win32_LogicalDisk object."""
    try:
        total_gb = round(int(disk.Size)      / (1024 ** 3), 2) if disk.Size      else 0.0
        free_gb  = round(int(disk.FreeSpace) / (1024 ** 3), 2) if disk.FreeSpace else 0.0
    except (ValueError, TypeError):
        total_gb, free_gb = 0.0, 0.0
    return total_gb, free_gb


# ─── Enforcement ──────────────────────────────────────────────────────────────

def eject_drive(drive_letter: str) -> bool:
    """
    FIX #5: Actually enforce BLOCKED decision by ejecting the drive.

    Uses Windows 'mountvol' command to dismount the volume.
    This prevents data access even if the physical device stays connected.

    Returns True if ejection succeeded, False otherwise.
    """
    try:
        # Ensure format is like "F:" not "F:\\"
        letter = drive_letter.rstrip("\\").rstrip("/")
        if not letter.endswith(":"):
            letter += ":"

        result = subprocess.run(
            ["mountvol", letter, "/D"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            print(f"\n  🔒 DRIVE {letter} HAS BEEN EJECTED (BLOCKED policy enforced)")
            log_event("DRIVE_EJECTED",
                      f"Drive {letter} ejected due to BLOCKED policy.",
                      level="WARNING")
            return True
        else:
            print(f"\n  ⚠  Eject failed for {letter}: {result.stderr.strip()}")
            log_event("EJECT_FAILED",
                      f"Could not eject {letter}: {result.stderr.strip()}",
                      level="ERROR")
            return False

    except Exception as exc:
        log_event("EJECT_ERROR", f"Exception during eject of {drive_letter}: {exc}", level="ERROR")
        return False


# ─── Event Handlers ────────────────────────────────────────────────────────────

def handle_device_connected(disk) -> None:
    """
    Handle a USB device connection event end-to-end:
        1. Display connection info
        2. Build hardware fingerprint profile
        3. Run authorization policy check
        4. FIX #5: Enforce BLOCKED decision by ejecting drive
        5. Start file auditing if authorized or unknown
        6. Log the event
    """
    drive_letter = disk.DeviceID
    volume_name  = disk.VolumeName or "Unknown"
    total_gb, free_gb = parse_disk_sizes(disk)

    # ── Display raw connection info ──────────────────────────────────────────
    print_usb_connected(drive_letter, volume_name, total_gb, free_gb)

    log_event("USB_CONNECTED",
              f"Drive={drive_letter} | Label={volume_name} | "
              f"Total={total_gb}GB | Free={free_gb}GB")

    # ── Build device profile via hardware fingerprinting ─────────────────────
    print(f"  [*] Fingerprinting device hardware...")
    profile = build_device_profile(drive_letter, volume_name, total_gb, free_gb)

    log_event("DEVICE_FINGERPRINTED",
              f"Drive={drive_letter} | VID={profile.vendor_id} | "
              f"PID={profile.product_id} | Serial={profile.serial_number} | "
              f"Fingerprint={profile.hardware_fingerprint[:24]}...")

    # ── Run authorization decision ────────────────────────────────────────────
    auth_result = authorize_device(profile)
    print_authorization_report(auth_result)

    # FIX #5: Actually enforce BLOCKED status — eject the drive
    if auth_result["status"] == AuthorizationResult.BLOCKED:
        if ENFORCE_BLOCK:
            print(f"  🚫 ENFORCEMENT: Ejecting blocked device on {drive_letter}...")
            eject_drive(drive_letter)
        else:
            print(f"  ⚠  MONITOR MODE: Blocked device NOT ejected (ENFORCE_BLOCK=False)")
        return  # Do not start auditing blocked devices

    # ── Start file auditing (for authorized and unknown devices) ─────────────
    # We also audit UNKNOWN devices to build evidence in case of future incident
    if ENABLE_FILE_AUDITING:
        start_auditing(
            drive_letter       = drive_letter,
            device_fingerprint = profile.hardware_fingerprint,
        )


def handle_device_removed(drive_letter: str) -> None:
    """
    Handle a USB device removal event:
        1. Stop file auditing for this drive
        2. Display and log the removal
    """
    stop_auditing(drive_letter)
    print_usb_removed(drive_letter)
    log_event("USB_REMOVED", f"Drive={drive_letter} disconnected from endpoint.")


# ─── Main Monitor Loop ─────────────────────────────────────────────────────────

def run_monitor() -> None:
    """
    Core monitoring loop. Polls WMI every POLL_INTERVAL seconds to detect
    USB insertion/removal events and dispatch to the appropriate handlers.
    """
    print_banner()
    log_session_start()

    c = wmi.WMI()

    # ── Snapshot drives already connected at startup ──────────────────────────
    known_drives = get_removable_drives(c)
    if known_drives:
        print(f"  [*] {len(known_drives)} drive(s) already connected at startup:")
        for did, disk in known_drives.items():
            print(f"      • {did}  ({disk.VolumeName or 'No Label'})")
    else:
        print("  [*] No removable drives detected. Waiting for USB insertion...\n")

    print(f"\n  {'─' * 58}")
    print(f"  Monitoring started. Press Ctrl+C to stop and generate report.")
    print(f"  {'─' * 58}\n")

    try:
        while True:
            current_drives = get_removable_drives(c)
            current_ids    = set(current_drives.keys())
            known_ids      = set(known_drives.keys())

            # New devices connected since last poll
            for drive_id in current_ids - known_ids:
                handle_device_connected(current_drives[drive_id])

            # Devices removed since last poll
            for drive_id in known_ids - current_ids:
                handle_device_removed(drive_id)

            known_drives = current_drives
            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n\n  [*] Shutdown signal received. Stopping all auditors...")

        for drive_id in list(known_drives.keys()):
            stop_auditing(drive_id)

        log_session_end()

        print("\n  Generating final security report...")
        print_report_summary()
        print("\n  SentinelUSB stopped. Stay secure. 🛡\n")


# ─── CLI Entry Point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelUSB — Advanced USB Security Framework"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate an audit report from existing logs and exit."
    )
    args = parser.parse_args()

    if args.report:
        print_report_summary()
        sys.exit(0)

    run_monitor()


if __name__ == "__main__":
    main()