"""
================================================================================
  SentinelUSB — Authorization Engine
  Module  : authorization.py
  Purpose : USB device fingerprinting, policy enforcement, and allowlist/
            blocklist evaluation. Detects unauthorized, spoofed, or renamed
            USB devices using hardware-level identifiers — NOT volume labels.
  Author  : SentinelUSB Framework
  Context : Blue Team / Endpoint Security / DLP / Insider Threat Prevention
================================================================================
"""

import os
import re
import json
import hashlib
import wmi
import winreg
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional

# FIX: Enable ANSI color codes on Windows terminal
# Without this, color codes print as raw text e.g. ←[93mSUSPICIOUS←[0m
os.system("")

from logger import log_event, log_alert


# ─── Constants ────────────────────────────────────────────────────────────────

ALLOWLIST_PATH = "allowlist.json"
BLOCKLIST_PATH = "blocklist.json"

# WMI query target — USB-attached PnP devices
WMI_USB_QUERY = "SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'DiskDrive' OR PNPClass = 'USB'"

# Registry path for USB device history (useful for audit / forensics)
USB_REGISTRY_PATH = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"


# ─── Data Model ───────────────────────────────────────────────────────────────

@dataclass
class USBDeviceProfile:
    """
    Represents a fully fingerprinted USB device.
    Hardware identifiers are used for policy decisions — NOT volume labels,
    which can be trivially spoofed by an attacker or insider threat.
    """
    drive_letter:         str
    volume_name:          str             # Untrusted — display only
    vendor_id:            Optional[str]
    product_id:           Optional[str]
    serial_number:        Optional[str]
    pnp_device_id:        Optional[str]
    manufacturer:         Optional[str]
    hardware_fingerprint: str             # SHA-256 of stable hardware identifiers
    first_seen:           str             # ISO timestamp of detection
    total_space_gb:       float
    free_space_gb:        float


# ─── Device Fingerprinting ────────────────────────────────────────────────────

def extract_vid_pid_serial(pnp_device_id: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parse Vendor ID, Product ID, and Serial Number from a PNPDeviceID string.

    PNPDeviceID format:
        USBSTOR\\DISK&VEN_SanDisk&PROD_Ultra&REV_1.00\\4C530001..._&0

    Security Note:
        These identifiers come directly from the USB controller layer and
        are significantly harder to spoof than volume names or drive labels.
    """
    vendor_id  = None
    product_id = None
    serial_num = None

    # FIX #1: Check for None OR empty string — both are invalid
    if not pnp_device_id or not pnp_device_id.strip():
        return vendor_id, product_id, serial_num

    # Vendor extraction — VEN_<name> or VID_<hex>
    vid_match = re.search(r'VEN_([^&\\]+)|VID_([0-9A-Fa-f]{4})', pnp_device_id)
    if vid_match:
        vendor_id = (vid_match.group(1) or vid_match.group(2)).strip()

    # Product extraction — PROD_<name> or PID_<hex>
    pid_match = re.search(r'PROD_([^&\\]+)|PID_([0-9A-Fa-f]{4})', pnp_device_id)
    if pid_match:
        product_id = (pid_match.group(1) or pid_match.group(2)).strip()

    # Serial Number — last path component before optional &suffix
    serial_match = re.search(r'\\([A-Za-z0-9_\-]{8,})(?:&\d+)?$', pnp_device_id)
    if serial_match:
        candidate = serial_match.group(1)
        if not candidate.startswith('&') and len(candidate) > 4:
            serial_num = candidate

    return vendor_id, product_id, serial_num


def compute_hardware_fingerprint(vendor_id: Optional[str],
                                  product_id: Optional[str],
                                  serial_number: Optional[str],
                                  pnp_device_id: Optional[str]) -> str:
    """
    Generate a deterministic SHA-256 fingerprint from hardware-level USB
    identifiers.

    FIX #6: If ALL fields are None/empty, return a sentinel value instead
    of hashing "None|None|None|None" — which would make every unidentified
    device share the same fingerprint and accidentally match policy entries.
    """
    # FIX #6: Guard against all-None fingerprint collision
    if not any([vendor_id, product_id, serial_number, pnp_device_id]):
        return "UNIDENTIFIABLE"

    raw = f"{vendor_id}|{product_id}|{serial_number}|{pnp_device_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def query_pnp_for_drive(drive_letter: str) -> Optional[dict]:
    """
    Cross-reference a logical drive letter with WMI PnP device data to
    extract hardware-level USB identifiers.
    """
    try:
        c = wmi.WMI()

        for disk in c.Win32_DiskDrive():
            if "USB" not in (disk.InterfaceType or "").upper():
                continue

            for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    if logical_disk.DeviceID.upper() == drive_letter.upper():
                        return {
                            "pnp_device_id": disk.PNPDeviceID,
                            "manufacturer":  disk.Manufacturer,
                            "model":         disk.Model,
                            # FIX #2: Strip whitespace properly before returning
                            "serial_number": (disk.SerialNumber or "").strip(),
                        }
    except Exception as exc:
        log_event("FINGERPRINT_ERROR", f"WMI query failed for {drive_letter}: {exc}", level="WARNING")

    return None


def build_device_profile(drive_letter: str,
                          volume_name: str,
                          total_gb: float,
                          free_gb: float) -> USBDeviceProfile:
    """
    Construct a complete USBDeviceProfile by combining logical disk data
    with hardware fingerprint data from the WMI PnP layer.
    """
    pnp_data = query_pnp_for_drive(drive_letter)

    pnp_device_id = None
    manufacturer  = None
    hw_serial     = None
    vendor_id     = None
    product_id    = None

    if pnp_data:
        pnp_device_id = pnp_data.get("pnp_device_id")
        manufacturer  = pnp_data.get("manufacturer")

        # FIX #2: Use .strip() and convert empty string to None
        raw_serial = (pnp_data.get("serial_number") or "").strip()
        hw_serial  = raw_serial if raw_serial else None

        vendor_id, product_id, parsed_serial = extract_vid_pid_serial(pnp_device_id or "")

        # Prefer the hardware serial from WMI over the PNP-parsed one
        if not hw_serial and parsed_serial:
            hw_serial = parsed_serial

    fingerprint = compute_hardware_fingerprint(vendor_id, product_id, hw_serial, pnp_device_id)

    # FIX (volume_name sanitization): Strip newlines/escape sequences to
    # prevent log injection attacks via crafted volume labels
    safe_volume_name = (volume_name or "").replace("\n", "").replace("\r", "").strip()

    return USBDeviceProfile(
        drive_letter         = drive_letter,
        volume_name          = safe_volume_name,
        vendor_id            = vendor_id,
        product_id           = product_id,
        serial_number        = hw_serial,
        pnp_device_id        = pnp_device_id,
        manufacturer         = manufacturer,
        hardware_fingerprint = fingerprint,
        first_seen           = datetime.now().isoformat(),
        total_space_gb       = total_gb,
        free_space_gb        = free_gb,
    )


# ─── Policy Engine ────────────────────────────────────────────────────────────

def _load_policy(path: str) -> list[dict]:
    """
    Load and parse a JSON policy file (allowlist or blocklist).

    FIX #4: Log a WARNING when the policy file is missing so the operator
    knows the file is gone — not just silently returning an empty list.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("devices", [])
    except FileNotFoundError:
        # FIX #4: Warn operator that policy file is missing
        log_event("POLICY_ERROR",
                  f"Policy file NOT FOUND: '{path}'. "
                  f"All devices will be treated as UNKNOWN until this is restored.",
                  level="WARNING")
        return []
    except json.JSONDecodeError as e:
        log_event("POLICY_ERROR", f"Malformed JSON in {path}: {e}", level="ERROR")
        return []


def _matches_policy_entry(profile: USBDeviceProfile, entry: dict) -> bool:
    """
    Evaluate whether a device profile matches a single policy entry.

    Matching Priority (most → least trusted):
        1. hardware_fingerprint  — strongest, tamper-resistant
        2. serial_number         — strong, but some devices lack a real serial
        3. vendor_id + product_id — moderate; identifies device model/class
        4. pnp_device_id         — full string match fallback

    FIX (whitespace): Use .strip() on both sides before comparing to avoid
    hidden whitespace mismatches between device values and policy file values.
    """
    checks = {
        "hardware_fingerprint": profile.hardware_fingerprint,
        "serial_number":        profile.serial_number,
        "vendor_id":            profile.vendor_id,
        "product_id":           profile.product_id,
        "pnp_device_id":        profile.pnp_device_id,
    }

    for field, device_value in checks.items():
        policy_value = entry.get(field)
        if policy_value is None:
            continue  # Field not specified in policy — skip

        # FIX: .strip() on both sides prevents whitespace mismatches
        if str(device_value or "").strip().lower() != str(policy_value).strip().lower():
            return False

    return True


def check_allowlist(profile: USBDeviceProfile) -> tuple[bool, Optional[dict]]:
    """
    Check if the device is explicitly authorized in the allowlist.

    Returns:
        (True, matched_entry)  — device is authorized
        (False, None)          — device is not in allowlist
    """
    entries = _load_policy(ALLOWLIST_PATH)
    for entry in entries:
        if _matches_policy_entry(profile, entry):
            return True, entry
    return False, None


def check_blocklist(profile: USBDeviceProfile) -> tuple[bool, Optional[dict]]:
    """
    Check if the device is explicitly blocked in the blocklist.

    Returns:
        (True, matched_entry)  — device is blocked (threat/policy violation)
        (False, None)          — device is not in blocklist
    """
    entries = _load_policy(BLOCKLIST_PATH)
    for entry in entries:
        if _matches_policy_entry(profile, entry):
            return True, entry
    return False, None


# ─── Spoofing Detection ────────────────────────────────────────────────────────

def detect_label_spoofing(profile: USBDeviceProfile) -> Optional[str]:
    """
    Detect if a device's volume label has been renamed to impersonate a
    known/trusted device name while its hardware fingerprint differs.

    FIX #3: Only run fingerprint comparison if the allowlist entry actually
    HAS a hardware_fingerprint set. Incomplete entries previously caused a
    blind spot where any device with a matching label would pass the check.
    """
    entries = _load_policy(ALLOWLIST_PATH)
    for entry in entries:
        entry_label = (entry.get("volume_name") or "").strip().lower()
        if not entry_label:
            continue

        if entry_label == profile.volume_name.strip().lower():
            expected_fp = entry.get("hardware_fingerprint", "").strip()

            # FIX #3: Skip entries that have no fingerprint — they can't verify identity
            if not expected_fp:
                log_event(
                    "SPOOF_CHECK_SKIPPED",
                    f"Allowlist entry for label '{profile.volume_name}' has no "
                    f"hardware_fingerprint — cannot verify device identity. "
                    f"Add fingerprint to allowlist.json for full protection.",
                    level="WARNING"
                )
                continue

            if expected_fp != profile.hardware_fingerprint:
                return (
                    f"LABEL SPOOF DETECTED: Volume '{profile.volume_name}' matches a "
                    f"known trusted label but hardware fingerprint DIFFERS. "
                    f"Expected: {expected_fp[:16]}... | "
                    f"Got: {profile.hardware_fingerprint[:16]}..."
                )
    return None


# ─── Authorization Decision ────────────────────────────────────────────────────

class AuthorizationResult:
    ALLOWED    = "ALLOWED"
    BLOCKED    = "BLOCKED"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN    = "UNKNOWN"


def authorize_device(profile: USBDeviceProfile) -> dict:
    """
    Central authorization decision point for a USB device.

    Decision Logic:
        1. Check blocklist first (explicit deny — highest priority)
        2. Check allowlist (explicit allow)
        3. Check for label spoofing (threat indicator)
        4. Default-deny: unknown devices are flagged as UNKNOWN

    NOTE: This function returns a decision dict. Actual enforcement
    (ejecting/disabling the drive) must be handled by the caller
    (usb_monitor.py) based on the returned status.
    """

    now = datetime.now().isoformat()

    # ── Step 1: Blocklist Check ──────────────────────────────────────────────
    is_blocked, block_entry = check_blocklist(profile)

    if is_blocked:
        reason = (
            f"Device matches BLOCKLIST entry: "
            f"{block_entry.get('description', 'No description provided')}"
        )
        log_alert(
            "BLOCKED_DEVICE",
            profile.drive_letter,
            profile.hardware_fingerprint,
            reason
        )
        return {
            "status":       AuthorizationResult.BLOCKED,
            "reason":       reason,
            "threat_level": "CRITICAL",
            "policy_match": block_entry,
            "profile":      asdict(profile),
            "evaluated_at": now,
        }

    # ── Step 2: Allowlist Check ──────────────────────────────────────────────
    is_allowed, allow_entry = check_allowlist(profile)

    if is_allowed:
        reason = (
            f"Device matches ALLOWLIST entry: "
            f"{allow_entry.get('description', 'Authorized device')}"
        )
        log_event("DEVICE_AUTHORIZED", f"{profile.drive_letter} | {reason}")
        return {
            "status":       AuthorizationResult.ALLOWED,
            "reason":       reason,
            "threat_level": "LOW",
            "policy_match": allow_entry,
            "profile":      asdict(profile),
            "evaluated_at": now,
        }

    # ── Step 3: Spoofing Detection ───────────────────────────────────────────
    spoof_warning = detect_label_spoofing(profile)

    if spoof_warning:
        log_alert(
            "SPOOF_DETECTED",
            profile.drive_letter,
            profile.hardware_fingerprint,
            spoof_warning
        )
        return {
            "status":       AuthorizationResult.SUSPICIOUS,
            "reason":       spoof_warning,
            "threat_level": "HIGH",
            "policy_match": None,
            "profile":      asdict(profile),
            "evaluated_at": now,
        }

    # ── Step 4: Default Deny — Unknown Device ────────────────────────────────
    reason = (
        f"Device not found in allowlist or blocklist. "
        f"Fingerprint: {profile.hardware_fingerprint[:24]}... — flagged as UNKNOWN."
    )
    log_alert(
        "UNKNOWN_DEVICE",
        profile.drive_letter,
        profile.hardware_fingerprint,
        reason
    )
    return {
        "status":       AuthorizationResult.UNKNOWN,
        "reason":       reason,
        "threat_level": "MEDIUM",
        "policy_match": None,
        "profile":      asdict(profile),
        "evaluated_at": now,
    }


# ─── Console Output ────────────────────────────────────────────────────────────

def print_authorization_report(result: dict) -> None:
    """
    Render a structured authorization decision report to the console.
    Color-coded by threat level for operator readability.
    """
    status       = result["status"]
    threat       = result["threat_level"]
    profile_data = result["profile"]

    colors = {
        "ALLOWED":    "\033[92m",   # Green
        "BLOCKED":    "\033[91m",   # Red
        "SUSPICIOUS": "\033[93m",   # Yellow
        "UNKNOWN":    "\033[94m",   # Blue
    }
    RESET = "\033[0m"
    color = colors.get(status, "")

    status_icons = {
        "ALLOWED":    "✅",
        "BLOCKED":    "🚫",
        "SUSPICIOUS": "⚠️",
        "UNKNOWN":    "❓",
    }
    icon = status_icons.get(status, "•")

    print(f"\n{'═' * 58}")
    print(f"  {icon}  AUTHORIZATION DECISION: {color}{status}{RESET}  │  Threat: {threat}")
    print(f"{'═' * 58}")
    print(f"  Drive         : {profile_data['drive_letter']}")
    print(f"  Volume Label  : {profile_data['volume_name']}  (untrusted — display only)")
    print(f"  Vendor ID     : {profile_data['vendor_id'] or 'N/A'}")
    print(f"  Product ID    : {profile_data['product_id'] or 'N/A'}")
    print(f"  Serial Number : {profile_data['serial_number'] or 'N/A'}")
    print(f"  Manufacturer  : {profile_data['manufacturer'] or 'N/A'}")
    print(f"  Fingerprint   : {profile_data['hardware_fingerprint'][:32]}...")
    print(f"  Evaluated At  : {result['evaluated_at']}")
    print(f"{'─' * 58}")
    print(f"  Decision      : {color}{result['reason']}{RESET}")
    print(f"{'═' * 58}\n")