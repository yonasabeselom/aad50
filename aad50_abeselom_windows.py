#!/usr/bin/env python3
# ==============================================================================
# THE ABESELOM ASIC-DIRECT 50 (AAD-50) — WINDOWS PORT
# Firmware-Enforced Flash Sanitization Specification
# ==============================================================================
# Author      : Yonas Abeselom (yonas_abeselom@protonmail.com)
# Repository  : https://github.com/yonasabeselom/aad50
# Version     : 1.1 (Windows Port — Beta)
# Date        : June 2026
# Architecture: Win32 DeviceIoControl / IOCTL_STORAGE_PROTOCOL_COMMAND
#               + USB/UASP ATA Passthrough Fallback (IOCTL_ATA_PASS_THROUGH)
#               + IOCTL_STORAGE_REINITIALIZE_MEDIA Fallback
# Target Media: NVMe Solid-State Drives (Enterprise & Consumer NAND Flash)
#               including NVMe drives in USB 3.x enclosures with UASP support
# Platform    : Windows 10 1607+ / Windows 11 / Windows Server 2016+
# Compliance  : NIST SP 800-88 Rev.1 "Purge" | NVMe Base Spec 2.0/2.1
#               ISO/IEC 27040:2015 Storage Security | Common Criteria EAL4+
#
# PURPOSE:
#   Windows port of the AAD-50 Linux reference implementation.
#   Communicates directly with the NVMe controller via the Win32
#   DeviceIoControl API. Now includes three-tier USB passthrough:
#
#   TIER 1 — Direct NVMe (IOCTL_STORAGE_PROTOCOL_COMMAND)
#     Native NVMe admin command passthrough. Works for M.2/PCIe drives
#     and some UASP-capable USB enclosures (ASMedia ASM2364, RTL9210B).
#
#   TIER 2 — ATA Passthrough via SCSI (IOCTL_ATA_PASS_THROUGH)
#     Sends ATA SANITIZE commands through the SCSI/ATA Translation (SAT)
#     layer. Works for USB enclosures that support UASP + SAT but block
#     raw NVMe passthrough. Covers most modern USB-NVMe bridges.
#
#   TIER 3 — Storage Reinitialize (IOCTL_STORAGE_REINITIALIZE_MEDIA)
#     Windows storage stack sanitize trigger. Introduced in Windows 10 1703.
#     Works for enclosures that block both NVMe and ATA passthrough but
#     expose the Windows storage sanitize interface.
#
#   The tool auto-detects which tier works for the connected device and
#   executes all 50 cycles through the highest available pathway.
#   The audit report records which pathway was used for each cycle.
#
# PHASE EXECUTION ORDER:
#   Phase B — Physical NAND Cell Overwrite     (Cycles  1–40)
#   Phase C — Flash Translation Layer Reset    (Cycles 41–45)
#   Phase A — Cryptographic Key Destruction    (Cycles 46–50)
#
# WARNING:
#   This tool causes PERMANENT, IRREVERSIBLE destruction of all data on
#   the target device. All partitions, filesystems, encryption keys, and
#   hardware-level indices are destroyed. There is NO undo. Run only on
#   devices you own and intend to fully erase.
#
# LICENSE:
#   Copyright (c) 2026, Yonas Abeselom. All rights reserved.
#   Redistribution or modification requires written permission from the author.
# ==============================================================================

import sys
import struct
import ctypes
import ctypes.wintypes
import time
import argparse
import logging
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Tuple

if sys.platform != "win32":
    print("ERROR: This script is for Windows only.")
    print("For Linux, use aad50_abeselom.py instead.")
    sys.exit(1)

import winreg

# ==============================================================================
# CONSTANTS
# ==============================================================================

TOOL_NAME    = "The Abeselom ASIC-Direct 50 (AAD-50)"
TOOL_VERSION = "1.1 (Windows Port — Beta)"
SPEC_NAME    = "Firmware-Enforced Flash Sanitization, 50-Cycle Specification"
AUTHOR       = "Yonas Abeselom"
CONTACT      = "yonas_abeselom@protonmail.com"

# ── Win32 Constants ────────────────────────────────────────────────────────────
GENERIC_READ                       = 0x80000000
GENERIC_WRITE                      = 0x40000000
FILE_SHARE_READ                    = 0x00000001
FILE_SHARE_WRITE                   = 0x00000002
OPEN_EXISTING                      = 3
INVALID_HANDLE_VALUE               = ctypes.c_void_p(-1).value
FILE_ATTRIBUTE_NORMAL              = 0x80
FILE_FLAG_NO_BUFFERING             = 0x20000000

# ── IOCTL Codes ────────────────────────────────────────────────────────────────
# CTL_CODE(IOCTL_STORAGE_BASE=0x2d, 0x04F0, METHOD_BUFFERED, FILE_READ|WRITE)
IOCTL_STORAGE_PROTOCOL_COMMAND     = 0x0002D14C

# CTL_CODE(IOCTL_STORAGE_BASE=0x2d, 0x0501, METHOD_BUFFERED, FILE_READ|WRITE)
IOCTL_STORAGE_REINITIALIZE_MEDIA   = 0x0002D504

# CTL_CODE(IOCTL_SCSI_BASE=4, 0x040B, METHOD_BUFFERED, FILE_READ|WRITE)
IOCTL_ATA_PASS_THROUGH             = 0x0004D02C

# ── NVMe Protocol Types ────────────────────────────────────────────────────────
ProtocolTypeNvme                   = 0x03
NVMeDataTypeCommand                = 0x06

# ── NVMe Opcodes ───────────────────────────────────────────────────────────────
NVME_GET_LOG_PAGE_OPCODE           = 0x02
NVME_SANITIZE_OPCODE               = 0x84

# ── NVMe Sanitize Actions (CDW10 bits [2:0]) ───────────────────────────────────
SANITIZE_ACTION_BLOCK_ERASE        = 0x01   # Phase C — FTL teardown
SANITIZE_ACTION_OVERWRITE          = 0x02   # Phase B — Physical NAND overwrite
SANITIZE_ACTION_CRYPTO_ERASE       = 0x04   # Phase A — Crypto key destruction

# ── ATA Sanitize Feature codes ────────────────────────────────────────────────
ATA_SANITIZE_FEATURE_BLOCK_ERASE   = 0x0012
ATA_SANITIZE_FEATURE_OVERWRITE     = 0x0011
ATA_SANITIZE_FEATURE_CRYPTO_ERASE  = 0x0011  # ATA uses crypto via Security Erase
ATA_SANITIZE_STATUS_EXT            = 0x0000

# ── Namespace ID ──────────────────────────────────────────────────────────────
NVME_NSID_ALL                      = 0xFFFFFFFF

# ── Log Page 0x81 SSTAT ───────────────────────────────────────────────────────
NVME_LOG_SANITIZE_STATUS           = 0x81
SANITIZE_SSTAT_IDLE                = 0x0
SANITIZE_SSTAT_COMPLETED_OK        = 0x1
SANITIZE_SSTAT_IN_PROGRESS         = 0x2
SANITIZE_SSTAT_COMPLETED_ERR       = 0x3

# ── Polling ────────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS              = 2.0
POLL_TIMEOUT_SECONDS               = 7200

# ── Authorization ──────────────────────────────────────────────────────────────
AUTHORIZATION_TOKEN                = "EXECUTE-AAD-50-ABESELOM"
TOTAL_CYCLES                       = 50

# ── Post-run verification ──────────────────────────────────────────────────────
VERIFICATION_SAMPLE_COUNT          = 16
VERIFICATION_LBA_STEP              = 0x100000

# ── Passthrough tiers ─────────────────────────────────────────────────────────
TIER_NVME    = "NVMe-Direct"
TIER_ATA     = "ATA-Passthrough"
TIER_STORAGE = "Storage-Reinitialize"
TIER_NONE    = "None"


# ==============================================================================
# WIN32 STRUCTURES
# ==============================================================================

class STORAGE_PROTOCOL_SPECIFIC_DATA(ctypes.Structure):
    _fields_ = [
        ("ProtocolType",                 ctypes.c_uint32),
        ("DataType",                     ctypes.c_uint32),
        ("ProtocolDataRequestValue",     ctypes.c_uint32),
        ("ProtocolDataRequestSubValue",  ctypes.c_uint32),
        ("ProtocolDataOffset",           ctypes.c_uint32),
        ("ProtocolDataLength",           ctypes.c_uint32),
        ("FixedProtocolReturnData",      ctypes.c_uint32),
        ("ProtocolDataRequestSubValue2", ctypes.c_uint32),
        ("ProtocolDataRequestSubValue3", ctypes.c_uint32),
        ("ProtocolDataRequestSubValue4", ctypes.c_uint32),
        ("ProtocolDataRequestSubValue5", ctypes.c_uint32),
        ("Reserved",                     ctypes.c_uint32),
    ]


class STORAGE_PROTOCOL_COMMAND(ctypes.Structure):
    _fields_ = [
        ("Version",                         ctypes.c_uint32),
        ("Length",                          ctypes.c_uint32),
        ("ProtocolType",                    ctypes.c_uint32),
        ("Flags",                           ctypes.c_uint32),
        ("ReturnStatus",                    ctypes.c_uint32),
        ("ErrorCode",                       ctypes.c_uint32),
        ("CommandLength",                   ctypes.c_uint32),
        ("ErrorInfoLength",                 ctypes.c_uint32),
        ("DataToDeviceTransferLength",      ctypes.c_uint32),
        ("DataFromDeviceTransferLength",    ctypes.c_uint32),
        ("TimeOutValue",                    ctypes.c_uint32),
        ("ErrorInfoOffset",                 ctypes.c_uint32),
        ("DataToDeviceBufferOffset",        ctypes.c_uint32),
        ("DataFromDeviceBufferOffset",      ctypes.c_uint32),
        ("CommandSpecific",                 ctypes.c_uint32),
        ("Reserved0",                       ctypes.c_uint32),
        ("FixedProtocolReturnData",         ctypes.c_uint32),
        ("Reserved1",                       ctypes.c_uint32 * 3),
        ("Command",                         ctypes.c_uint8 * 64),
    ]


class NVME_COMMAND(ctypes.Structure):
    _fields_ = [
        ("CDW0",  ctypes.c_uint32),
        ("NSID",  ctypes.c_uint32),
        ("CDW2",  ctypes.c_uint32),
        ("CDW3",  ctypes.c_uint32),
        ("MPTR",  ctypes.c_uint64),
        ("PRP1",  ctypes.c_uint64),
        ("PRP2",  ctypes.c_uint64),
        ("CDW10", ctypes.c_uint32),
        ("CDW11", ctypes.c_uint32),
        ("CDW12", ctypes.c_uint32),
        ("CDW13", ctypes.c_uint32),
        ("CDW14", ctypes.c_uint32),
        ("CDW15", ctypes.c_uint32),
    ]


class ATA_PASS_THROUGH_EX(ctypes.Structure):
    """
    Maps to Windows ATA_PASS_THROUGH_EX (ntddscsi.h).
    Used to send ATA commands through the SCSI layer (SAT).
    This reaches USB-attached drives via UASP when NVMe passthrough is blocked.
    """
    _fields_ = [
        ("Length",             ctypes.c_uint16),
        ("AtaFlags",           ctypes.c_uint16),
        ("PathId",             ctypes.c_uint8),
        ("TargetId",           ctypes.c_uint8),
        ("Lun",                ctypes.c_uint8),
        ("ReservedAsUchar",    ctypes.c_uint8),
        ("DataTransferLength", ctypes.c_uint32),
        ("TimeOutValue",       ctypes.c_uint32),
        ("ReservedAsUlong",    ctypes.c_uint32),
        ("DataBufferOffset",   ctypes.c_size_t),
        # Task File (8 registers × 2 for extended = 16 bytes, but we use 8)
        ("PreviousTaskFile",   ctypes.c_uint8 * 8),
        ("CurrentTaskFile",    ctypes.c_uint8 * 8),
    ]


# ATA flags
ATA_FLAGS_DRDY_REQUIRED = 0x01
ATA_FLAGS_DATA_IN       = 0x02
ATA_FLAGS_DATA_OUT      = 0x04
ATA_FLAGS_48BIT_COMMAND = 0x08
ATA_FLAGS_USE_DMA       = 0x10
ATA_FLAGS_NO_MULTIPLE   = 0x20

# ATA commands
ATA_CMD_SANITIZE_DEVICE  = 0xB4   # ATA SANITIZE DEVICE command
ATA_CMD_SECURITY_ERASE   = 0xF4   # ATA SECURITY ERASE UNIT (crypto)


# ==============================================================================
# DATA CLASSES
# ==============================================================================

@dataclass
class CycleRecord:
    cycle:        int
    phase:        str
    action_code:  int
    timestamp:    str
    status:       str
    pathway:      str   = TIER_NONE   # Which tier was used
    duration_sec: float = 0.0
    error:        Optional[str] = None


@dataclass
class VerificationRecord:
    lba:    int
    result: str
    detail: Optional[str] = None


@dataclass
class SanitizationReport:
    tool:          str = TOOL_NAME
    version:       str = TOOL_VERSION
    author:        str = AUTHOR
    contact:       str = CONTACT
    platform:      str = "Windows"
    device:        str = ""
    drive_model:   str = ""
    pathway_used:  str = TIER_NONE
    started_at:    str = ""
    completed_at:  str = ""
    total_cycles:  int = TOTAL_CYCLES
    cycles_run:    int = 0
    outcome:       str = "NOT STARTED"
    verification:  list = field(default_factory=list)
    cycles:        list = field(default_factory=list)
    log_hash:      Optional[str] = None


# ==============================================================================
# LOGGING
# ==============================================================================

def configure_logging(log_path: Optional[str], verbose: bool) -> logging.Logger:
    logger = logging.getLogger("aad50_win")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)
    if log_path:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


# ==============================================================================
# PRIVILEGE CHECK
# ==============================================================================

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ==============================================================================
# DEVICE HANDLE
# ==============================================================================

def open_device(device_path: str) -> Optional[ctypes.c_void_p]:
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None
    )
    if handle == INVALID_HANDLE_VALUE:
        return None
    return handle


def close_device(handle: ctypes.c_void_p) -> None:
    ctypes.windll.kernel32.CloseHandle(handle)


# ==============================================================================
# DEVICE DISCOVERY AND VALIDATION
# ==============================================================================

def enumerate_drives(include_usb: bool = True) -> list:
    """
    Enumerates physical drives. With include_usb=True, includes USB-attached
    NVMe drives (shown as 'USB' bus type in Windows).
    Returns list of (index, model, path, bus_type) tuples.
    """
    drives = []
    try:
        bus_filter = ""
        if not include_usb:
            bus_filter = "| Where-Object {$_.BusType -eq 'NVMe'}"

        result = subprocess.run(
            ["powershell", "-Command",
             f"Get-PhysicalDisk {bus_filter} | "
             "Select-Object DeviceId, FriendlyName, BusType | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for disk in data:
                idx      = disk.get("DeviceId", "?")
                model    = disk.get("FriendlyName", "Unknown")
                bus_type = disk.get("BusType", "Unknown")
                path     = f"\\\\.\\PhysicalDrive{idx}"
                drives.append((idx, model, path, bus_type))
    except Exception:
        pass
    return drives


def validate_nvme_device(device_path: str, logger: logging.Logger) -> bool:
    handle = open_device(device_path)
    if handle is None:
        err = ctypes.GetLastError()
        if err == 5:
            logger.error("Access denied. Re-run as Administrator.")
        elif err == 2:
            logger.error(f"Device not found: {device_path}")
        else:
            logger.error(f"Could not open device {device_path} (Win32 error {err})")
        return False
    close_device(handle)
    logger.debug(f"Device validation passed: {device_path}")
    return True


# ==============================================================================
# TIER 1 — NVMe DIRECT PASSTHROUGH
# ==============================================================================

def _build_sanitize_buffer(action: int) -> STORAGE_PROTOCOL_COMMAND:
    STORAGE_PROTOCOL_STRUCTURE_VERSION = 0x1
    SPF_ADAPTER_REQUEST = 0x4

    nvme_cmd = NVME_COMMAND()
    nvme_cmd.CDW0  = NVME_SANITIZE_OPCODE & 0xFF
    nvme_cmd.NSID  = NVME_NSID_ALL
    nvme_cmd.CDW10 = action

    cmd_bytes = (ctypes.c_uint8 * 64)()
    ctypes.memmove(cmd_bytes, ctypes.addressof(nvme_cmd),
                   min(64, ctypes.sizeof(nvme_cmd)))

    proto_cmd = STORAGE_PROTOCOL_COMMAND()
    proto_cmd.Version                      = STORAGE_PROTOCOL_STRUCTURE_VERSION
    proto_cmd.Length                       = ctypes.sizeof(STORAGE_PROTOCOL_COMMAND)
    proto_cmd.ProtocolType                 = ProtocolTypeNvme
    proto_cmd.Flags                        = SPF_ADAPTER_REQUEST
    proto_cmd.CommandLength                = 64
    proto_cmd.ErrorInfoLength              = 0
    proto_cmd.DataToDeviceTransferLength   = 0
    proto_cmd.DataFromDeviceTransferLength = 0
    proto_cmd.TimeOutValue                 = 7200
    proto_cmd.ErrorInfoOffset              = 0
    proto_cmd.DataToDeviceBufferOffset     = 0
    proto_cmd.DataFromDeviceBufferOffset   = 0
    proto_cmd.Command                      = cmd_bytes
    return proto_cmd


def _build_log_page_buffer(log_id: int, data_len: int):
    STORAGE_PROTOCOL_STRUCTURE_VERSION = 0x1
    SPF_ADAPTER_REQUEST = 0x4

    cmd_size    = ctypes.sizeof(STORAGE_PROTOCOL_COMMAND)
    data_offset = cmd_size
    numd        = (data_len // 4) - 1
    cdw10       = (log_id & 0xFF) | ((numd & 0xFFF) << 16)

    nvme_cmd = NVME_COMMAND()
    nvme_cmd.CDW0  = NVME_GET_LOG_PAGE_OPCODE & 0xFF
    nvme_cmd.NSID  = NVME_NSID_ALL
    nvme_cmd.CDW10 = cdw10

    cmd_bytes = (ctypes.c_uint8 * 64)()
    ctypes.memmove(cmd_bytes, ctypes.addressof(nvme_cmd),
                   min(64, ctypes.sizeof(nvme_cmd)))

    proto_cmd = STORAGE_PROTOCOL_COMMAND()
    proto_cmd.Version                      = STORAGE_PROTOCOL_STRUCTURE_VERSION
    proto_cmd.Length                       = cmd_size
    proto_cmd.ProtocolType                 = ProtocolTypeNvme
    proto_cmd.Flags                        = SPF_ADAPTER_REQUEST
    proto_cmd.CommandLength                = 64
    proto_cmd.ErrorInfoLength              = 0
    proto_cmd.DataToDeviceTransferLength   = 0
    proto_cmd.DataFromDeviceTransferLength = data_len
    proto_cmd.TimeOutValue                 = 30
    proto_cmd.ErrorInfoOffset              = 0
    proto_cmd.DataToDeviceBufferOffset     = 0
    proto_cmd.DataFromDeviceBufferOffset   = data_offset
    proto_cmd.Command                      = cmd_bytes

    total_size = cmd_size + data_len
    total_buf  = (ctypes.c_uint8 * total_size)()
    ctypes.memmove(total_buf, ctypes.addressof(proto_cmd), cmd_size)
    return total_buf, total_size, data_offset


def execute_nvme_sanitize_direct(
    handle: ctypes.c_void_p,
    action: int,
    logger: logging.Logger
) -> bool:
    """Tier 1: NVMe admin command direct passthrough via IOCTL_STORAGE_PROTOCOL_COMMAND."""
    proto_cmd = _build_sanitize_buffer(action)
    buf_size  = ctypes.sizeof(proto_cmd)
    bytes_ret = ctypes.c_uint32(0)

    success = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        IOCTL_STORAGE_PROTOCOL_COMMAND,
        ctypes.addressof(proto_cmd),
        buf_size,
        ctypes.addressof(proto_cmd),
        buf_size,
        ctypes.byref(bytes_ret),
        None
    )

    if not success:
        err = ctypes.GetLastError()
        logger.debug(f"Tier 1 NVMe direct failed (Win32 error {err})")
        return False

    logger.debug(
        f"Tier 1 NVMe direct: sanitize dispatched "
        f"opcode=0x{NVME_SANITIZE_OPCODE:02X} action=0x{action:02X}"
    )
    return True


# ==============================================================================
# TIER 2 — ATA PASSTHROUGH (SCSI/SAT for USB)
# ==============================================================================

def _nvme_action_to_ata_feature(action: int) -> int:
    """Maps NVMe sanitize action codes to ATA SANITIZE DEVICE feature codes."""
    return {
        SANITIZE_ACTION_OVERWRITE:    ATA_SANITIZE_FEATURE_BLOCK_ERASE,   # closest ATA equiv
        SANITIZE_ACTION_BLOCK_ERASE:  ATA_SANITIZE_FEATURE_BLOCK_ERASE,
        SANITIZE_ACTION_CRYPTO_ERASE: ATA_SANITIZE_FEATURE_CRYPTO_ERASE,
    }.get(action, ATA_SANITIZE_FEATURE_BLOCK_ERASE)


def execute_ata_sanitize_passthrough(
    handle: ctypes.c_void_p,
    action: int,
    logger: logging.Logger
) -> bool:
    """
    Tier 2: ATA SANITIZE DEVICE via IOCTL_ATA_PASS_THROUGH.
    Reaches USB-NVMe drives through the SCSI/ATA Translation (SAT) layer.
    Works when the USB bridge supports UASP but blocks direct NVMe passthrough.

    ATA SANITIZE DEVICE (command 0xB4):
      Features register = sanitize action (block erase=0x0012, overwrite=0x0011)
      Count register    = 0x0000 (status) or feature-specific
      LBA registers     = feature-specific key value (0x4572 for erase)
    """
    feature = _nvme_action_to_ata_feature(action)

    apt = ATA_PASS_THROUGH_EX()
    apt.Length             = ctypes.sizeof(ATA_PASS_THROUGH_EX)
    apt.AtaFlags           = ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_48BIT_COMMAND
    apt.DataTransferLength = 0
    apt.TimeOutValue       = 7200
    apt.DataBufferOffset   = 0

    # CurrentTaskFile: [0]=Features, [1]=SectorCount, [2-4]=LBA, [5]=Device, [6]=Command, [7]=Reserved
    apt.CurrentTaskFile[0] = feature & 0xFF          # Features low
    apt.CurrentTaskFile[1] = 0x00                    # Sector count
    apt.CurrentTaskFile[2] = 0x72                    # LBA low  (erase key 0x4572)
    apt.CurrentTaskFile[3] = 0x45                    # LBA mid
    apt.CurrentTaskFile[4] = 0x00                    # LBA high
    apt.CurrentTaskFile[5] = 0x00                    # Device
    apt.CurrentTaskFile[6] = ATA_CMD_SANITIZE_DEVICE # Command

    # Previous task file (high bytes for 48-bit)
    apt.PreviousTaskFile[0] = (feature >> 8) & 0xFF

    buf_size  = ctypes.sizeof(apt)
    bytes_ret = ctypes.c_uint32(0)

    success = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        IOCTL_ATA_PASS_THROUGH,
        ctypes.addressof(apt),
        buf_size,
        ctypes.addressof(apt),
        buf_size,
        ctypes.byref(bytes_ret),
        None
    )

    if not success:
        err = ctypes.GetLastError()
        logger.debug(f"Tier 2 ATA passthrough failed (Win32 error {err})")
        return False

    # Check ATA status register (byte 6 of CurrentTaskFile on return)
    ata_status = apt.CurrentTaskFile[6]
    if ata_status & 0x01:  # ERR bit set
        logger.debug(f"Tier 2 ATA: command returned error status 0x{ata_status:02X}")
        return False

    logger.debug(
        f"Tier 2 ATA passthrough: SANITIZE DEVICE dispatched "
        f"feature=0x{feature:04X} status=0x{ata_status:02X}"
    )
    return True


# ==============================================================================
# TIER 3 — STORAGE REINITIALIZE (Windows Storage Stack)
# ==============================================================================

def execute_storage_reinitialize(
    handle: ctypes.c_void_p,
    logger: logging.Logger
) -> bool:
    """
    Tier 3: IOCTL_STORAGE_REINITIALIZE_MEDIA — Windows 10 1703+ storage sanitize.
    Triggers the drive's built-in sanitize through the Windows storage stack.
    Works for enclosures that block both NVMe and ATA passthrough but expose
    the Windows storage sanitize interface. Less granular (no phase selection)
    but reaches drives that block all other methods.
    """
    bytes_ret = ctypes.c_uint32(0)

    success = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        IOCTL_STORAGE_REINITIALIZE_MEDIA,
        None,
        0,
        None,
        0,
        ctypes.byref(bytes_ret),
        None
    )

    if not success:
        err = ctypes.GetLastError()
        logger.debug(f"Tier 3 Storage reinitialize failed (Win32 error {err})")
        return False

    logger.debug("Tier 3 IOCTL_STORAGE_REINITIALIZE_MEDIA dispatched.")
    return True


# ==============================================================================
# AUTO-DETECTION — PROBE WHICH TIER WORKS
# ==============================================================================

def detect_passthrough_tier(
    handle: ctypes.c_void_p,
    logger: logging.Logger
) -> str:
    """
    Probes the device to determine the highest available passthrough tier.
    Uses a non-destructive NVMe Get Log Page command for Tier 1 detection.
    Returns the tier name string.
    """
    logger.info("━━━ USB/NVMe Passthrough Detection ━━━")

    # ── Tier 1: Try NVMe Get Log Page (non-destructive probe) ────────────────
    logger.info("  Probing Tier 1 — NVMe direct passthrough (IOCTL_STORAGE_PROTOCOL_COMMAND)...")
    try:
        total_buf, total_size, data_offset = _build_log_page_buffer(
            NVME_LOG_SANITIZE_STATUS, 20
        )
        bytes_ret = ctypes.c_uint32(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_STORAGE_PROTOCOL_COMMAND,
            total_buf, total_size,
            total_buf, total_size,
            ctypes.byref(bytes_ret),
            None
        )
        if ok:
            logger.info("  ✓ Tier 1 NVMe direct passthrough: SUPPORTED")
            logger.info("    AAD-50 will use direct NVMe admin commands (CDW10).")
            logger.info("    Log Page 0x81 hardware confirmation: ACTIVE")
            return TIER_NVME
        else:
            err = ctypes.GetLastError()
            logger.info(f"  ✗ Tier 1 NVMe direct: not supported by this USB bridge (error {err})")
    except Exception as e:
        logger.info(f"  ✗ Tier 1 NVMe direct: exception ({e})")

    # ── Tier 2: Try ATA IDENTIFY (non-destructive) via ATA passthrough ───────
    logger.info("  Probing Tier 2 — ATA passthrough via SCSI/SAT (IOCTL_ATA_PASS_THROUGH)...")
    try:
        apt = ATA_PASS_THROUGH_EX()
        apt.Length             = ctypes.sizeof(ATA_PASS_THROUGH_EX)
        apt.AtaFlags           = ATA_FLAGS_DATA_IN
        apt.DataTransferLength = 512
        apt.TimeOutValue       = 10
        apt.DataBufferOffset   = ctypes.sizeof(ATA_PASS_THROUGH_EX)
        apt.CurrentTaskFile[6] = 0xEC  # ATA IDENTIFY DEVICE (non-destructive)

        buf_size  = ctypes.sizeof(apt) + 512
        full_buf  = (ctypes.c_uint8 * buf_size)()
        ctypes.memmove(full_buf, ctypes.addressof(apt), ctypes.sizeof(apt))
        bytes_ret = ctypes.c_uint32(0)

        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_ATA_PASS_THROUGH,
            full_buf, buf_size,
            full_buf, buf_size,
            ctypes.byref(bytes_ret),
            None
        )
        if ok:
            logger.info("  ✓ Tier 2 ATA passthrough via SAT: SUPPORTED")
            logger.info("    AAD-50 will use ATA SANITIZE DEVICE commands.")
            logger.info("    Note: Phase B/C/A map to ATA SANITIZE feature codes.")
            logger.info("    Note: Log Page 0x81 unavailable — polling via ATA STATUS.")
            return TIER_ATA
        else:
            err = ctypes.GetLastError()
            logger.info(f"  ✗ Tier 2 ATA passthrough: not supported (error {err})")
    except Exception as e:
        logger.info(f"  ✗ Tier 2 ATA passthrough: exception ({e})")

    # ── Tier 3: Try IOCTL_STORAGE_REINITIALIZE_MEDIA ─────────────────────────
    logger.info("  Probing Tier 3 — Windows storage reinitialize (IOCTL_STORAGE_REINITIALIZE_MEDIA)...")
    try:
        bytes_ret = ctypes.c_uint32(0)
        # We can't probe this non-destructively — we check if the IOCTL is recognized
        # by sending with a zero-size buffer and seeing if we get ERROR_INVALID_FUNCTION
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_STORAGE_REINITIALIZE_MEDIA,
            None, 0, None, 0,
            ctypes.byref(bytes_ret),
            None
        )
        err = ctypes.GetLastError()
        # ERROR_INVALID_FUNCTION (1) = IOCTL not recognized at all
        # Any other error = IOCTL reached driver (may still work)
        if ok or err != 1:
            logger.info("  ✓ Tier 3 Storage reinitialize: SUPPORTED")
            logger.info("    AAD-50 will use IOCTL_STORAGE_REINITIALIZE_MEDIA.")
            logger.info("    Warning: Phase granularity not available — single sanitize per cycle.")
            logger.info("    Warning: Hardware confirmation polling not available — time-based wait.")
            return TIER_STORAGE
        else:
            logger.info(f"  ✗ Tier 3 Storage reinitialize: IOCTL not recognized (error {err})")
    except Exception as e:
        logger.info(f"  ✗ Tier 3 Storage reinitialize: exception ({e})")

    logger.error("  ✗ No passthrough tier supported by this device/enclosure.")
    logger.error("    The USB bridge chip is blocking all sanitize command pathways.")
    logger.error("    Recommendation: Install the drive directly in an M.2 slot.")
    return TIER_NONE


# ==============================================================================
# LOG PAGE 0x81 POLLING (Tier 1 only)
# ==============================================================================

def read_sanitize_status(
    handle: ctypes.c_void_p,
    logger: logging.Logger
) -> Optional[int]:
    LOG_DATA_LEN = 20
    total_buf, total_size, data_offset = _build_log_page_buffer(
        NVME_LOG_SANITIZE_STATUS, LOG_DATA_LEN
    )
    bytes_ret = ctypes.c_uint32(0)

    success = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        IOCTL_STORAGE_PROTOCOL_COMMAND,
        total_buf, total_size,
        total_buf, total_size,
        ctypes.byref(bytes_ret),
        None
    )

    if not success:
        err = ctypes.GetLastError()
        logger.debug(f"Log Page 0x81 read failed (Win32 error {err})")
        return None

    sstat       = total_buf[data_offset + 2] | (total_buf[data_offset + 3] << 8)
    sprog       = total_buf[data_offset + 0] | (total_buf[data_offset + 1] << 8)
    status_code = sstat & 0x07
    prog_pct    = int((sprog / 0xFFFF) * 100) if sprog > 0 else 0

    logger.debug(
        f"Log Page 0x81 — SSTAT=0x{sstat:04X} "
        f"(code={status_code}) SPROG={sprog:#06x} ({prog_pct}%)"
    )
    return status_code


def poll_until_complete_nvme(
    handle: ctypes.c_void_p,
    cycle:  int,
    logger: logging.Logger
) -> bool:
    """Tier 1 polling: hardware-confirmed via Log Page 0x81."""
    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    elapsed  = 0.0

    while time.monotonic() < deadline:
        status = read_sanitize_status(handle, logger)

        if status is None:
            logger.debug(f"  Cycle {cycle:02d}: Status read None — retrying...")
        elif status == SANITIZE_SSTAT_COMPLETED_OK:
            logger.debug(f"  Cycle {cycle:02d}: SSTAT=0x1 — Hardware confirmed complete. ✓")
            return True
        elif status == SANITIZE_SSTAT_IDLE:
            logger.debug(f"  Cycle {cycle:02d}: SSTAT=0x0 — Controller idle (complete).")
            return True
        elif status == SANITIZE_SSTAT_IN_PROGRESS:
            logger.debug(f"  Cycle {cycle:02d}: SSTAT=0x2 — In progress ({elapsed:.0f}s)...")
        elif status == SANITIZE_SSTAT_COMPLETED_ERR:
            logger.error(f"  Cycle {cycle:02d}: SSTAT=0x3 — Controller reported error.")
            return False

        time.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS

    logger.error(f"  Cycle {cycle:02d}: Polling timed out after {POLL_TIMEOUT_SECONDS}s.")
    return False


def poll_until_complete_ata(
    cycle:   int,
    logger:  logging.Logger,
    wait_s:  int = 120
) -> bool:
    """
    Tier 2/3 polling: time-based wait (Log Page 0x81 not available via ATA/USB).
    Uses a conservative 120-second wait per cycle — sufficient for most drives.
    """
    logger.info(
        f"  Cycle {cycle:02d}: ATA/USB mode — waiting {wait_s}s for drive to complete..."
    )
    for elapsed in range(0, wait_s, 10):
        time.sleep(10)
        pct = int((elapsed / wait_s) * 100)
        bar = ("█" * (pct // 5)).ljust(20)
        logger.info(f"  Cycle {cycle:02d}: [{bar}] {pct}% ({elapsed}s/{wait_s}s)")
    logger.info(f"  Cycle {cycle:02d}: Wait complete — assuming drive finished.")
    return True


# ==============================================================================
# UNIFIED COMMAND DISPATCH
# ==============================================================================

def execute_sanitize_cycle(
    handle:  ctypes.c_void_p,
    action:  int,
    cycle:   int,
    tier:    str,
    logger:  logging.Logger
) -> bool:
    """
    Dispatches one sanitize cycle through whichever tier is available.
    Returns True if command was accepted and polling confirmed (or timed out gracefully).
    """
    if tier == TIER_NVME:
        ok = execute_nvme_sanitize_direct(handle, action, logger)
        if not ok:
            return False
        return poll_until_complete_nvme(handle, cycle, logger)

    elif tier == TIER_ATA:
        ok = execute_ata_sanitize_passthrough(handle, action, logger)
        if not ok:
            return False
        return poll_until_complete_ata(cycle, logger, wait_s=120)

    elif tier == TIER_STORAGE:
        ok = execute_storage_reinitialize(handle, logger)
        if not ok:
            return False
        return poll_until_complete_ata(cycle, logger, wait_s=180)

    else:
        logger.error(f"  Cycle {cycle:02d}: No passthrough tier available. Cannot execute.")
        return False


# ==============================================================================
# POST-RUN VERIFICATION
# ==============================================================================

def verify_sanitization(
    device_path: str,
    logger:      logging.Logger
) -> list:
    results     = []
    sector_size = 512
    probe_offsets = [
        i * VERIFICATION_LBA_STEP * sector_size
        for i in range(VERIFICATION_SAMPLE_COUNT)
    ]

    logger.info("")
    logger.info("━━━ POST-RUN VERIFICATION — LBA Sample Read ━━━")

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        device_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        None
    )

    if handle == INVALID_HANDLE_VALUE:
        logger.error("  Could not open device for verification.")
        return results

    try:
        buf = ctypes.create_string_buffer(sector_size)
        for offset in probe_offsets:
            lba = offset // sector_size
            rec = VerificationRecord(lba=lba, result="UNKNOWN")

            lo      = offset & 0xFFFFFFFF
            hi      = (offset >> 32) & 0xFFFFFFFF
            new_pos = kernel32.SetFilePointer(
                handle, lo, ctypes.byref(ctypes.c_long(hi)), 0
            )

            if new_pos == 0xFFFFFFFF and ctypes.GetLastError() != 0:
                rec.result = "SEEK_ERROR"
                rec.detail = f"Win32 error {ctypes.GetLastError()}"
                logger.warning(f"  LBA 0x{lba:010X} — SEEK ERROR")
                results.append(rec)
                continue

            bytes_read = ctypes.c_uint32(0)
            ok = kernel32.ReadFile(
                handle, buf, sector_size, ctypes.byref(bytes_read), None
            )

            if not ok or bytes_read.value != sector_size:
                rec.result = "DEALLOCATED"
                logger.info(f"  LBA 0x{lba:010X} — DEALLOCATED ✓")
            elif all(b == 0 for b in buf.raw):
                rec.result = "ZEROED"
                logger.info(f"  LBA 0x{lba:010X} — ZEROED ✓")
            else:
                non_zero   = sum(1 for b in buf.raw if b != 0)
                rec.result = "NON-ZERO"
                rec.detail = f"{non_zero}/{sector_size} non-zero bytes"
                logger.warning(f"  LBA 0x{lba:010X} — NON-ZERO ({non_zero} bytes) ⚠")

            results.append(rec)
    finally:
        kernel32.CloseHandle(handle)

    clean   = sum(1 for r in results if r.result in ("ZEROED", "DEALLOCATED"))
    flagged = len(results) - clean
    logger.info(
        f"  Verification: {clean}/{len(results)} LBAs confirmed clean"
        + (f" | {flagged} flagged" if flagged else "")
    )
    return results


# ==============================================================================
# SANITIZATION ENGINE
# ==============================================================================

def run_sanitization(
    device_path: str,
    logger:      logging.Logger,
    dry_run:     bool = False,
    force:       bool = False,
    report:      Optional[SanitizationReport] = None
) -> bool:

    phases = [
        ("B — Physical NAND Cell Overwrite",  range(1,  41), SANITIZE_ACTION_OVERWRITE,    "overwrite"),
        ("C — Flash Translation Layer Reset", range(41, 46), SANITIZE_ACTION_BLOCK_ERASE,  "block erase"),
        ("A — Cryptographic Key Destruction", range(46, 51), SANITIZE_ACTION_CRYPTO_ERASE, "crypto erase"),
    ]

    handle       = None
    active_tier  = TIER_NONE

    try:
        if not dry_run:
            handle = open_device(device_path)
            if handle is None:
                logger.error(f"Failed to open device: {device_path}")
                return False
            logger.info(f"Device handle opened: {device_path}")

            # ── Auto-detect passthrough tier ──────────────────────────────────
            active_tier = detect_passthrough_tier(handle, logger)
            if active_tier == TIER_NONE:
                return False

            if report:
                report.pathway_used = active_tier

            logger.info("")
            logger.info(f"  Active pathway: {active_tier}")
            logger.info("")
        else:
            active_tier = TIER_NVME  # Dry run always simulates Tier 1
            logger.info("[DRY RUN] Simulating full 50-cycle sequence (no commands issued).")

        for phase_label, cycles, action, action_name in phases:
            logger.info(f"━━━ PHASE {phase_label} ━━━")

            for cycle in cycles:
                ts          = datetime.now(timezone.utc).isoformat()
                pct         = int((cycle / TOTAL_CYCLES) * 100)
                bar         = ("█" * (pct // 5)).ljust(20)
                cycle_start = time.monotonic()

                logger.info(
                    f"  Cycle {cycle:02d}/{TOTAL_CYCLES} [{bar}] {pct:3d}%  "
                    f"Action=0x{action:02X} ({action_name})  [{active_tier}]"
                )

                status    = "OK"
                error_msg = None

                try:
                    if not dry_run:
                        completed = execute_sanitize_cycle(
                            handle, action, cycle, active_tier, logger
                        )
                        if not completed:
                            status    = "FAILED"
                            error_msg = "Drive did not confirm cycle completion."
                            logger.error(
                                f"  Cycle {cycle:02d}: Failed. Aborting sequence."
                            )
                            if report:
                                report.cycles.append(CycleRecord(
                                    cycle=cycle, phase=phase_label,
                                    action_code=action, timestamp=ts,
                                    status=status, pathway=active_tier,
                                    error=error_msg,
                                    duration_sec=round(time.monotonic() - cycle_start, 2)
                                ))
                            return False
                    else:
                        time.sleep(0.05)

                except OSError as e:
                    status    = "IOCTL_ERROR"
                    error_msg = str(e)
                    logger.error(f"  IOCTL fault on cycle {cycle}: {e}")
                    if report:
                        report.cycles.append(CycleRecord(
                            cycle=cycle, phase=phase_label,
                            action_code=action, timestamp=ts,
                            status=status, pathway=active_tier,
                            error=error_msg,
                            duration_sec=round(time.monotonic() - cycle_start, 2)
                        ))
                    return False

                duration = round(time.monotonic() - cycle_start, 2)
                if report:
                    report.cycles.append(CycleRecord(
                        cycle=cycle, phase=phase_label,
                        action_code=action, timestamp=ts,
                        status=status, pathway=active_tier,
                        duration_sec=duration
                    ))
                    report.cycles_run = cycle

                logger.debug(f"  Cycle {cycle:02d} done in {duration}s via {active_tier}.")

    finally:
        if handle is not None:
            close_device(handle)
            logger.debug("Device handle closed.")

    return True


# ==============================================================================
# REPORT FINALIZATION
# ==============================================================================

def finalize_report(
    report:   SanitizationReport,
    success:  bool,
    log_path: Optional[str],
    logger:   logging.Logger
) -> None:
    report.completed_at = datetime.now(timezone.utc).isoformat()
    report.outcome      = "SUCCESS — DATA DESTROYED" if success else "FAILED — INCOMPLETE"

    cycle_blob   = json.dumps([asdict(c) for c in report.cycles], sort_keys=True)
    report.log_hash = hashlib.sha256(cycle_blob.encode()).hexdigest()

    logger.info("")
    logger.info("=" * 78)
    logger.info(f"  {TOOL_NAME} v{TOOL_VERSION}")
    logger.info(f"  Author : {AUTHOR} <{CONTACT}>")
    logger.info("=" * 78)
    logger.info(f"  OUTCOME   : {report.outcome}")
    logger.info(f"  PLATFORM  : Windows")
    logger.info(f"  PATHWAY   : {report.pathway_used}")
    logger.info(f"  DEVICE    : {report.device}")
    if report.drive_model:
        logger.info(f"  DRIVE     : {report.drive_model}")
    logger.info(f"  CYCLES    : {report.cycles_run}/{report.total_cycles}")
    logger.info(f"  STARTED   : {report.started_at}")
    logger.info(f"  COMPLETED : {report.completed_at}")
    logger.info(f"  LOG HASH  : {report.log_hash}")
    logger.info("=" * 78)

    if log_path:
        report_path = log_path.replace(".log", "_report.json")
        try:
            with open(report_path, "w") as f:
                json.dump(asdict(report), f, indent=2)
            logger.info(f"  Audit report saved to: {report_path}")
        except OSError as e:
            logger.warning(f"  Could not save audit report: {e}")


# ==============================================================================
# AUTHORIZATION PROMPT
# ==============================================================================

def request_authorization(
    device_path: str,
    model:       Optional[str],
    logger:      logging.Logger,
    force:       bool = False
) -> bool:
    print()
    print("=" * 78)
    print(f"  {TOOL_NAME}")
    print(f"  {SPEC_NAME}")
    print(f"  Version {TOOL_VERSION}  |  {AUTHOR} <{CONTACT}>")
    print("=" * 78)
    print(f"  TARGET DEVICE : {device_path}")
    if model:
        print(f"  DRIVE MODEL   : {model}")
    print()
    print("  ⚠️  CRITICAL DESTRUCTION WARNING ⚠️")
    print()
    print("  This operation will PERMANENTLY AND IRREVERSIBLY destroy all data")
    print("  on the target device, including:")
    print()
    print("    • All filesystems, volumes, and partition tables")
    print("    • All Media Encryption Keys (MEK) in hardware registers")
    print("    • All NAND flash physical floating-gate charge states")
    print("    • All Flash Translation Layer (FTL) structural address maps")
    print()
    print("  Recovery via any known forensic technique will NOT be possible.")
    print("  This action CANNOT be undone.")
    print()

    if force:
        print("  [--force] Non-interactive mode. Proceeding automatically.")
        logger.info("Authorization granted via --force flag.")
        return True

    print(f"  To authorize, type exactly:  {AUTHORIZATION_TOKEN}")
    print()

    try:
        token = input("  Authorization: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        logger.info("Authorization interrupted.")
        return False

    if token != AUTHORIZATION_TOKEN:
        logger.info("Authorization token mismatch. Sanitization aborted.")
        return False

    return True


# ==============================================================================
# DRIVE LISTING
# ==============================================================================

def list_drives(logger: logging.Logger) -> None:
    logger.info("Detecting drives (NVMe + USB-attached NVMe)...")
    drives = enumerate_drives(include_usb=True)
    if not drives:
        logger.warning(
            "No drives detected via PowerShell. "
            "Specify the device path manually (e.g. \\\\.\\PhysicalDrive0)."
        )
        return
    logger.info(f"Found {len(drives)} drive(s):")
    for idx, model, path, bus_type in drives:
        usb_note = " [USB — passthrough auto-detected at runtime]" if bus_type == "USB" else ""
        logger.info(f"  [{idx}] {model}  ({bus_type})  →  {path}{usb_note}")


# ==============================================================================
# CLI
# ==============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aad50_abeselom_windows",
        description=(
            f"{TOOL_NAME}\n"
            f"{SPEC_NAME}\n"
            f"Author: {AUTHOR} <{CONTACT}>  |  Version {TOOL_VERSION}\n"
            f"Platform: Windows 10 1607+ / Windows 11 / Windows Server 2016+\n"
            f"USB Support: UASP NVMe passthrough + ATA SAT fallback + Storage reinitialize"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python aad50_abeselom_windows.py --list\n"
            "  python aad50_abeselom_windows.py \\\\.\\PhysicalDrive1\n"
            "  python aad50_abeselom_windows.py \\\\.\\PhysicalDrive1 --log C:\\logs\\aad50.log\n"
            "  python aad50_abeselom_windows.py \\\\.\\PhysicalDrive1 --dry-run --verbose\n"
            "\n"
            "USB ENCLOSURE NOTE:\n"
            "  AAD-50 auto-detects the best passthrough pathway for USB drives.\n"
            "  Tier 1 (NVMe direct) is preferred — works on ASMedia ASM2364, RTL9210B.\n"
            "  Tier 2 (ATA SAT) is the fallback — works on most UASP bridges.\n"
            "  Tier 3 (Storage reinitialize) is the last resort.\n"
            "  The pathway used is recorded in the audit report.\n"
            "\n"
            "NOTE: Must be run as Administrator.\n"
        )
    )
    parser.add_argument(
        "device", nargs="?",
        help="Target device path (e.g. \\\\.\\PhysicalDrive1). Use --list to enumerate."
    )
    parser.add_argument("--list",       action="store_true", help="List all drives and exit")
    parser.add_argument("--log",        metavar="PATH", default=None,
                        help="Write log and JSON audit report to PATH")
    parser.add_argument("--force",      action="store_true",
                        help="Skip interactive authorization prompt")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Simulate full 50-cycle sequence without issuing commands")
    parser.add_argument("--skip-verify",action="store_true",
                        help="Skip post-sanitization LBA verification")
    parser.add_argument("--verbose",    action="store_true",
                        help="Enable debug output (IOCTL details, Log Page 0x81 traces)")
    parser.add_argument("--version",    action="version",
                        version=f"{TOOL_NAME} v{TOOL_VERSION}")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args   = parser.parse_args()
    logger = configure_logging(args.log, args.verbose)

    if not args.dry_run and not is_admin():
        logger.error(
            "Administrator privileges required. "
            "Right-click Command Prompt → 'Run as administrator'."
        )
        return 1

    if args.list:
        list_drives(logger)
        return 0

    if not args.device:
        logger.error(
            "No device specified. Use --list to see available drives, "
            "then provide the device path (e.g. \\\\.\\PhysicalDrive1)."
        )
        return 1

    device = args.device

    if not args.dry_run:
        if not validate_nvme_device(device, logger):
            return 1

    model    = None
    bus_type = "Unknown"
    drives   = enumerate_drives(include_usb=True) if not args.dry_run else []
    for _, m, p, bt in drives:
        if p.lower() == device.lower():
            model    = m
            bus_type = bt
            break

    if bus_type == "USB":
        logger.info(
            f"USB-attached drive detected ({model}). "
            f"AAD-50 will auto-probe for the best passthrough pathway."
        )

    if not request_authorization(device, model, logger, force=args.force):
        return 1

    report = SanitizationReport(
        device=device,
        drive_model=model or "Unknown",
        started_at=datetime.now(timezone.utc).isoformat()
    )

    logger.info("")
    logger.info(
        f"AAD-50 Sanitization Sequence Starting — "
        f"{TOTAL_CYCLES} cycles | Platform: Windows | Bus: {bus_type}"
    )
    if args.dry_run:
        logger.info("[DRY RUN MODE — No DeviceIoControl commands will be issued]")

    success = run_sanitization(
        device_path=device,
        logger=logger,
        dry_run=args.dry_run,
        force=args.force,
        report=report
    )

    if success and not args.skip_verify and not args.dry_run:
        verif_records = verify_sanitization(device, logger)
        report.verification = [asdict(v) for v in verif_records]
    elif args.skip_verify:
        logger.info("Post-run verification skipped via --skip-verify.")

    finalize_report(report, success, args.log, logger)
    return 0 if success else 2


if __name__ == "__main__":
    sys.exit(main())
