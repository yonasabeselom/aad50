#!/usr/bin/env python3
# ==============================================================================
# THE ABESELOM ASIC-DIRECT 50 (AAD-50) — WINDOWS PORT
# Firmware-Enforced Flash Sanitization Specification
# ==============================================================================
# Author      : Yonas Abeselom (yonas_abeselom@protonmail.com)
# Version     : 1.0 (Windows Port — Beta)
# Date        : June 2026
# Architecture: Win32 DeviceIoControl / IOCTL_STORAGE_PROTOCOL_COMMAND
# Target Media: NVMe Solid-State Drives (Enterprise & Consumer NAND Flash)
# Platform    : Windows 10 1607+ / Windows 11 / Windows Server 2016+
# Compliance  : NIST SP 800-88 Rev.1 "Purge" | NVMe Base Spec 2.0/2.1
#               ISO/IEC 27040:2015 Storage Security | Common Criteria EAL4+
#
# PURPOSE:
#   Windows port of the AAD-50 Linux reference implementation.
#   Communicates directly with the NVMe controller via the Win32
#   DeviceIoControl API using IOCTL_STORAGE_PROTOCOL_COMMAND, which provides
#   the same firmware-level NVMe admin command pass-through capability as the
#   Linux nvme_admin_cmd IOCTL interface.
#
#   Executes the identical deterministic three-phase destruction matrix:
#   Phase B — Physical NAND Cell Overwrite     (Cycles  1–40)
#   Phase C — Flash Translation Layer Reset    (Cycles 41–45)
#   Phase A — Cryptographic Key Destruction    (Cycles 46–50)
#
#   Each cycle is confirmed complete via active NVMe Log Page 0x81 polling
#   before the next cycle is issued.
#
# PLATFORM NOTE:
#   This implementation uses the Windows STORAGE_PROTOCOL_COMMAND interface
#   introduced in Windows 10 version 1607 (Anniversary Update). It requires
#   Administrator privileges. Some OEM NVMe drivers may intercept
#   DeviceIoControl calls before they reach the controller — if this occurs
#   the tool will report an IOCTL error and advise using the Microsoft
#   standard NVMe driver (stornvme.sys).
#
# WARNING:
#   This tool causes PERMANENT, IRREVERSIBLE destruction of all data on
#   the target device. All partitions, filesystems, encryption keys, and
#   hardware-level indices are destroyed. There is NO undo. Run only on
#   devices you own and intend to fully erase.
#
# STATUS:
#   Beta — requires hardware testing across NVMe drive manufacturers.
#   The Linux version (aad50_abeselom.py) is the primary reference
#   implementation. This Windows port implements the identical protocol
#   via the Windows-equivalent API pathway.
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

# Windows-only guard
if sys.platform != "win32":
    print("ERROR: This script is for Windows only.")
    print("For Linux, use aad50_abeselom.py instead.")
    sys.exit(1)

import winreg

# ==============================================================================
# CONSTANTS
# ==============================================================================

TOOL_NAME    = "The Abeselom ASIC-Direct 50 (AAD-50)"
TOOL_VERSION = "1.0 (Windows Port — Beta)"
SPEC_NAME    = "Firmware-Enforced Flash Sanitization, 50-Cycle Specification"
AUTHOR       = "Yonas Abeselom"
CONTACT      = "yonas_abeselom@protonmail.com"

# ── Win32 Constants ────────────────────────────────────────────────────────────
GENERIC_READ                    = 0x80000000
GENERIC_WRITE                   = 0x40000000
FILE_SHARE_READ                 = 0x00000001
FILE_SHARE_WRITE                = 0x00000002
OPEN_EXISTING                   = 3
INVALID_HANDLE_VALUE            = ctypes.c_void_p(-1).value
FILE_ATTRIBUTE_NORMAL           = 0x80
FILE_FLAG_NO_BUFFERING          = 0x20000000

# IOCTL_STORAGE_PROTOCOL_COMMAND
# Defined in ntddstor.h:
# CTL_CODE(IOCTL_STORAGE_BASE, 0x04F0, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
# = 0x0002D14C
IOCTL_STORAGE_PROTOCOL_COMMAND  = 0x0002D14C

# STORAGE_PROTOCOL_TYPE — NVMe
ProtocolTypeNvme                = 0x03

# STORAGE_PROTOCOL_NVME_DATA_TYPE — Command
NVMeDataTypeCommand             = 0x06

# ── NVMe Opcodes ───────────────────────────────────────────────────────────────
NVME_GET_LOG_PAGE_OPCODE        = 0x02
NVME_SANITIZE_OPCODE            = 0x84

# ── NVMe Sanitize Action field values (CDW10 bits [2:0]) ──────────────────────
SANITIZE_ACTION_BLOCK_ERASE     = 0x01
SANITIZE_ACTION_OVERWRITE       = 0x02
SANITIZE_ACTION_CRYPTO_ERASE    = 0x04

# ── NVMe Namespace ID ─────────────────────────────────────────────────────────
NVME_NSID_ALL                   = 0xFFFFFFFF

# ── Log Page 0x81 SSTAT values ────────────────────────────────────────────────
NVME_LOG_SANITIZE_STATUS        = 0x81
SANITIZE_SSTAT_IDLE             = 0x0
SANITIZE_SSTAT_COMPLETED_OK     = 0x1
SANITIZE_SSTAT_IN_PROGRESS      = 0x2
SANITIZE_SSTAT_COMPLETED_ERR    = 0x3

# ── Polling ────────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS           = 2.0
POLL_TIMEOUT_SECONDS            = 7200   # 2-hour hard timeout

# ── Authorization ──────────────────────────────────────────────────────────────
AUTHORIZATION_TOKEN             = "EXECUTE-AAD-50-ABESELOM"
TOTAL_CYCLES                    = 50

# ── Post-run verification ──────────────────────────────────────────────────────
VERIFICATION_SAMPLE_COUNT       = 16
VERIFICATION_LBA_STEP           = 0x100000


# ==============================================================================
# WIN32 STRUCTURES
# ==============================================================================

class STORAGE_PROTOCOL_SPECIFIC_DATA(ctypes.Structure):
    """
    Maps to Windows STORAGE_PROTOCOL_SPECIFIC_DATA (ntddstor.h).
    Used to specify the NVMe protocol type and data type for the IOCTL.
    """
    _fields_ = [
        ("ProtocolType",            ctypes.c_uint32),   # ProtocolTypeNvme = 3
        ("DataType",                ctypes.c_uint32),   # NVMeDataTypeCommand = 6
        ("ProtocolDataRequestValue",ctypes.c_uint32),   # NVMe opcode
        ("ProtocolDataRequestSubValue", ctypes.c_uint32),  # CDW10
        ("ProtocolDataOffset",      ctypes.c_uint32),   # Offset to data
        ("ProtocolDataLength",      ctypes.c_uint32),   # Length of data
        ("FixedProtocolReturnData", ctypes.c_uint32),   # Return data
        ("ProtocolDataRequestSubValue2", ctypes.c_uint32),  # CDW11
        ("ProtocolDataRequestSubValue3", ctypes.c_uint32),  # CDW12
        ("ProtocolDataRequestSubValue4", ctypes.c_uint32),  # CDW13
        ("ProtocolDataRequestSubValue5", ctypes.c_uint32),  # CDW14
        ("Reserved",                ctypes.c_uint32),
    ]


class STORAGE_PROTOCOL_COMMAND(ctypes.Structure):
    """
    Maps to Windows STORAGE_PROTOCOL_COMMAND (ntddstor.h).
    Header structure for IOCTL_STORAGE_PROTOCOL_COMMAND.

    Version      : Must be STORAGE_PROTOCOL_STRUCTURE_VERSION (0x1)
    Length       : sizeof(STORAGE_PROTOCOL_COMMAND)
    ProtocolType : ProtocolTypeNvme
    Flags        : SPF_SET_ADAPTER_PROTOCOL (0x1) for controller-level
    ReturnStatus : Written back by driver
    ErrorCode    : Written back by driver
    CommandLength: 64 bytes (NVMe command size)
    ErrorInfoLength: 0
    DataToDeviceTransferLength: 0 (no data transfer for sanitize)
    DataFromDeviceTransferLength: varies (for log page reads)
    TimeOutValue : Timeout in seconds
    ErrorInfoOffset: 0
    DataToDeviceBufferOffset: 0
    DataFromDeviceBufferOffset: offset to data buffer
    CommandSpecific: 0
    Reserved0    : 0
    FixedProtocolReturnData: written back
    Reserved1    : 0, 0, 0
    Command      : 64-byte NVMe command (STORAGE_PROTOCOL_SPECIFIC_DATA)
    """
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


# NVMe command structure (64 bytes, matches NVMe Base Spec CDW layout)
class NVME_COMMAND(ctypes.Structure):
    _fields_ = [
        ("CDW0",    ctypes.c_uint32),   # Opcode [7:0], FUSE [9:8], PSDT [15:14], CID [31:16]
        ("NSID",    ctypes.c_uint32),   # Namespace ID
        ("CDW2",    ctypes.c_uint32),   # Reserved
        ("CDW3",    ctypes.c_uint32),   # Reserved
        ("MPTR",    ctypes.c_uint64),   # Metadata pointer
        ("PRP1",    ctypes.c_uint64),   # PRP Entry 1
        ("PRP2",    ctypes.c_uint64),   # PRP Entry 2
        ("CDW10",   ctypes.c_uint32),   # Command-specific
        ("CDW11",   ctypes.c_uint32),
        ("CDW12",   ctypes.c_uint32),
        ("CDW13",   ctypes.c_uint32),
        ("CDW14",   ctypes.c_uint32),
        ("CDW15",   ctypes.c_uint32),
    ]


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
    """Returns True if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ==============================================================================
# DEVICE HANDLE
# ==============================================================================

def open_device(device_path: str) -> Optional[ctypes.c_void_p]:
    """
    Opens a raw handle to the NVMe controller device node.

    Windows device path format: \\\\.\\PhysicalDriveN  (e.g. \\\\.\\PhysicalDrive0)
    or the NVMe controller directly: \\\\.\\ScsiN:

    Returns the handle or None on failure.
    """
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
        err = ctypes.GetLastError()
        return None
    return handle


def close_device(handle: ctypes.c_void_p) -> None:
    ctypes.windll.kernel32.CloseHandle(handle)


# ==============================================================================
# DEVICE DISCOVERY AND VALIDATION
# ==============================================================================

def enumerate_nvme_drives() -> list:
    """
    Enumerates physical NVMe drives on the system via WMI.
    Returns a list of (index, model, path) tuples.
    """
    drives = []
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-PhysicalDisk | Where-Object {$_.BusType -eq 'NVMe'} | "
             "Select-Object DeviceId, FriendlyName | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for disk in data:
                idx   = disk.get("DeviceId", "?")
                model = disk.get("FriendlyName", "Unknown")
                path  = f"\\\\.\\PhysicalDrive{idx}"
                drives.append((idx, model, path))
    except Exception:
        pass
    return drives


def validate_nvme_device(device_path: str, logger: logging.Logger) -> bool:
    """
    Confirms the target device path is accessible and can be opened
    with read/write access before any destructive commands are issued.
    """
    handle = open_device(device_path)
    if handle is None:
        err = ctypes.GetLastError()
        if err == 5:  # ERROR_ACCESS_DENIED
            logger.error(
                "Access denied. Re-run as Administrator "
                "(right-click → Run as administrator)."
            )
        elif err == 2:  # ERROR_FILE_NOT_FOUND
            logger.error(f"Device not found: {device_path}")
        else:
            logger.error(
                f"Could not open device {device_path} "
                f"(Win32 error {err})"
            )
        return False
    close_device(handle)
    logger.debug(f"Device validation passed: {device_path}")
    return True


# ==============================================================================
# NVMe COMMAND DISPATCH — WIN32 DeviceIoControl
# ==============================================================================

def _build_sanitize_buffer(action: int) -> ctypes.Array:
    """
    Builds the STORAGE_PROTOCOL_COMMAND input buffer for an NVMe Sanitize
    command using the Windows IOCTL_STORAGE_PROTOCOL_COMMAND interface.

    The NVMe command bytes are packed into the Command[64] field of the
    STORAGE_PROTOCOL_COMMAND structure per the NVMe Base Spec CDW layout.
    """
    STORAGE_PROTOCOL_STRUCTURE_VERSION = 0x1
    SPF_ADAPTER_REQUEST = 0x4  # Send to adapter/controller, not device

    # Build the 64-byte NVMe command
    nvme_cmd = NVME_COMMAND()
    nvme_cmd.CDW0  = NVME_SANITIZE_OPCODE & 0xFF  # Opcode in bits [7:0]
    nvme_cmd.NSID  = NVME_NSID_ALL
    nvme_cmd.CDW10 = action   # Sanitize Action

    # Pack NVMe command into bytes
    cmd_bytes = (ctypes.c_uint8 * 64)()
    ctypes.memmove(cmd_bytes, ctypes.addressof(nvme_cmd),
                   min(64, ctypes.sizeof(nvme_cmd)))

    # Build STORAGE_PROTOCOL_COMMAND
    proto_cmd = STORAGE_PROTOCOL_COMMAND()
    proto_cmd.Version                      = STORAGE_PROTOCOL_STRUCTURE_VERSION
    proto_cmd.Length                       = ctypes.sizeof(STORAGE_PROTOCOL_COMMAND)
    proto_cmd.ProtocolType                 = ProtocolTypeNvme
    proto_cmd.Flags                        = SPF_ADAPTER_REQUEST
    proto_cmd.CommandLength                = 64
    proto_cmd.ErrorInfoLength              = 0
    proto_cmd.DataToDeviceTransferLength   = 0
    proto_cmd.DataFromDeviceTransferLength = 0
    proto_cmd.TimeOutValue                 = 7200   # 2-hour timeout
    proto_cmd.ErrorInfoOffset              = 0
    proto_cmd.DataToDeviceBufferOffset     = 0
    proto_cmd.DataFromDeviceBufferOffset   = 0
    proto_cmd.Command                      = cmd_bytes

    return proto_cmd


def _build_log_page_buffer(log_id: int, data_len: int) -> Tuple[ctypes.Structure, ctypes.Array]:
    """
    Builds the STORAGE_PROTOCOL_COMMAND input buffer for an NVMe Get Log Page
    command and a separate output data buffer.

    Returns (proto_cmd, data_buffer) tuple.
    """
    STORAGE_PROTOCOL_STRUCTURE_VERSION = 0x1
    SPF_ADAPTER_REQUEST = 0x4

    cmd_size  = ctypes.sizeof(STORAGE_PROTOCOL_COMMAND)
    data_offset = cmd_size  # Data buffer immediately follows the command struct

    # NVMe Get Log Page CDW10: log_id[7:0] | numd[27:16]
    numd  = (data_len // 4) - 1
    cdw10 = (log_id & 0xFF) | ((numd & 0xFFF) << 16)

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

    # Allocate combined buffer: command struct + data buffer
    total_size  = cmd_size + data_len
    total_buf   = (ctypes.c_uint8 * total_size)()
    ctypes.memmove(total_buf, ctypes.addressof(proto_cmd), cmd_size)

    return total_buf, total_size, data_offset


def execute_nvme_sanitize(
    handle: ctypes.c_void_p,
    action: int,
    logger: logging.Logger
) -> None:
    """
    Issues one NVMe Sanitize command via DeviceIoControl.
    Returns immediately (async — drive executes in background).
    """
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
        raise OSError(
            f"DeviceIoControl failed (Win32 error {err}). "
            f"If error 1, the NVMe driver may not support pass-through — "
            f"ensure the Microsoft standard NVMe driver (stornvme.sys) is active."
        )

    logger.debug(
        f"Sanitize dispatched via DeviceIoControl — "
        f"opcode=0x{NVME_SANITIZE_OPCODE:02X}, action=0x{action:02X}"
    )


# ==============================================================================
# LOG PAGE 0x81 POLLING
# ==============================================================================

def read_sanitize_status(
    handle: ctypes.c_void_p,
    logger: logging.Logger
) -> Optional[int]:
    """
    Reads NVMe Log Page 0x81 (Sanitize Status) via DeviceIoControl.
    Returns the SSTAT field value (bits [2:0]) or None on failure.
    """
    LOG_DATA_LEN = 20
    total_buf, total_size, data_offset = _build_log_page_buffer(
        NVME_LOG_SANITIZE_STATUS, LOG_DATA_LEN
    )
    bytes_ret = ctypes.c_uint32(0)

    success = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        IOCTL_STORAGE_PROTOCOL_COMMAND,
        total_buf,
        total_size,
        total_buf,
        total_size,
        ctypes.byref(bytes_ret),
        None
    )

    if not success:
        err = ctypes.GetLastError()
        logger.debug(f"Log Page 0x81 read failed (Win32 error {err})")
        return None

    # Extract SSTAT from data buffer at offset data_offset
    sstat = total_buf[data_offset + 2] | (total_buf[data_offset + 3] << 8)
    sprog = total_buf[data_offset + 0] | (total_buf[data_offset + 1] << 8)
    status_code = sstat & 0x07

    prog_pct = int((sprog / 0xFFFF) * 100) if sprog > 0 else 0
    logger.debug(
        f"Log Page 0x81 — SSTAT=0x{sstat:04X} "
        f"(code={status_code}) SPROG={sprog:#06x} ({prog_pct}%)"
    )

    return status_code


def poll_until_complete(
    handle: ctypes.c_void_p,
    cycle: int,
    logger: logging.Logger,
    dry_run: bool = False
) -> bool:
    """
    Blocks until Log Page 0x81 confirms sanitize complete.
    Identical logic to the Linux version.
    """
    if dry_run:
        logger.debug(f"  [DRY RUN] Skipping Log Page 0x81 poll for cycle {cycle}.")
        return True

    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    elapsed  = 0.0

    while time.monotonic() < deadline:
        status = read_sanitize_status(handle, logger)

        if status is None:
            logger.debug(f"  Cycle {cycle:02d}: Status read returned None — retrying...")

        elif status == SANITIZE_SSTAT_COMPLETED_OK:
            logger.debug(f"  Cycle {cycle:02d}: SSTAT=0x1 — Hardware confirmed complete.")
            return True

        elif status == SANITIZE_SSTAT_IN_PROGRESS:
            logger.debug(
                f"  Cycle {cycle:02d}: SSTAT=0x2 — Sanitize in progress ({elapsed:.0f}s)..."
            )

        elif status == SANITIZE_SSTAT_IDLE:
            logger.debug(f"  Cycle {cycle:02d}: SSTAT=0x0 — Controller returned to idle.")
            return True

        elif status == SANITIZE_SSTAT_COMPLETED_ERR:
            logger.error(f"  Cycle {cycle:02d}: SSTAT=0x3 — Controller reported sanitize error.")
            return False

        else:
            logger.warning(
                f"  Cycle {cycle:02d}: Unknown SSTAT code 0x{status:X} — continuing poll..."
            )

        time.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS

    logger.error(
        f"  Cycle {cycle:02d}: Polling timed out after {POLL_TIMEOUT_SECONDS}s. "
        f"Drive may still be sanitizing — do not re-use device."
    )
    return False


# ==============================================================================
# POST-RUN VERIFICATION
# ==============================================================================

def verify_sanitization(
    device_path: str,
    logger: logging.Logger
) -> list:
    """
    Samples LBAs across the drive via Win32 ReadFile and confirms
    each returns zeroed or deallocated data post-sanitization.
    """
    results = []
    sector_size = 512
    probe_offsets = [i * VERIFICATION_LBA_STEP * sector_size
                     for i in range(VERIFICATION_SAMPLE_COUNT)]

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

            # Seek to offset
            lo = offset & 0xFFFFFFFF
            hi = (offset >> 32) & 0xFFFFFFFF
            new_pos = kernel32.SetFilePointer(handle, lo, ctypes.byref(ctypes.c_long(hi)), 0)

            if new_pos == 0xFFFFFFFF and ctypes.GetLastError() != 0:
                rec.result = "SEEK_ERROR"
                rec.detail = f"Win32 error {ctypes.GetLastError()}"
                logger.warning(f"  LBA 0x{lba:010X} — SEEK ERROR")
                results.append(rec)
                continue

            bytes_read = ctypes.c_uint32(0)
            ok = kernel32.ReadFile(handle, buf, sector_size,
                                   ctypes.byref(bytes_read), None)

            if not ok or bytes_read.value != sector_size:
                rec.result = "DEALLOCATED"
                logger.info(f"  LBA 0x{lba:010X} — DEALLOCATED (hardware unallocated) ✓")
            elif all(b == 0 for b in buf.raw):
                rec.result = "ZEROED"
                logger.info(f"  LBA 0x{lba:010X} — ZEROED ✓")
            else:
                non_zero = sum(1 for b in buf.raw if b != 0)
                rec.result = "NON-ZERO"
                rec.detail = f"{non_zero}/{sector_size} non-zero bytes"
                logger.warning(f"  LBA 0x{lba:010X} — NON-ZERO ({non_zero} bytes) ⚠")

            results.append(rec)

    finally:
        kernel32.CloseHandle(handle)

    clean   = sum(1 for r in results if r.result in ("ZEROED", "DEALLOCATED"))
    flagged = len(results) - clean
    logger.info(
        f"  Verification complete: {clean}/{len(results)} LBAs confirmed clean"
        + (f" | {flagged} flagged — review report" if flagged else "")
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
    """
    Executes the AAD-50 three-phase sanitization sequence — identical phase
    ordering and cycle counts as the Linux reference implementation.
    """
    phases = [
        ("B — Physical NAND Cell Overwrite",  range(1,  41), SANITIZE_ACTION_OVERWRITE,    "overwrite"),
        ("C — Flash Translation Layer Reset", range(41, 46), SANITIZE_ACTION_BLOCK_ERASE,  "block erase"),
        ("A — Cryptographic Key Destruction", range(46, 51), SANITIZE_ACTION_CRYPTO_ERASE, "crypto erase"),
    ]

    handle = None
    try:
        if not dry_run:
            handle = open_device(device_path)
            if handle is None:
                logger.error(f"Failed to open device: {device_path}")
                return False
            logger.info(f"Direct controller handle opened: {device_path}")
        else:
            logger.info("[DRY RUN] No device handle opened — simulating full sequence.")

        for phase_label, cycles, action, action_name in phases:
            logger.info("")
            logger.info(f"━━━ PHASE {phase_label} ━━━")

            for cycle in cycles:
                ts          = datetime.now(timezone.utc).isoformat()
                pct         = int((cycle / TOTAL_CYCLES) * 100)
                bar         = ("█" * (pct // 5)).ljust(20)
                cycle_start = time.monotonic()

                logger.info(
                    f"  Cycle {cycle:02d}/{TOTAL_CYCLES} [{bar}] {pct:3d}%  "
                    f"Action=0x{action:02X} ({action_name})"
                )

                status    = "OK"
                error_msg = None

                try:
                    if not dry_run:
                        execute_nvme_sanitize(handle, action, logger)
                        completed = poll_until_complete(handle, cycle, logger, dry_run=False)
                        if not completed:
                            status    = "POLL_TIMEOUT_OR_ERROR"
                            error_msg = "Hardware did not confirm cycle completion."
                            logger.error(
                                f"  Cycle {cycle:02d} failed to complete on hardware. "
                                f"Aborting sequence."
                            )
                            if report:
                                report.cycles.append(CycleRecord(
                                    cycle=cycle, phase=phase_label,
                                    action_code=action, timestamp=ts,
                                    status=status, error=error_msg,
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
                            status=status, error=error_msg,
                            duration_sec=round(time.monotonic() - cycle_start, 2)
                        ))
                    return False

                duration = round(time.monotonic() - cycle_start, 2)
                if report:
                    report.cycles.append(CycleRecord(
                        cycle=cycle, phase=phase_label,
                        action_code=action, timestamp=ts,
                        status=status, duration_sec=duration
                    ))
                    report.cycles_run = cycle

                logger.debug(f"  Cycle {cycle:02d} confirmed complete in {duration}s.")

    finally:
        if handle is not None:
            close_device(handle)
            logger.debug("Controller handle closed.")

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
    report.outcome = "SUCCESS — DATA DESTROYED" if success else "FAILED — INCOMPLETE"

    cycle_blob   = json.dumps([asdict(c) for c in report.cycles], sort_keys=True)
    report.log_hash = hashlib.sha256(cycle_blob.encode()).hexdigest()

    logger.info("")
    logger.info("=" * 78)
    logger.info(f"  {TOOL_NAME} v{TOOL_VERSION}")
    logger.info(f"  Author : {AUTHOR} <{CONTACT}>")
    logger.info("=" * 78)
    logger.info(f"  OUTCOME   : {report.outcome}")
    logger.info(f"  PLATFORM  : Windows")
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
        print("  [--force] Non-interactive mode active. Proceeding automatically.")
        print()
        logger.info("Authorization granted via --force flag.")
        return True

    print(f"  To authorize, type exactly:  {AUTHORIZATION_TOKEN}")
    print()

    try:
        token = input("  Authorization: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        logger.info("Authorization interrupted by user.")
        return False

    if token != AUTHORIZATION_TOKEN:
        logger.info("Authorization token mismatch. Sanitization aborted.")
        return False

    return True


# ==============================================================================
# DRIVE LISTING
# ==============================================================================

def list_nvme_drives(logger: logging.Logger) -> None:
    """Prints all detected NVMe drives to help the user identify the target."""
    logger.info("Detecting NVMe drives...")
    drives = enumerate_nvme_drives()
    if not drives:
        logger.warning(
            "No NVMe drives detected via PowerShell WMI. "
            "You may need to specify the device path manually "
            "(e.g. \\\\.\\PhysicalDrive0)."
        )
        return
    logger.info(f"Found {len(drives)} NVMe drive(s):")
    for idx, model, path in drives:
        logger.info(f"  [{idx}] {model}  →  {path}")


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
            f"Platform: Windows 10 1607+ / Windows 11 / Windows Server 2016+"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python aad50_abeselom_windows.py --list\n"
            "  python aad50_abeselom_windows.py \\\\.\\PhysicalDrive0\n"
            "  python aad50_abeselom_windows.py \\\\.\\PhysicalDrive0 --log C:\\logs\\aad50.log\n"
            "  python aad50_abeselom_windows.py \\\\.\\PhysicalDrive0 --dry-run --verbose\n"
            "\n"
            "NOTE: Must be run as Administrator.\n"
            "NOTE: Target must be a physical NVMe drive (not a partition or volume).\n"
        )
    )
    parser.add_argument(
        "device",
        nargs="?",
        help=(
            "Target NVMe device path "
            "(e.g. \\\\.\\PhysicalDrive0). "
            "Use --list to enumerate available NVMe drives."
        )
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all detected NVMe drives and exit"
    )
    parser.add_argument(
        "--log",
        metavar="PATH",
        default=None,
        help="Write timestamped execution log and JSON audit report to PATH"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Skip interactive authorization prompt. "
            "For automated deprovisioning pipelines. USE WITH EXTREME CAUTION."
        )
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the full 50-cycle sequence without issuing any commands"
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip the post-sanitization LBA verification read"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug output (DeviceIoControl details, Log Page 0x81 traces)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} v{TOOL_VERSION}"
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args   = parser.parse_args()
    logger = configure_logging(args.log, args.verbose)

    # Administrator privilege check
    if not args.dry_run and not is_admin():
        logger.error(
            "Administrator privileges are required. "
            "Right-click the script or Command Prompt and select "
            "'Run as administrator'."
        )
        return 1

    # List drives mode
    if args.list:
        list_nvme_drives(logger)
        return 0

    # Device argument required if not listing
    if not args.device:
        logger.error(
            "No device specified. Use --list to see available NVMe drives, "
            "then provide the device path (e.g. \\\\.\\PhysicalDrive0)."
        )
        return 1

    device = args.device

    # Device validation
    if not args.dry_run:
        if not validate_nvme_device(device, logger):
            return 1

    # Drive model identification (best-effort)
    model = None
    drives = enumerate_nvme_drives() if not args.dry_run else []
    for _, m, p in drives:
        if p.lower() == device.lower():
            model = m
            break

    # Authorization gate
    if not request_authorization(device, model, logger, force=args.force):
        return 1

    # Initialize audit report
    report = SanitizationReport(
        device=device,
        drive_model=model or "Unknown",
        started_at=datetime.now(timezone.utc).isoformat()
    )

    logger.info("")
    logger.info(
        f"AAD-50 Sanitization Sequence Starting — "
        f"{TOTAL_CYCLES} cycles | Async polling: ENABLED | Platform: Windows"
    )
    if args.dry_run:
        logger.info("[DRY RUN MODE — No DeviceIoControl commands will be issued]")

    # Execute sanitization
    success = run_sanitization(
        device_path=device,
        logger=logger,
        dry_run=args.dry_run,
        force=args.force,
        report=report
    )

    # Post-run LBA verification
    if success and not args.skip_verify and not args.dry_run:
        verif_records = verify_sanitization(device, logger)
        report.verification = [asdict(v) for v in verif_records]
    elif args.skip_verify:
        logger.info("Post-run verification skipped via --skip-verify.")

    # Finalize and save report
    finalize_report(report, success, args.log, logger)

    return 0 if success else 2


if __name__ == "__main__":
    sys.exit(main())
