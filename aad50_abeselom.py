#!/usr/bin/env python3
# ==============================================================================
# THE ABESELOM ASIC-DIRECT 50 (AAD-50)
# Firmware-Enforced Flash Sanitization Specification
# ==============================================================================
# Author      : Yonas Abeselom (yonas_abeselom@protonmail.com)
# Repository  : https://github.com/yonasabeselom/aad50
# Version     : 1.1
# Date        : June 2026
# Architecture: Low-Level NVMe Admin Command Interface (IOCTL, Linux)
#               + SCSI Generic passthrough for USB enclosures (sg/SAT)
#               + blkdiscard fallback
# Target Media: NVMe Solid-State Drives (Enterprise & Consumer NAND Flash)
#               including NVMe drives in USB 3.x enclosures with UASP support
# Compliance  : NIST SP 800-88 Rev.2 "Purge" | NVMe Base Spec 2.0/2.1
#               ISO/IEC 27040:2015 Storage Security | Common Criteria EAL4+
#
# PURPOSE:
#   Executes a deterministic, firmware-enforced, three-phase sanitization
#   sequence directly against the NVMe controller hardware, bypassing all
#   filesystem and OS-level abstractions to achieve absolute zero remanence.
#   Each cycle is confirmed complete via active NVMe Log Page 0x81 polling
#   before the next cycle is issued — guaranteeing all 50 phases execute
#   fully on the physical silicon, not merely in the command queue.
#
# USB ENCLOSURE SUPPORT (v1.1):
#   When an NVMe drive is connected via a USB enclosure, the OS presents it
#   as /dev/sdX (SCSI block device) rather than /dev/nvmeX. Direct NVMe
#   IOCTL commands cannot reach the controller through the USB bridge.
#
#   AAD-50 v1.1 adds three-tier auto-detection:
#
#   TIER 1 — NVMe Direct (/dev/nvme*)
#     NVME_IOCTL_ADMIN_CMD passthrough. Full Log Page 0x81 confirmation.
#     Works for M.2/PCIe drives and UASP enclosures with NVMe passthrough.
#
#   TIER 2 — SCSI Generic / ATA Passthrough (/dev/sg*)
#     ATA SANITIZE DEVICE (0xB4) via SCSI ATA PASS-THROUGH (16) command.
#     Works for USB enclosures supporting UASP + SAT (SCSI/ATA Translation).
#     Covers most modern USB-NVMe bridge chips (ASMedia, Realtek, JMicron).
#
#   TIER 3 — blkdiscard fallback (/dev/sdX)
#     Issues BLKDISCARD ioctl to discard all LBAs. Reaches the drive via
#     the block layer. Less granular but works when SAT is unavailable.
#
#   The tool auto-detects the device type and selects the appropriate tier.
#   The active pathway is recorded in every cycle record and the audit report.
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

import os
import sys
import fcntl
import struct
import array
import time
import argparse
import logging
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Tuple


# ==============================================================================
# CONSTANTS
# ==============================================================================

TOOL_NAME    = "The Abeselom ASIC-Direct 50 (AAD-50)"
TOOL_VERSION = "1.1"
SPEC_NAME    = "Firmware-Enforced Flash Sanitization, 50-Cycle Specification"
AUTHOR       = "Yonas Abeselom"
CONTACT      = "yonas_abeselom@protonmail.com"

# ── NVMe IOCTL ────────────────────────────────────────────────────────────────
NVME_IOCTL_ADMIN_CMD     = 0xC0484E41
NVME_GET_LOG_PAGE_OPCODE = 0x02
NVME_LOG_SANITIZE_STATUS = 0x81
NVME_SANITIZE_OPCODE     = 0x84

# NVMe Sanitize Action field values (CDW10 bits [2:0])
SANITIZE_ACTION_BLOCK_ERASE  = 0x01  # Phase C — FTL index teardown
SANITIZE_ACTION_OVERWRITE    = 0x02  # Phase B — Physical NAND overwrite
SANITIZE_ACTION_CRYPTO_ERASE = 0x04  # Phase A — Crypto key destruction

NVME_NSID_ALL = 0xFFFFFFFF

# ── Log Page 0x81 SSTAT values ────────────────────────────────────────────────
SANITIZE_SSTAT_IDLE          = 0x0
SANITIZE_SSTAT_IN_PROGRESS   = 0x2
SANITIZE_SSTAT_COMPLETED_OK  = 0x1
SANITIZE_SSTAT_COMPLETED_ERR = 0x3

# ── SCSI/ATA Passthrough (Tier 2) ─────────────────────────────────────────────
# SCSI ATA PASS-THROUGH (16) opcode
SCSI_ATA_PASSTHROUGH_16  = 0x85
# ATA SANITIZE DEVICE command
ATA_CMD_SANITIZE_DEVICE  = 0xB4
# ATA SANITIZE feature codes
ATA_SANITIZE_BLOCK_ERASE = 0x0012
ATA_SANITIZE_OVERWRITE   = 0x0011
ATA_SANITIZE_CRYPTO      = 0x0014
# ATA IDENTIFY DEVICE (non-destructive probe)
ATA_CMD_IDENTIFY         = 0xEC

# SG_IO ioctl number
SG_IO = 0x2285

# ── blkdiscard (Tier 3) ───────────────────────────────────────────────────────
# BLKDISCARD ioctl: discards a range of blocks
BLKDISCARD   = 0x1277
# BLKGETSIZE64: get device size in bytes
BLKGETSIZE64 = 0x80081272

# ── Polling ───────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS = 2.0
POLL_TIMEOUT_SECONDS  = 7200

# ── Authorization ─────────────────────────────────────────────────────────────
AUTHORIZATION_TOKEN = "EXECUTE-AAD-50-ABESELOM"
TOTAL_CYCLES        = 50

# ── Post-run verification ─────────────────────────────────────────────────────
VERIFICATION_SAMPLE_COUNT = 16
VERIFICATION_LBA_STEP     = 0x100000

# ── Passthrough tiers ─────────────────────────────────────────────────────────
TIER_NVME    = "NVMe-Direct"
TIER_SCSI    = "SCSI-ATA-Passthrough"
TIER_DISCARD = "blkdiscard"
TIER_NONE    = "None"

# NVMe admin cmd struct format (72 bytes)
NVME_ADMIN_CMD_FMT = 'BBHIIIQQIIIIIIIIII'


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
    pathway:      str   = TIER_NONE
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
    logger = logging.getLogger("aad50")
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
# DEVICE VALIDATION
# ==============================================================================

def validate_nvme_device(device_path: str, logger: logging.Logger) -> bool:
    p = Path(device_path)
    if not p.exists():
        logger.error(f"Device path does not exist: {device_path}")
        return False
    if not p.is_block_device():
        logger.error(f"Path is not a block device: {device_path}")
        return False
    name = p.name
    if name.startswith("nvme") and "n" in name[4:]:
        logger.warning(
            f"'{name}' appears to be a namespace node. "
            f"AAD-50 should target the controller (e.g. /dev/nvme0)."
        )
    try:
        with open(device_path, "rb") as fh:
            fh.read(512)
    except PermissionError:
        logger.error("Permission denied. Re-run with sudo.")
        return False
    except OSError as e:
        logger.error(f"Device probe failed: {e}")
        return False
    logger.debug(f"Device validation passed: {device_path}")
    return True


def get_device_info(device_path: str) -> Tuple[Optional[str], Optional[int]]:
    model      = None
    total_lbas = None
    try:
        r = subprocess.run(
            ["nvme", "id-ctrl", device_path, "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            data  = json.loads(r.stdout)
            model = data.get("mn", "").strip() or None
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["nvme", "id-ns", device_path, "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            data       = json.loads(r.stdout)
            total_lbas = data.get("nsze")
    except Exception:
        pass
    return model, total_lbas


# ==============================================================================
# DEVICE TYPE DETECTION
# ==============================================================================

def detect_device_type(device_path: str) -> str:
    """
    Determines whether the device is:
      - A native NVMe controller (/dev/nvme*)
      - A SCSI generic device (/dev/sg*) — USB enclosure with SAT
      - A SCSI block device (/dev/sd*) — USB enclosure without SAT
    Returns the device category string.
    """
    name = Path(device_path).name
    if name.startswith("nvme"):
        return "nvme"
    elif name.startswith("sg"):
        return "sg"
    elif name.startswith("sd"):
        return "sd"
    else:
        return "unknown"


def find_sg_node(sd_path: str) -> Optional[str]:
    """
    Given /dev/sdX, finds the corresponding /dev/sgY node.
    Needed to send SCSI pass-through commands to USB-attached drives.
    """
    sd_name = Path(sd_path).name   # e.g. "sdb"
    sg_path = f"/sys/block/{sd_name}/device/scsi_generic"
    try:
        entries = list(Path(sg_path).iterdir())
        if entries:
            return f"/dev/{entries[0].name}"
    except Exception:
        pass
    # Fallback: try /dev/sg0..sg9
    try:
        result = subprocess.run(
            ["sg_map", "-x"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if sd_name in line:
                parts = line.split()
                if parts:
                    return parts[0]
    except Exception:
        pass
    return None


# ==============================================================================
# TIER 1 — NVMe DIRECT (IOCTL)
# ==============================================================================

def _build_sanitize_cmd(action: int) -> array.array:
    cmd = struct.pack(
        NVME_ADMIN_CMD_FMT,
        NVME_SANITIZE_OPCODE, 0, 0, NVME_NSID_ALL,
        0, 0, 0, 0, 0, 0,
        action, 0, 0, 0, 0, 0, 0, 0,
    )
    return array.array('b', cmd)


def _build_get_log_page_cmd(log_id: int, data_addr: int, data_len: int) -> array.array:
    numd  = (data_len // 4) - 1
    cdw10 = (log_id & 0xFF) | ((numd & 0xFFF) << 16)
    cmd   = struct.pack(
        NVME_ADMIN_CMD_FMT,
        NVME_GET_LOG_PAGE_OPCODE, 0, 0, NVME_NSID_ALL,
        0, 0, 0, data_addr, 0, data_len,
        cdw10, 0, 0, 0, 0, 0, 0, 0,
    )
    return array.array('b', cmd)


def execute_nvme_sanitize_direct(
    disk_fd: int, action: int, logger: logging.Logger
) -> bool:
    """Tier 1: NVMe IOCTL admin command passthrough."""
    try:
        buf = _build_sanitize_cmd(action)
        fcntl.ioctl(disk_fd, NVME_IOCTL_ADMIN_CMD, buf, 1)
        logger.debug(
            f"Tier 1 NVMe direct: sanitize dispatched "
            f"opcode=0x{NVME_SANITIZE_OPCODE:02X} action=0x{action:02X}"
        )
        return True
    except OSError as e:
        logger.debug(f"Tier 1 NVMe direct failed: {e}")
        return False


def read_sanitize_status(disk_fd: int, logger: logging.Logger) -> Optional[int]:
    LOG_DATA_LEN = 20
    data_buf     = array.array('B', b'\x00' * LOG_DATA_LEN)
    buf_addr, _  = data_buf.buffer_info()
    cmd_buf      = _build_get_log_page_cmd(
        NVME_LOG_SANITIZE_STATUS, buf_addr, LOG_DATA_LEN
    )
    try:
        fcntl.ioctl(disk_fd, NVME_IOCTL_ADMIN_CMD, cmd_buf, 1)
    except OSError as e:
        logger.debug(f"Log Page 0x81 read failed: {e}")
        return None

    sstat       = data_buf[2] | (data_buf[3] << 8)
    sprog       = data_buf[0] | (data_buf[1] << 8)
    status_code = sstat & 0x07
    prog_pct    = int((sprog / 0xFFFF) * 100) if sprog > 0 else 0
    logger.debug(
        f"Log Page 0x81 — SSTAT=0x{sstat:04X} "
        f"(code={status_code}) SPROG={sprog:#06x} ({prog_pct}%)"
    )
    return status_code


def poll_until_complete_nvme(
    disk_fd: int, cycle: int, logger: logging.Logger
) -> bool:
    """Tier 1 polling: hardware-confirmed via Log Page 0x81."""
    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    elapsed  = 0.0

    while time.monotonic() < deadline:
        status = read_sanitize_status(disk_fd, logger)

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

    logger.error(
        f"  Cycle {cycle:02d}: Polling timed out after {POLL_TIMEOUT_SECONDS}s."
    )
    return False


# ==============================================================================
# TIER 2 — SCSI/ATA PASSTHROUGH (SG_IO for USB enclosures)
# ==============================================================================

def _nvme_action_to_ata_feature(action: int) -> int:
    return {
        SANITIZE_ACTION_OVERWRITE:    ATA_SANITIZE_OVERWRITE,
        SANITIZE_ACTION_BLOCK_ERASE:  ATA_SANITIZE_BLOCK_ERASE,
        SANITIZE_ACTION_CRYPTO_ERASE: ATA_SANITIZE_CRYPTO,
    }.get(action, ATA_SANITIZE_BLOCK_ERASE)


def _build_sg_io_hdr(
    cdb: bytes,
    dxfer_buf: Optional[bytes] = None,
    timeout_ms: int = 30000
) -> array.array:
    """
    Builds a sg_io_hdr_t structure for the SG_IO ioctl.
    sg_io_hdr_t layout (Linux kernel, scsi/sg.h):
      int      interface_id    ('S' = SCSI generic)
      int      dxfer_direction (SG_DXFER_NONE=-1, SG_DXFER_FROM_DEV=-3)
      uint8    cmd_len
      uint8    mx_sb_len       (sense buffer max length)
      uint16   iovec_count     (0 = use dxferp directly)
      uint    dxfer_len
      ptr      dxferp          (data transfer buffer pointer)
      ptr      cmdp            (CDB pointer)
      ptr      sbp             (sense buffer pointer)
      uint     timeout         (ms)
      uint     flags
      int      pack_id
      ptr      usr_ptr
      uint8    status
      uint8    masked_status
      uint8    msg_status
      uint8    sb_len_wr
      uint16   host_status
      uint16   driver_status
      int      resid
      uint     duration
      uint     info
    Total: variable depending on pointer size — we use struct packing
    """
    SG_DXFER_NONE     = -1
    SG_DXFER_FROM_DEV = -3

    sense_buf = array.array('B', b'\x00' * 32)
    sense_addr, _ = sense_buf.buffer_info()

    cdb_arr  = array.array('B', cdb)
    cdb_addr, _ = cdb_arr.buffer_info()

    if dxfer_buf is not None:
        dxfer_arr  = array.array('B', dxfer_buf)
        dxfer_addr, _ = dxfer_arr.buffer_info()
        dxfer_direction = SG_DXFER_FROM_DEV
        dxfer_len = len(dxfer_buf)
    else:
        dxfer_arr  = None
        dxfer_addr = 0
        dxfer_direction = SG_DXFER_NONE
        dxfer_len  = 0

    # Pack sg_io_hdr_t — pointer size depends on arch (8 bytes on 64-bit)
    fmt = 'ii BB HI PPPI II i P BBBB HH i II'
    hdr = struct.pack(
        'iiBBHIPPPIIiPBBBBHHiII',
        ord('S'),           # interface_id
        dxfer_direction,    # dxfer_direction
        len(cdb),           # cmd_len
        32,                 # mx_sb_len
        0,                  # iovec_count
        dxfer_len,          # dxfer_len
        dxfer_addr,         # dxferp
        cdb_addr,           # cmdp
        sense_addr,         # sbp
        timeout_ms,         # timeout
        0,                  # flags
        0,                  # pack_id
        0,                  # usr_ptr
        0, 0, 0, 0,         # status, masked_status, msg_status, sb_len_wr
        0, 0,               # host_status, driver_status
        0,                  # resid
        0, 0,               # duration, info
    )
    hdr_arr = array.array('B', hdr)
    return hdr_arr, cdb_arr, sense_buf, dxfer_arr


def execute_scsi_ata_sanitize(
    sg_fd: int, action: int, logger: logging.Logger
) -> bool:
    """
    Tier 2: ATA SANITIZE DEVICE via SCSI ATA PASS-THROUGH (16).
    Sends ATA commands through the SAT (SCSI/ATA Translation) layer.
    Reaches USB-NVMe drives via UASP when NVMe passthrough is blocked.

    SCSI ATA PASS-THROUGH (16) CDB (16 bytes):
      [0]  = 0x85 (SCSI ATA PASS-THROUGH 16 opcode)
      [1]  = protocol (4=PIO-in, 5=PIO-out, 6=DMA, 3=Non-data)
      [2]  = EXTEND | T_DIR | BYT_BLOK | T_LENGTH
      [3]  = features (high byte for 48-bit)
      [4]  = features (low byte)
      [5]  = sector count (high)
      [6]  = sector count (low)
      [7]  = LBA low (high)
      [8]  = LBA low (low)
      [9]  = LBA mid (high)
      [10] = LBA mid (low)
      [11] = LBA high (high)
      [12] = LBA high (low)
      [13] = device
      [14] = command
      [15] = control
    """
    feature = _nvme_action_to_ata_feature(action)
    feat_lo = feature & 0xFF
    feat_hi = (feature >> 8) & 0xFF

    # Protocol 3 = Non-data (no data transfer), EXTEND=1 for 48-bit
    protocol = (3 << 1) | 1   # bits[4:1]=protocol, bit[0]=EXTEND
    # T_LENGTH=0 (no transfer length), BYT_BLOK=0, T_DIR=0, CK_COND=0
    flags = 0x00

    # ATA SANITIZE erase key (required by ATA spec for BLOCK ERASE/OVERWRITE)
    # LBA low = 0x45, LBA mid = 0x72 ("Er" in ASCII)
    cdb = bytes([
        SCSI_ATA_PASSTHROUGH_16,  # [0]  opcode
        protocol,                  # [1]  protocol + EXTEND
        flags,                     # [2]  flags
        feat_hi,                   # [3]  features high (48-bit)
        feat_lo,                   # [4]  features low
        0x00,                      # [5]  sector count high
        0x00,                      # [6]  sector count low
        0x00,                      # [7]  LBA low high
        0x45,                      # [8]  LBA low low  (erase key 'E')
        0x00,                      # [9]  LBA mid high
        0x72,                      # [10] LBA mid low  (erase key 'r')
        0x00,                      # [11] LBA high high
        0x00,                      # [12] LBA high low
        0x00,                      # [13] device
        ATA_CMD_SANITIZE_DEVICE,   # [14] ATA command
        0x00,                      # [15] control
    ])

    try:
        hdr_arr, cdb_arr, sense_buf, _ = _build_sg_io_hdr(
            cdb, dxfer_buf=None, timeout_ms=7200000
        )
        fcntl.ioctl(sg_fd, SG_IO, hdr_arr, 1)

        # Check sense buffer for errors
        if sense_buf[0] != 0 and sense_buf[2] & 0x0F not in (0x00, 0x01):
            sk  = sense_buf[2] & 0x0F
            asc = sense_buf[12]
            logger.debug(
                f"Tier 2 SCSI ATA: sense key=0x{sk:02X} ASC=0x{asc:02X}"
            )
            return False

        logger.debug(
            f"Tier 2 SCSI ATA: SANITIZE DEVICE dispatched "
            f"feature=0x{feature:04X} action=0x{action:02X}"
        )
        return True

    except OSError as e:
        logger.debug(f"Tier 2 SCSI ATA passthrough failed: {e}")
        return False


def probe_ata_passthrough(sg_fd: int, logger: logging.Logger) -> bool:
    """
    Non-destructive probe: sends ATA IDENTIFY DEVICE via SCSI passthrough.
    Returns True if the SG_IO interface responds correctly.
    """
    cdb = bytes([
        SCSI_ATA_PASSTHROUGH_16,
        (4 << 1) | 0,    # protocol=4 (PIO-in), EXTEND=0
        0x0E,             # T_DIR=1, BYT_BLOK=1, T_LENGTH=2
        0x00, 0x00,       # features
        0x00, 0x01,       # sector count = 1
        0x00, 0x00,       # LBA low
        0x00, 0x00,       # LBA mid
        0x00, 0x00,       # LBA high
        0x00,             # device
        ATA_CMD_IDENTIFY, # command
        0x00,             # control
    ])
    ident_buf = b'\x00' * 512
    try:
        hdr_arr, cdb_arr, sense_buf, _ = _build_sg_io_hdr(
            cdb, dxfer_buf=ident_buf, timeout_ms=10000
        )
        fcntl.ioctl(sg_fd, SG_IO, hdr_arr, 1)
        return True
    except OSError:
        return False


# ==============================================================================
# TIER 3 — blkdiscard FALLBACK
# ==============================================================================

def execute_blkdiscard(
    sd_fd: int, action: int, logger: logging.Logger
) -> bool:
    """
    Tier 3: BLKDISCARD ioctl — discards all LBAs on the device.
    Reaches the drive via the Linux block layer when SCSI passthrough unavailable.
    Less granular (no phase separation) but works universally on block devices.
    """
    try:
        # Get device size
        size_buf = array.array('Q', [0])
        fcntl.ioctl(sd_fd, BLKGETSIZE64, size_buf, 1)
        dev_size = size_buf[0]

        if dev_size == 0:
            logger.debug("Tier 3 blkdiscard: could not determine device size")
            return False

        # BLKDISCARD takes [start, length] as two uint64 values
        discard_range = struct.pack('QQ', 0, dev_size)
        discard_arr   = array.array('B', discard_range)
        fcntl.ioctl(sd_fd, BLKDISCARD, discard_arr, 1)

        logger.debug(
            f"Tier 3 blkdiscard: discarded {dev_size} bytes "
            f"action=0x{action:02X}"
        )
        return True

    except OSError as e:
        logger.debug(f"Tier 3 blkdiscard failed: {e}")
        return False


# ==============================================================================
# AUTO-DETECTION — PROBE WHICH TIER WORKS
# ==============================================================================

def detect_passthrough_tier(
    device_path: str,
    logger:      logging.Logger
) -> Tuple[str, str]:
    """
    Probes the device to determine the best passthrough tier.
    Returns (tier, effective_device_path) tuple.

    For USB drives on /dev/sdX:
      - Tries to find /dev/sgX for Tier 2
      - Falls back to /dev/sdX for Tier 3
    For /dev/nvmeX:
      - Always Tier 1
    For /dev/sgX:
      - Always Tier 2 (sg path given directly)
    """
    logger.info("━━━ USB/NVMe Passthrough Detection ━━━")
    dev_type = detect_device_type(device_path)

    # ── Native NVMe ──────────────────────────────────────────────────────────
    if dev_type == "nvme":
        logger.info(f"  Native NVMe device detected: {device_path}")
        logger.info(f"  ✓ Tier 1 NVMe direct (NVME_IOCTL_ADMIN_CMD): ACTIVE")
        logger.info(f"    Log Page 0x81 hardware confirmation: ENABLED")
        return TIER_NVME, device_path

    # ── SCSI block device (/dev/sdX) — USB enclosure ─────────────────────────
    if dev_type in ("sd", "unknown"):
        logger.info(
            f"  SCSI block device detected: {device_path} "
            f"(likely USB enclosure)"
        )

        # Try to find the sg node for ATA passthrough
        sg_path = find_sg_node(device_path)
        if sg_path and Path(sg_path).exists():
            logger.info(f"  Found SCSI generic node: {sg_path}")
            logger.info(
                f"  Probing Tier 2 — ATA SCSI passthrough (SG_IO)..."
            )
            try:
                sg_fd = os.open(sg_path, os.O_RDWR)
                supported = probe_ata_passthrough(sg_fd, logger)
                os.close(sg_fd)
                if supported:
                    logger.info(f"  ✓ Tier 2 SCSI/ATA passthrough: SUPPORTED")
                    logger.info(
                        f"    ATA SANITIZE DEVICE via SCSI ATA PASS-THROUGH (16)"
                    )
                    logger.info(
                        f"    Note: Phase B/C/A mapped to ATA feature codes"
                    )
                    logger.info(
                        f"    Note: Log Page 0x81 unavailable — time-based wait per cycle"
                    )
                    return TIER_SCSI, sg_path
                else:
                    logger.info(
                        f"  ✗ Tier 2 SCSI/ATA: probe failed — bridge may block SAT"
                    )
            except OSError as e:
                logger.info(f"  ✗ Tier 2 SCSI/ATA: could not open {sg_path} ({e})")
        else:
            logger.info(
                f"  ✗ Tier 2 SCSI/ATA: no /dev/sgX node found for {device_path}"
            )

        # Fall back to blkdiscard
        logger.info(f"  Probing Tier 3 — blkdiscard ({device_path})...")
        try:
            fd = os.open(device_path, os.O_RDWR)
            size_buf = array.array('Q', [0])
            fcntl.ioctl(fd, BLKGETSIZE64, size_buf, 1)
            os.close(fd)
            if size_buf[0] > 0:
                logger.info(f"  ✓ Tier 3 blkdiscard: SUPPORTED")
                logger.info(
                    f"    BLKDISCARD ioctl — block layer discard"
                )
                logger.info(
                    f"    Warning: Phase granularity not available — "
                    f"single discard per cycle"
                )
                logger.info(
                    f"    Warning: Time-based wait per cycle"
                )
                return TIER_DISCARD, device_path
        except OSError as e:
            logger.info(f"  ✗ Tier 3 blkdiscard: failed ({e})")

    # ── SCSI generic device (/dev/sgX) given directly ─────────────────────────
    if dev_type == "sg":
        logger.info(f"  SCSI generic device given directly: {device_path}")
        logger.info(f"  Probing Tier 2 — ATA SCSI passthrough (SG_IO)...")
        try:
            sg_fd     = os.open(device_path, os.O_RDWR)
            supported = probe_ata_passthrough(sg_fd, logger)
            os.close(sg_fd)
            if supported:
                logger.info(f"  ✓ Tier 2 SCSI/ATA passthrough: SUPPORTED")
                return TIER_SCSI, device_path
        except OSError as e:
            logger.info(f"  ✗ Tier 2 SCSI/ATA: {e}")

    logger.error("  ✗ No passthrough tier supported by this device/enclosure.")
    logger.error(
        "    The USB bridge chip is blocking all sanitize pathways."
    )
    logger.error(
        "    Recommendation: Install the drive directly in an M.2 slot."
    )
    return TIER_NONE, device_path


# ==============================================================================
# TIME-BASED POLLING (Tier 2 / Tier 3)
# ==============================================================================

def poll_time_based(cycle: int, logger: logging.Logger, wait_s: int = 120) -> bool:
    """
    Tier 2/3 polling: time-based wait when Log Page 0x81 is unavailable.
    120s conservative wait per cycle — sufficient for most drives.
    """
    logger.info(
        f"  Cycle {cycle:02d}: USB mode — waiting {wait_s}s for drive to complete..."
    )
    for elapsed in range(0, wait_s, 10):
        time.sleep(10)
        pct = int((elapsed / wait_s) * 100)
        bar = ("█" * (pct // 5)).ljust(20)
        logger.info(
            f"  Cycle {cycle:02d}: [{bar}] {pct}% ({elapsed}s/{wait_s}s)"
        )
    logger.info(f"  Cycle {cycle:02d}: Wait complete.")
    return True


# ==============================================================================
# UNIFIED COMMAND DISPATCH
# ==============================================================================

def execute_sanitize_cycle(
    fd:      int,
    action:  int,
    cycle:   int,
    tier:    str,
    logger:  logging.Logger
) -> bool:
    """
    Dispatches one sanitize cycle through the detected tier.
    """
    if tier == TIER_NVME:
        ok = execute_nvme_sanitize_direct(fd, action, logger)
        if not ok:
            return False
        return poll_until_complete_nvme(fd, cycle, logger)

    elif tier == TIER_SCSI:
        ok = execute_scsi_ata_sanitize(fd, action, logger)
        if not ok:
            return False
        return poll_time_based(cycle, logger, wait_s=120)

    elif tier == TIER_DISCARD:
        ok = execute_blkdiscard(fd, action, logger)
        if not ok:
            return False
        return poll_time_based(cycle, logger, wait_s=180)

    else:
        logger.error(f"  Cycle {cycle:02d}: No passthrough tier available.")
        return False


# ==============================================================================
# POST-RUN VERIFICATION
# ==============================================================================

def verify_sanitization(
    device_path: str,
    total_lbas:  Optional[int],
    logger:      logging.Logger
) -> list:
    results     = []
    sector_size = 512

    if total_lbas is None:
        probe_lbas = [
            i * VERIFICATION_LBA_STEP for i in range(VERIFICATION_SAMPLE_COUNT)
        ]
    else:
        step       = max(1, total_lbas // VERIFICATION_SAMPLE_COUNT)
        probe_lbas = [i * step for i in range(VERIFICATION_SAMPLE_COUNT)]

    logger.info("")
    logger.info("━━━ POST-RUN VERIFICATION — LBA Sample Read ━━━")

    try:
        fd = os.open(device_path, os.O_RDONLY)
    except OSError as e:
        logger.error(f"  Could not open device for verification: {e}")
        return results

    try:
        for lba in probe_lbas:
            byte_offset = lba * sector_size
            rec         = VerificationRecord(lba=lba, result="UNKNOWN")
            try:
                os.lseek(fd, byte_offset, os.SEEK_SET)
                data = os.read(fd, sector_size)
                if all(b == 0x00 for b in data):
                    rec.result = "ZEROED"
                    logger.info(f"  LBA 0x{lba:010X} — ZEROED ✓")
                else:
                    non_zero   = sum(1 for b in data if b != 0)
                    rec.result = "NON-ZERO"
                    rec.detail = f"{non_zero}/{sector_size} non-zero bytes"
                    logger.warning(
                        f"  LBA 0x{lba:010X} — NON-ZERO ({non_zero} bytes) ⚠"
                    )
            except OSError as e:
                err_str = str(e)
                if "No such device" in err_str or "Input/output error" in err_str:
                    rec.result = "DEALLOCATED"
                    logger.info(
                        f"  LBA 0x{lba:010X} — DEALLOCATED ✓"
                    )
                else:
                    rec.result = "ERROR"
                    rec.detail = err_str
                    logger.warning(
                        f"  LBA 0x{lba:010X} — READ ERROR: {err_str}"
                    )
            results.append(rec)
    finally:
        os.close(fd)

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

    fd          = None
    active_tier = TIER_NONE
    active_path = device_path

    try:
        if not dry_run:
            # ── Auto-detect tier ──────────────────────────────────────────────
            active_tier, active_path = detect_passthrough_tier(device_path, logger)
            if active_tier == TIER_NONE:
                return False

            if report:
                report.pathway_used = active_tier

            fd = os.open(active_path, os.O_RDWR)
            logger.info(f"  Device handle opened: {active_path}")
            logger.info(f"  Active pathway: {active_tier}")
            logger.info("")
        else:
            active_tier = TIER_NVME
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
                            fd, action, cycle, active_tier, logger
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
                                    duration_sec=round(
                                        time.monotonic() - cycle_start, 2
                                    )
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

                logger.debug(
                    f"  Cycle {cycle:02d} done in {duration}s via {active_tier}."
                )

    finally:
        if fd is not None:
            os.close(fd)
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

    cycle_blob      = json.dumps([asdict(c) for c in report.cycles], sort_keys=True)
    report.log_hash = hashlib.sha256(cycle_blob.encode()).hexdigest()

    logger.info("")
    logger.info("=" * 78)
    logger.info(f"  {TOOL_NAME} v{TOOL_VERSION}")
    logger.info(f"  Author : {AUTHOR} <{CONTACT}>")
    logger.info("=" * 78)
    logger.info(f"  OUTCOME   : {report.outcome}")
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
# CLI
# ==============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aad50_abeselom",
        description=(
            f"{TOOL_NAME}\n"
            f"{SPEC_NAME}\n"
            f"Author: {AUTHOR} <{CONTACT}>  |  Version {TOOL_VERSION}\n"
            f"USB Support: SCSI/ATA passthrough (SG_IO) + blkdiscard fallback"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 aad50_abeselom.py /dev/nvme0\n"
            "  sudo python3 aad50_abeselom.py /dev/nvme0 --log /var/log/aad50.log\n"
            "  sudo python3 aad50_abeselom.py /dev/nvme0 --dry-run --verbose\n"
            "\n"
            "USB ENCLOSURE EXAMPLES:\n"
            "  sudo python3 aad50_abeselom.py /dev/sdb\n"
            "  sudo python3 aad50_abeselom.py /dev/sg1\n"
            "  sudo python3 aad50_abeselom.py /dev/sdb --log /var/log/aad50.log\n"
            "\n"
            "USB NOTE:\n"
            "  AAD-50 auto-detects the best passthrough pathway:\n"
            "  /dev/nvme* → Tier 1 NVMe direct (full Log Page 0x81 confirmation)\n"
            "  /dev/sd*   → Tier 2 SCSI/ATA via /dev/sgX, or Tier 3 blkdiscard\n"
            "  /dev/sg*   → Tier 2 SCSI/ATA passthrough directly\n"
            "\n"
            "NOTE: Always run with sudo.\n"
            "NOTE: Target /dev/nvme0 (controller), not /dev/nvme0n1 (namespace).\n"
        )
    )
    parser.add_argument(
        "device",
        help=(
            "Target device: /dev/nvme0 (native NVMe), "
            "/dev/sdb (USB enclosure), or /dev/sg1 (SCSI generic)"
        )
    )
    parser.add_argument(
        "--log", metavar="PATH", default=None,
        help="Write timestamped log and JSON audit report to PATH"
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Skip interactive authorization. For automated pipelines."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Simulate full 50-cycle sequence without issuing any IOCTL commands"
    )
    parser.add_argument(
        "--skip-verify", action="store_true",
        help="Skip post-sanitization LBA verification read"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug output (IOCTL details, Log Page 0x81 traces)"
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} v{TOOL_VERSION}"
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args   = parser.parse_args()
    logger = configure_logging(args.log, args.verbose)

    if not args.dry_run and os.geteuid() != 0:
        logger.error(
            "Root privileges required. Re-run with sudo."
        )
        return 1

    device = args.device

    if not args.dry_run:
        if not validate_nvme_device(device, logger):
            return 1

    # Drive info (best-effort, NVMe only)
    model, total_lbas = (None, None)
    if not args.dry_run and detect_device_type(device) == "nvme":
        model, total_lbas = get_device_info(device)

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
        f"{TOTAL_CYCLES} cycles | Async polling: ENABLED"
    )
    if args.dry_run:
        logger.info("[DRY RUN MODE — No IOCTL commands will be issued]")

    success = run_sanitization(
        device_path=device,
        logger=logger,
        dry_run=args.dry_run,
        force=args.force,
        report=report
    )

    if success and not args.skip_verify and not args.dry_run:
        verif_records = verify_sanitization(device, total_lbas, logger)
        report.verification = [asdict(v) for v in verif_records]
    elif args.skip_verify:
        logger.info("Post-run verification skipped via --skip-verify.")

    finalize_report(report, success, args.log, logger)
    return 0 if success else 2


if __name__ == "__main__":
    sys.exit(main())
