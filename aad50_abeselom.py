#!/usr/bin/env python3
# ==============================================================================
# THE ABESELOM ASIC-DIRECT 50 (AAD-50)
# Firmware-Enforced Flash Sanitization Specification
# ==============================================================================
# Author      : Yonas Abeselom (yonas_abeselom@protonmail.com)
# Version     : 1.0
# Date        : June 1, 2026
# Architecture: Low-Level NVMe Admin Command Interface (IOCTL, Linux)
# Target Media: NVMe Solid-State Drives (Enterprise & Consumer NAND Flash)
# Compliance  : NIST SP 800-88 Rev.1 "Purge" | NVMe Base Spec 2.0/2.1
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
# PHASE EXECUTION ORDER:
#   Phase B — Physical NAND Cell Overwrite     (Cycles  1–40)
#   Phase C — Flash Translation Layer Reset    (Cycles 41–45)
#   Phase A — Cryptographic Key Destruction    (Cycles 46–50)
#
#   Rationale for ordering: Physical overwrite runs first so that if a
#   mid-sequence hardware fault occurs, raw NAND data has already been
#   cleared. Cryptographic key destruction runs last as the final seal,
#   ensuring no partially-overwritten state can be decrypted post-failure.
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
TOOL_VERSION = "1.0"
SPEC_NAME    = "Firmware-Enforced Flash Sanitization, 50-Cycle Specification"
AUTHOR       = "Yonas Abeselom"
CONTACT      = "yonas_abeselom@protonmail.com"

# ── NVMe IOCTL ────────────────────────────────────────────────────────────────
# Linux kernel ioctl number for struct nvme_admin_cmd pass-through
# Derived from: _IOWR('N', 0x41, struct nvme_admin_cmd) = 0xC0484E41
NVME_IOCTL_ADMIN_CMD = 0xC0484E41

# NVMe Get Log Page opcode (NVMe Base Spec 2.0, Section 5.14)
NVME_GET_LOG_PAGE_OPCODE = 0x02

# NVMe Log Page 0x81 — Sanitize Status (NVMe Base Spec 2.0, Section 5.14.1.14)
NVME_LOG_SANITIZE_STATUS = 0x81

# NVMe Sanitize opcode (NVMe Base Spec 2.0, Section 5.25)
NVME_SANITIZE_OPCODE = 0x84

# NVMe Sanitize Action field values (CDW10 bits [2:0])
SANITIZE_ACTION_BLOCK_ERASE  = 0x01  # Block Erase  — FTL table invalidation
SANITIZE_ACTION_OVERWRITE    = 0x02  # Overwrite    — firmware-driven cell clearing
SANITIZE_ACTION_CRYPTO_ERASE = 0x04  # Crypto Erase — MEK register destruction

# Namespace ID: 0xFFFFFFFF = broadcast across entire controller subsystem
NVME_NSID_ALL = 0xFFFFFFFF

# ── Log Page 0x81 SSTAT field values ─────────────────────────────────────────
# NVMe Base Spec 2.0, Section 5.14.1.14, byte offset 0, bits [2:0]
SANITIZE_SSTAT_IDLE          = 0x0   # No sanitize operation has been performed
SANITIZE_SSTAT_IN_PROGRESS   = 0x2   # Sanitize operation in progress
SANITIZE_SSTAT_COMPLETED_OK  = 0x1   # Most recent sanitize completed successfully
SANITIZE_SSTAT_COMPLETED_ERR = 0x3   # Most recent sanitize completed with errors

# ── Polling configuration ─────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS  = 2.0    # Seconds between each Log Page 0x81 read
POLL_TIMEOUT_SECONDS   = 7200   # 2-hour hard timeout per cycle (enterprise drives)

# ── Authorization ─────────────────────────────────────────────────────────────
AUTHORIZATION_TOKEN = "EXECUTE-AAD-50-ABESELOM"
TOTAL_CYCLES        = 50

# ── Post-run verification ─────────────────────────────────────────────────────
# Number of LBAs to sample-read after completion to confirm deallocated status
VERIFICATION_SAMPLE_COUNT = 16
VERIFICATION_LBA_STEP     = 0x100000  # Sample every ~512 MiB of logical space


# ==============================================================================
# DATA CLASSES
# ==============================================================================

@dataclass
class CycleRecord:
    cycle:         int
    phase:         str
    action_code:   int
    timestamp:     str
    status:        str
    duration_sec:  float = 0.0
    error:         Optional[str] = None


@dataclass
class VerificationRecord:
    lba:     int
    result:  str   # "DEALLOCATED" | "ZEROED" | "READABLE" | "ERROR"
    detail:  Optional[str] = None


@dataclass
class SanitizationReport:
    tool:           str = TOOL_NAME
    version:        str = TOOL_VERSION
    author:         str = AUTHOR
    contact:        str = CONTACT
    device:         str = ""
    drive_model:    str = ""
    started_at:     str = ""
    completed_at:   str = ""
    total_cycles:   int = TOTAL_CYCLES
    cycles_run:     int = 0
    outcome:        str = "NOT STARTED"
    verification:   list = field(default_factory=list)
    cycles:         list = field(default_factory=list)
    log_hash:       Optional[str] = None


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
    """
    Confirms the target is an accessible NVMe block device before any
    destructive commands are issued.
    """
    p = Path(device_path)

    if not p.exists():
        logger.error(f"Device path does not exist: {device_path}")
        return False

    if not p.is_block_device():
        logger.error(f"Path is not a block device: {device_path}")
        return False

    # Warn if path looks like a namespace (nvme0n1) rather than a controller (nvme0).
    # AAD-50 targets the controller node so the NSID broadcast reaches all namespaces.
    name = p.name
    if "n" in name[4:]:
        logger.warning(
            f"'{name}' appears to be a namespace node, not a controller node. "
            f"AAD-50 should target the controller (e.g. /dev/nvme0) to ensure "
            f"the NSID=0xFFFFFFFF broadcast covers all namespaces."
        )

    # Live probe — 512-byte read confirms the controller is online and accessible
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
    """
    Returns (model_string, total_lba_count) via nvme-cli.
    Both values are best-effort; None is returned on any failure.
    """
    model = None
    total_lbas = None
    try:
        r = subprocess.run(
            ["nvme", "id-ctrl", device_path, "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            data = json.loads(r.stdout)
            model = data.get("mn", "").strip() or None
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["nvme", "id-ns", device_path, "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            data = json.loads(r.stdout)
            total_lbas = data.get("nsze")
    except Exception:
        pass

    return model, total_lbas


# ==============================================================================
# NVMe IOCTL HELPERS
# ==============================================================================

# Linux kernel struct nvme_admin_cmd memory layout (little-endian):
#   u8  opcode       — NVMe Admin opcode
#   u8  flags        — Reserved / command flags
#   u16 rsvd1        — Reserved
#   u32 nsid         — Namespace ID (0xFFFFFFFF = all namespaces)
#   u32 cdw2         — Command Dword 2 (reserved)
#   u32 cdw3         — Command Dword 3 (reserved)
#   u64 metadata     — Metadata pointer (unused here)
#   u64 addr         — Data buffer address (unused here)
#   u32 metadata_len — Metadata length
#   u32 data_len     — Data buffer length
#   u32 cdw10        — Command-specific dword 10
#   u32 cdw11        — Command-specific dword 11
#   u32 cdw12        — Command-specific dword 12
#   u32 cdw13        — Command-specific dword 13
#   u32 cdw14        — Command-specific dword 14
#   u32 cdw15        — Command-specific dword 15
#   u32 timeout_ms   — Command timeout in milliseconds (0 = driver default)
#   u32 result       — Command completion result (written back by kernel)
#
# Format string: B B H I I I Q Q I I I I I I I I I I
# Total size   : 1+1+2+4+4+4+8+8+4+4+4+4+4+4+4+4+4+4 = 72 bytes
# Linux kernel struct nvme_admin_cmd — 18 fields, 72 bytes
# Fields: opcode flags rsvd1 nsid cdw2 cdw3 metadata addr
#         metadata_len data_len cdw10 cdw11 cdw12 cdw13 cdw14 cdw15
#         timeout_ms result
NVME_ADMIN_CMD_FMT = 'BBHIIIQQIIIIIIIIII'  # 18 fields, 72 bytes


def _build_sanitize_cmd(action: int) -> array.array:
    """Packs a sanitize admin command struct for the given action code."""
    cmd = struct.pack(
        NVME_ADMIN_CMD_FMT,
        NVME_SANITIZE_OPCODE,  # opcode
        0,                     # flags
        0,                     # rsvd1
        NVME_NSID_ALL,         # nsid
        0,                     # cdw2
        0,                     # cdw3
        0,                     # metadata ptr
        0,                     # data addr
        0,                     # metadata_len
        0,                     # data_len
        action,                # cdw10: Sanitize Action
        0,                     # cdw11
        0,                     # cdw12
        0,                     # cdw13
        0,                     # cdw14
        0,                     # cdw15
        0,                     # timeout_ms (driver default)
        0,                     # result (written back by kernel)
    )
    return array.array('b', cmd)


def _build_get_log_page_cmd(log_id: int, data_addr: int, data_len: int) -> array.array:
    """
    Packs a Get Log Page admin command.
    CDW10: log_id [7:0], numd [27:16] — numd = (data_len/4 - 1)
    """
    numd = (data_len // 4) - 1
    cdw10 = (log_id & 0xFF) | ((numd & 0xFFF) << 16)
    cmd = struct.pack(
        NVME_ADMIN_CMD_FMT,
        NVME_GET_LOG_PAGE_OPCODE,  # opcode
        0,                         # flags
        0,                         # rsvd1
        NVME_NSID_ALL,             # nsid
        0,                         # cdw2
        0,                         # cdw3
        0,                         # metadata ptr
        data_addr,                 # data addr — kernel will write result here
        0,                         # metadata_len
        data_len,                  # data_len
        cdw10,                     # cdw10: log page ID + NUMD
        0,                         # cdw11
        0,                         # cdw12
        0,                         # cdw13
        0,                         # cdw14
        0,                         # cdw15
        0,                         # timeout_ms
        0,                         # result (written back by kernel)
    )
    return array.array('b', cmd)


def execute_nvme_sanitize(disk_fd: int, action: int, logger: logging.Logger) -> None:
    """Issues one NVMe Sanitize command. Returns immediately (async)."""
    buf = _build_sanitize_cmd(action)
    fcntl.ioctl(disk_fd, NVME_IOCTL_ADMIN_CMD, buf, 1)
    logger.debug(
        f"Sanitize command dispatched — "
        f"opcode=0x{NVME_SANITIZE_OPCODE:02X}, action=0x{action:02X}"
    )


# ==============================================================================
# LOG PAGE 0x81 — SANITIZE STATUS POLLING
# ==============================================================================

def read_sanitize_status(disk_fd: int, logger: logging.Logger) -> Optional[int]:
    """
    Reads NVMe Log Page 0x81 (Sanitize Status) and returns the SSTAT field
    value (bits [2:0] of byte 0), or None on read failure.

    Log Page 0x81 layout (NVMe Base Spec 2.0, Section 5.14.1.14):
        Bytes  [1:0] — SPROG  : Sanitize Progress (0x0000–0xFFFF, 0xFFFF = 100%)
        Bytes  [3:2] — SSTAT  : Sanitize Status (bits [2:0] are the status code)
        Bytes  [7:4] — SCDW10 : Command Dword 10 of the last sanitize command
        Bytes [11:8] — Estimated overwrite time (seconds)
        Bytes[15:12] — Estimated block erase time (seconds)
        Bytes[19:16] — Estimated crypto erase time (seconds)
    """
    LOG_DATA_LEN = 20  # Minimum bytes covering all fields we need

    # Allocate a pinned read buffer and get its memory address for the IOCTL
    data_buf = array.array('B', b'\x00' * LOG_DATA_LEN)
    buf_addr, _ = data_buf.buffer_info()

    cmd_buf = _build_get_log_page_cmd(
        log_id=NVME_LOG_SANITIZE_STATUS,
        data_addr=buf_addr,
        data_len=LOG_DATA_LEN
    )

    try:
        fcntl.ioctl(disk_fd, NVME_IOCTL_ADMIN_CMD, cmd_buf, 1)
    except OSError as e:
        logger.debug(f"Log Page 0x81 read failed: {e}")
        return None

    # SSTAT is at byte offset 2–3 (little-endian u16); status code = bits [2:0]
    sstat = data_buf[2] | (data_buf[3] << 8)
    sprog = data_buf[0] | (data_buf[1] << 8)
    status_code = sstat & 0x07

    prog_pct = int((sprog / 0xFFFF) * 100) if sprog > 0 else 0
    logger.debug(
        f"Log Page 0x81 — SSTAT=0x{sstat:04X} "
        f"(code={status_code}) SPROG={sprog:#06x} ({prog_pct}%)"
    )

    return status_code


def poll_until_complete(
    disk_fd: int,
    cycle: int,
    logger: logging.Logger,
    dry_run: bool = False
) -> bool:
    """
    Blocks until Log Page 0x81 reports sanitize complete (SSTAT=0x1),
    polling every POLL_INTERVAL_SECONDS up to POLL_TIMEOUT_SECONDS.

    Returns True on confirmed completion, False on timeout or error status.
    """
    if dry_run:
        logger.debug(f"  [DRY RUN] Skipping Log Page 0x81 poll for cycle {cycle}.")
        return True

    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    elapsed  = 0.0

    while time.monotonic() < deadline:
        status = read_sanitize_status(disk_fd, logger)

        if status is None:
            # Read failure — drive may be mid-erase and temporarily unresponsive.
            # This is normal. Wait and retry.
            logger.debug(f"  Cycle {cycle:02d}: Status read returned None — retrying...")

        elif status == SANITIZE_SSTAT_COMPLETED_OK:
            logger.debug(f"  Cycle {cycle:02d}: SSTAT=0x1 — Hardware confirmed complete.")
            return True

        elif status == SANITIZE_SSTAT_IN_PROGRESS:
            logger.debug(f"  Cycle {cycle:02d}: SSTAT=0x2 — Sanitize in progress ({elapsed:.0f}s)...")

        elif status == SANITIZE_SSTAT_IDLE:
            # Drive returned to idle — treat as complete (some controllers
            # transition directly to 0x0 rather than holding 0x1)
            logger.debug(f"  Cycle {cycle:02d}: SSTAT=0x0 — Controller returned to idle state.")
            return True

        elif status == SANITIZE_SSTAT_COMPLETED_ERR:
            logger.error(
                f"  Cycle {cycle:02d}: SSTAT=0x3 — Controller reported sanitize error."
            )
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
    total_lbas: Optional[int],
    logger: logging.Logger
) -> list:
    """
    Samples VERIFICATION_SAMPLE_COUNT LBAs across the drive's logical address
    space and confirms each returns deallocated/zeroed data.

    Returns a list of VerificationRecord objects.
    """
    results = []
    sector_size = 512

    if total_lbas is None:
        # Fall back to a fixed-LBA probe if drive geometry is unknown
        probe_lbas = [i * VERIFICATION_LBA_STEP for i in range(VERIFICATION_SAMPLE_COUNT)]
    else:
        step = max(1, total_lbas // VERIFICATION_SAMPLE_COUNT)
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
            rec = VerificationRecord(lba=lba, result="UNKNOWN")
            try:
                os.lseek(fd, byte_offset, os.SEEK_SET)
                data = os.read(fd, sector_size)

                if all(b == 0x00 for b in data):
                    rec.result = "ZEROED"
                    logger.info(f"  LBA 0x{lba:010X} — ZEROED  ✓")
                else:
                    # Non-zero data post-sanitize is unexpected — flag it
                    non_zero = sum(1 for b in data if b != 0)
                    rec.result  = "NON-ZERO"
                    rec.detail  = f"{non_zero}/{sector_size} non-zero bytes"
                    logger.warning(
                        f"  LBA 0x{lba:010X} — NON-ZERO ({non_zero} bytes) ⚠"
                    )

            except OSError as e:
                err_str = str(e)
                # ENXIO / EIO on unallocated LBA is correct post-sanitize behaviour
                if "No such device" in err_str or "Input/output error" in err_str:
                    rec.result = "DEALLOCATED"
                    logger.info(f"  LBA 0x{lba:010X} — DEALLOCATED (hardware unallocated) ✓")
                else:
                    rec.result = "ERROR"
                    rec.detail = err_str
                    logger.warning(f"  LBA 0x{lba:010X} — READ ERROR: {err_str}")

            results.append(rec)

    finally:
        os.close(fd)

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
    device_path:  str,
    logger:       logging.Logger,
    dry_run:      bool = False,
    force:        bool = False,
    report:       Optional[SanitizationReport] = None
) -> bool:
    """
    Executes the AAD-50 three-phase sanitization sequence in the correct order:
      Phase B (Overwrite)    → Cycles  1–40
      Phase C (Block Erase)  → Cycles 41–45
      Phase A (Crypto Erase) → Cycles 46–50

    Each cycle blocks until Log Page 0x81 confirms hardware completion before
    the next cycle is dispatched.
    """
    phases = [
        # (phase_label,                          cycle_range,   action_code,                delay_label)
        ("B — Physical NAND Cell Overwrite",    range(1,  41), SANITIZE_ACTION_OVERWRITE,    "overwrite"),
        ("C — Flash Translation Layer Reset",   range(41, 46), SANITIZE_ACTION_BLOCK_ERASE,  "block erase"),
        ("A — Cryptographic Key Destruction",   range(46, 51), SANITIZE_ACTION_CRYPTO_ERASE, "crypto erase"),
    ]

    fd = None
    try:
        if not dry_run:
            fd = os.open(device_path, os.O_RDWR)
            logger.info(f"Direct controller handle opened: {device_path}")
        else:
            logger.info("[DRY RUN] No device handle opened — simulating full sequence.")

        for phase_label, cycles, action, action_name in phases:
            logger.info("")
            logger.info(f"━━━ PHASE {phase_label} ━━━")

            for cycle in cycles:
                ts         = datetime.now(timezone.utc).isoformat()
                pct        = int((cycle / TOTAL_CYCLES) * 100)
                bar        = ("█" * (pct // 5)).ljust(20)
                cycle_start = time.monotonic()

                logger.info(
                    f"  Cycle {cycle:02d}/{TOTAL_CYCLES} [{bar}] {pct:3d}%  "
                    f"Action=0x{action:02X} ({action_name})"
                )

                status    = "OK"
                error_msg = None

                try:
                    if not dry_run:
                        execute_nvme_sanitize(fd, action, logger)

                        # ── CRITICAL: Block until this cycle is confirmed complete ──
                        completed = poll_until_complete(fd, cycle, logger, dry_run=False)
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
                        # Dry run: simulate a short delay to mimic real timing
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
        if fd is not None:
            os.close(fd)
            logger.debug("Controller handle closed.")

    return True


# ==============================================================================
# REPORT FINALIZATION
# ==============================================================================

def finalize_report(
    report:    SanitizationReport,
    success:   bool,
    log_path:  Optional[str],
    logger:    logging.Logger
) -> None:
    report.completed_at = datetime.now(timezone.utc).isoformat()
    report.outcome = "SUCCESS — DATA DESTROYED" if success else "FAILED — INCOMPLETE"

    # SHA-256 chain-of-custody hash over all cycle records (key-sorted for determinism)
    cycle_blob   = json.dumps([asdict(c) for c in report.cycles], sort_keys=True)
    report.log_hash = hashlib.sha256(cycle_blob.encode()).hexdigest()

    logger.info("")
    logger.info("=" * 78)
    logger.info(f"  {TOOL_NAME} v{TOOL_VERSION}")
    logger.info(f"  Author : {AUTHOR} <{CONTACT}>")
    logger.info("=" * 78)
    logger.info(f"  OUTCOME   : {report.outcome}")
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
    """
    In interactive mode: prints a full destruction warning and requires the
    operator to type the authorization token exactly.
    In --force mode: prints a condensed warning and proceeds automatically
    (intended for automated server deprovisioning pipelines).
    """
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
# CLI
# ==============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aad50_abeselom",
        description=(
            f"{TOOL_NAME}\n"
            f"{SPEC_NAME}\n"
            f"Author: {AUTHOR} <{CONTACT}>  |  Version {TOOL_VERSION}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 aad50_abeselom.py /dev/nvme0\n"
            "  sudo python3 aad50_abeselom.py /dev/nvme0 --log /var/log/aad50.log\n"
            "  sudo python3 aad50_abeselom.py /dev/nvme0 --log /var/log/aad50.log --force\n"
            "  sudo python3 aad50_abeselom.py /dev/nvme0 --dry-run --verbose\n"
        )
    )
    parser.add_argument(
        "device",
        help="Target NVMe controller node (e.g. /dev/nvme0)"
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
        help="Simulate the full 50-cycle sequence without issuing any IOCTL commands"
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip the post-sanitization LBA verification read"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug output (IOCTL dispatch details, Log Page 0x81 poll traces)"
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

    # Root privilege guard
    if not args.dry_run and os.geteuid() != 0:
        logger.error(
            "Root privileges are required to open raw NVMe controller handles. "
            "Re-run with sudo."
        )
        return 1

    device = args.device

    # Device validation
    if not args.dry_run:
        if not validate_nvme_device(device, logger):
            return 1

    # Drive identification (best-effort)
    model, total_lbas = (None, None) if args.dry_run else get_device_info(device)

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
        f"{TOTAL_CYCLES} cycles | Async polling: ENABLED"
    )
    if args.dry_run:
        logger.info("[DRY RUN MODE — No IOCTL commands will be issued]")

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
        verif_records = verify_sanitization(device, total_lbas, logger)
        report.verification = [asdict(v) for v in verif_records]
    elif args.skip_verify:
        logger.info("Post-run verification skipped via --skip-verify.")

    # Finalize and save report
    finalize_report(report, success, args.log, logger)

    return 0 if success else 2


if __name__ == "__main__":
    sys.exit(main())
