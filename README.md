# The Abeselom ASIC-Direct 50 (AAD-50)

<p align="center">
  <img src="AAD50_Logo.png" alt="AAD-50 Official Logo" width="600"/>
</p>

### Firmware-Enforced Flash Sanitization Specification for NVMe Solid-State Storage

**Author:** Yonas Abeselom — BSc Computer Science | Diploma in Information Technology  
**Contact:** yonas_abeselom@protonmail.com | https://github.com/yonasabeselom  
**Version:** 1.0 — June 2026  
**Status:** Open for peer review

---

## Abstract

The Abeselom ASIC-Direct 50 (AAD-50) is a firmware-enforced, 50-cycle data sanitization specification designed explicitly for NVMe solid-state drives. By leveraging low-level IOCTL pass-through structures to communicate directly with the on-drive ASIC, AAD-50 bypasses the operating-system filesystem layer entirely. The protocol executes a deterministic three-phase destruction matrix — physical NAND cell overwrite, Flash Translation Layer index teardown, and cryptographic key destruction — each cycle gated by active polling of NVMe Log Page 0x81 (Sanitize Status) to guarantee hardware-confirmed completion before the next cycle is issued.

The result is a mathematically provable, forensically irreversible, and fully auditable sanitization standard aligned with NIST SP 800-88 Rev. 1 Purge classification and the NVMe Base Specification 2.0/2.1 Sanitize command set.

---

## How AAD-50 Works — Step by Step

![AAD-50 Step-by-Step Process](AAD50_Process_Infographic.png)

---

## The Problem

Traditional data sanitization standards (DoD 5220.22-M, Gutmann 35-pass) were engineered for magnetic hard disk drives. On solid-state drives, they are fundamentally ineffective.

The Flash Translation Layer (FTL) constantly intercepts host writes and redirects data to fresh physical blocks. When standard software attempts to overwrite a drive, the target data is not destroyed — it is merely unmapped. The original data remains fully intact in:

- **Over-provisioned zones** — 7%–27% of raw capacity, completely invisible to the OS
- **Retired bad blocks** — degraded cells isolated by the FTL but never erased
- **Wear-levelling pools** — historical data preserved across charge-trap nitride layers

Recovering this data via chip-level hardware extraction or Magnetic Force Microscopy (MFM) is a known attack vector used in state-sponsored forensic operations.

---

## The AAD-50 Solution

AAD-50 bypasses the OS and communicates directly with the drive controller via firmware-level NVMe Sanitize commands (Opcode `0x84`) that the on-chip ASIC executes internally at silicon speeds.

- **Linux:** via the kernel's `nvme_admin_cmd` IOCTL interface (`0xC0484E41`)
- **Windows:** via `DeviceIoControl` with `IOCTL_STORAGE_PROTOCOL_COMMAND` (`0x0002D14C`)

### Phase Execution Matrix

| Phase | Cycles | Action | CDW10 |
|---|---|---|---|
| B — Physical NAND Cell Overwrite | 1–40 | Firmware Overwrite | `0x02` |
| C — Flash Translation Layer Reset | 41–45 | Block Erase | `0x01` |
| A — Cryptographic Key Destruction | 46–50 | Crypto Erase | `0x04` |

The deliberate **B → C → A** ordering is a security design decision. Physical cell overwrite runs first so that if a mid-sequence hardware fault occurs, raw NAND data has already been cleared. Cryptographic key destruction runs last as the final seal.

### Async Polling — The Critical Distinction

The NVMe Sanitize command is **asynchronous**. The drive controller acknowledges the command instantly while performing the actual erasure in the background. Issuing 50 consecutive commands without confirmation produces a race condition that defeats the multi-cycle guarantee entirely.

AAD-50 mandates active polling of **NVMe Log Page 0x81** (Sanitize Status) after every single cycle dispatch. The next cycle is only issued once the SSTAT field returns `0x1` (Completed Successfully) or `0x0` (Idle). Any error code aborts the sequence immediately and writes a fault record to the audit log.

This is the architectural detail that distinguishes AAD-50 from naive multi-pass implementations.

---

## Protocol Comparison

| Standard | Era | Bypasses FTL? | Clears OP Zones? | Clears Bad Blocks? | NAND Wear |
|---|---|---|---|---|---|
| DoD 5220.22-M (3-pass) | HDD 1995 | No | No | No | High |
| Gutmann (35-pass) | HDD 1996 | No | No | No | Extreme |
| NIST SP 800-88 (1-pass) | SSD 2014 | Yes | Yes | Vendor-dependent | Very Low |
| **AAD-50 (50-cycle)** | **NVMe 2026** | **Yes** | **Yes (Full)** | **Yes (SED Purge)** | **Optimised** |

---

## Reference Implementation

AAD-50 is available as a reference implementation on both **Linux** and **Windows**. Both versions execute the identical 50-cycle B → C → A destruction matrix via firmware-level NVMe Sanitize commands — only the OS interface layer differs.

| File | Platform | Interface | Status |
|---|---|---|---|
| `aad50_abeselom.py` | Linux 5.15+ | `nvme_admin_cmd` IOCTL (`0xC0484E41`) | Stable |
| `aad50_abeselom_windows.py` | Windows 10 1607+ / 11 | `DeviceIoControl` (`IOCTL_STORAGE_PROTOCOL_COMMAND`) | Beta |

> **Windows Beta status:** The Windows port implements the identical AAD-50 protocol via the Windows-equivalent API pathway. Hardware testing across NVMe manufacturers is ongoing. If you test it on a real drive, please open a GitHub Issue with your results — your feedback directly contributes to validating the specification.

### Linux Requirements

- Python 3.10+
- Linux kernel 5.15+
- Root / sudo access
- Target: NVMe controller node (e.g. `/dev/nvme0`, not a namespace node like `/dev/nvme0n1`)
- Optional: `nvme-cli` for drive model identification

### Windows Requirements

- Python 3.10+
- Windows 10 version 1607+ / Windows 11 / Windows Server 2016+
- Administrator privileges (right-click → Run as administrator)
- Target: Physical NVMe drive (e.g. `\\.\PhysicalDrive0`)
- No external Python dependencies — standard library only

### Installation

```bash
git clone https://github.com/yonasabeselom/aad50
cd aad50
```

No external Python dependencies on either platform. Both implementations use only the standard library.

### Linux Usage

```bash
# List available NVMe drives
sudo python3 aad50_abeselom.py --help

# Standard interactive execution
sudo python3 aad50_abeselom.py /dev/nvme0

# With full execution log and JSON audit report
sudo python3 aad50_abeselom.py /dev/nvme0 --log /var/log/aad50.log

# Non-interactive mode for automated server deprovisioning pipelines
sudo python3 aad50_abeselom.py /dev/nvme0 --log /var/log/aad50.log --force

# Simulate the full 50-cycle sequence without issuing any IOCTL commands
sudo python3 aad50_abeselom.py /dev/nvme0 --dry-run --verbose
```

### Windows Usage

```powershell
# List all detected NVMe drives
python aad50_abeselom_windows.py --list

# Standard interactive execution
python aad50_abeselom_windows.py \\.\PhysicalDrive0

# With full execution log and JSON audit report
python aad50_abeselom_windows.py \\.\PhysicalDrive0 --log C:\logs\aad50.log

# Non-interactive mode for automated deprovisioning pipelines
python aad50_abeselom_windows.py \\.\PhysicalDrive0 --log C:\logs\aad50.log --force

# Simulate the full 50-cycle sequence without issuing any commands
python aad50_abeselom_windows.py \\.\PhysicalDrive0 --dry-run --verbose
```

### Authorization

In interactive mode, both versions require the operator to type the following token exactly before any destructive command is issued:

```
EXECUTE-AAD-50-ABESELOM
```

### Key Implementation Features (v1.0)

- Mandatory **Log Page 0x81 polling** after every cycle — hardware-confirmed completion, not nominal
- Correct **B → C → A** phase ordering for maximum fault resilience
- Post-sanitization **LBA sample verification** read
- **SHA-256 tamper-evident audit report** for chain-of-custody compliance
- Non-interactive `--force` flag for automated deprovisioning pipelines
- `--dry-run` simulation mode for pre-deployment validation
- Windows `--list` flag to enumerate all detected NVMe drives

---

## Audit Report

Upon completion, the tool generates a structured JSON audit report containing every cycle record — timestamp, action code, duration, and completion status. A SHA-256 hash is computed over the key-sorted JSON serialisation of all 50 cycle records:

```
H_audit = SHA-256(JSON_sorted(CycleRecords_1..50))
```

This immutable hash provides downstream security auditors with tamper-evident proof that all 50 phases completed cleanly on the hardware, fulfilling chain-of-custody requirements for ISO/IEC 27040 and Common Criteria EAL4+ data destruction assurance.

---

## Peer Review

I am sharing the specification for The Abeselom ASIC-Direct 50 (AAD-50), a firmware-enforced data sanitization protocol for NVMe devices. The standard addresses physical data remanence vulnerabilities — including voltage hysteresis, over-provisioning zone exposure, and bad block retention — by bypassing operating system file abstractions to communicate directly with the on-drive ASIC via raw IOCTL administration commands. I would welcome peer review on the 50-cycle cryptographic, physical, and structural FTL reset matrix.

Specific areas where review is invited:

- Correctness of the `nvme_admin_cmd` struct memory layout for the Linux kernel IOCTL interface
- Log Page 0x81 SSTAT polling logic and timeout handling
- Phase ordering security rationale (B → C → A)
- Validity of the voltage hysteresis flattening argument for the 40-cycle Phase B allocation

Please open a GitHub Issue or contact directly at **yonas_abeselom@protonmail.com**.

---

## Whitepaper

The full technical whitepaper — formatted to IEEE double-column standard — is available in this repository:

📄 **[AAD50_Abeselom_Whitepaper.pdf](./AAD50_Abeselom_Whitepaper.pdf)**

---

## Compliance Alignment

| Standard | Relevance |
|---|---|
| NIST SP 800-88 Rev. 1 | Purge classification for solid-state media |
| NVMe Base Specification 2.0/2.1 | Sanitize command set (Opcode 0x84) |
| ISO/IEC 27040:2015 | Storage security and chain-of-custody |
| IEEE 2883-2022 | International standard for storage device sanitization |
| Common Criteria EAL4+ | Data destruction assurance |

---

## Warning

> **This tool causes PERMANENT, IRREVERSIBLE destruction of all data on the target device.** All partitions, filesystems, encryption keys, and hardware-level indices are destroyed. There is NO undo. Run only on devices you own and intend to fully erase.

---

## License

Copyright © 2026, Yonas Abeselom. All rights reserved.
Redistribution or modification requires written permission from the author.

---

## Contributing

Contributions and hardware testing reports are welcome. The highest priority areas are:

- **Windows Beta hardware testing** — if you run `aad50_abeselom_windows.py` on a real NVMe drive, please open a GitHub Issue with your drive model, Windows version, and whether the sequence completed successfully. Every test result directly contributes to validating the specification across manufacturers.
- **Linux driver compatibility** — reports of drives where Log Page 0x81 polling behaves unexpectedly are valuable for improving SSTAT handling.
- **Technical peer review** — open a GitHub Issue for any corrections or improvements to the protocol specification, struct layout, or phase ordering rationale.

Please open a GitHub Issue at `https://github.com/yonasabeselom/aad50/issues` or contact directly at **yonas_abeselom@protonmail.com**.

---

## Changelog

### v1.0 — June 2026
- Initial release — Linux reference implementation (Stable)
- Windows port (Beta) — `DeviceIoControl` / `IOCTL_STORAGE_PROTOCOL_COMMAND`
- IEEE double-column format technical whitepaper
- Step-by-step process infographic
- SHA-256 tamper-evident audit report
- Log Page 0x81 async polling — hardware-confirmed cycle completion

---

## Citation

If you reference AAD-50 in your own research or documentation, please cite as:

```
Y. Abeselom, "The Abeselom ASIC-Direct 50 (AAD-50): A Firmware-Enforced,
50-Cycle Sanitization Specification for NVMe Solid-State Storage Media,"
Version 1.0, June 2026. [Online]. Available: https://github.com/yonasabeselom
```
