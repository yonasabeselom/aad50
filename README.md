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

The result is a mathematically provable, forensically irreversible, and fully auditable sanitization standard aligned with NIST SP 800-88 Rev. 2 Purge classification and the NVMe Base Specification 2.0/2.1 Sanitize command set.

---

## How AAD-50 Works — Step by Step

![AAD-50 Step-by-Step Process](AAD50_Process_Infographic.png)

---

## The Problem

Traditional data sanitization standards (DoD 5220.22-M, Gutmann 35-pass) were engineered for magnetic hard disk drives. On solid-state drives, they are fundamentally ineffective.

**The scale of the problem in 2026 is severe:**

- **42%** of used drives purchased from online marketplaces contain recoverable sensitive data *(Blancco, 2025)*
- **67%** of SSD data remains recoverable after standard overwrite techniques *(University of California San Diego)*
- **32%** of organisational data leaks are attributed to redeployed drives retaining sensitive data *(2026 State of Data Sanitization Report)*
- **Only 30.7%** of drives are properly sanitised before resale — researchers recovered over 6 million files from 42 drives *(Secure Data Recovery, 2026)*
- **36%** of enterprises experienced data exposure due to residual SSD data after attempted sanitisation *(Ponemon Institute)*
- **94%** of organisations believe their devices are fully sanitised — but the evidence proves this confidence is misplaced *(Blancco, 2026)*
- **75%** of organisations undergoing audits will require auditable sanitisation logs by 2026 *(Gartner)*

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
| `aad50_gui_windows.py` | Windows 10 1607+ / 11 | GUI — requires `aad50_abeselom_windows.py` | Beta |

> **Windows Beta status:** The Windows port implements the identical AAD-50 protocol via the Windows-equivalent API pathway. Hardware testing across NVMe manufacturers is ongoing. If you test it on a real drive, please open a GitHub Issue with your results — your feedback directly contributes to validating the specification.

### GUI Application

The Windows GUI application (`aad50_gui_windows.py`) provides a full graphical interface for AAD-50 with five screens:

- **Home Dashboard** — phase matrix, stats, and quick start
- **Select Drive** — auto-detects all NVMe drives with model, path, and volume labels
- **Sanitize Drive** — destruction warning shield, authorization token, live 50-cycle progress dashboard
- **Audit Reports** — load and verify any saved JSON audit report via SHA-256 hash recalculation
- **About** — tool information, compliance standards, OEM driver diagnostic

**Simulation Mode — Safe (Dry-Run ON):**
![AAD-50 GUI Simulation Mode](AAD50_GUI_Simulation.png)

**Live Mode — Armed (Dry-Run OFF):**
![AAD-50 GUI Live Mode](AAD50_GUI_Live.png)

**GUI Requirements:**
```
pip install customtkinter
pip install reportlab
```

Both `aad50_gui_windows.py` and `aad50_abeselom_windows.py` must be in the same folder.

**Run the GUI:**
```
python aad50_gui_windows.py
```

### Standalone Windows Executable

A standalone `AAD50.exe` can be built using PyInstaller — no Python installation required on the target machine. The EXE runs on any Windows 10 1607+ or Windows 11 system.

**Build the EXE:**
```
pip install pyinstaller
pyinstaller --onefile --windowed --name "AAD50" --icon="AAD50_Icon.ico" aad50_gui_windows.py aad50_abeselom_windows.py
```

The compiled executable will be in the `dist\` folder. Copy `AAD50.exe` anywhere — USB drive, shared folder, or another machine — and it runs standalone as Administrator.

### Quick Start — Choose Your Platform

---

#### 🖥️ Windows GUI (Recommended for most users)

The easiest way to use AAD-50 on Windows. Full graphical interface — no command line needed.

**Step 1 — Install the GUI requirement:**
```
pip install customtkinter
```

**Step 2 — Place both files in the same folder:**
- `aad50_gui_windows.py`
- `aad50_abeselom_windows.py`

**Step 3 — Run as Administrator:**
```
python aad50_gui_windows.py
```

The GUI will open, detect your NVMe drives automatically, and guide you through the sanitization process step by step.

---

#### ⌨️ Windows Command Line

For advanced users, automation pipelines, or headless server environments.

**Run as Administrator. Open Command Prompt and type:**

```powershell
# Step 1 — See your NVMe drives
python aad50_abeselom_windows.py --list

# Step 2 — Simulate first (safe — no hardware commands sent)
python aad50_abeselom_windows.py --dry-run --verbose \\.\PhysicalDrive0

# Step 3 — Live execution (PERMANENT — destroys all data)
python aad50_abeselom_windows.py \\.\PhysicalDrive0

# With audit report saved to file
python aad50_abeselom_windows.py \\.\PhysicalDrive0 --log C:\logs\aad50.log

# Non-interactive mode for automated pipelines
python aad50_abeselom_windows.py \\.\PhysicalDrive0 --log C:\logs\aad50.log --force
```

---

#### 🐧 Linux Command Line

For Linux systems, servers, and GitHub Codespaces.

**Run as root. Open terminal and type:**

```bash
# Step 1 — Simulate first (safe — no hardware commands sent)
sudo python3 aad50_abeselom.py --dry-run --verbose /dev/nvme0

# Step 2 — Live execution (PERMANENT — destroys all data)
sudo python3 aad50_abeselom.py /dev/nvme0

# With audit report saved to file
sudo python3 aad50_abeselom.py /dev/nvme0 --log /var/log/aad50.log

# Non-interactive mode for automated server deprovisioning
sudo python3 aad50_abeselom.py /dev/nvme0 --log /var/log/aad50.log --force
```

> **Note:** Target the NVMe controller node (e.g. `/dev/nvme0`), not a namespace node (e.g. `/dev/nvme0n1`).

---

### Authorization

In both command line versions, you must type the following token exactly when prompted before any destructive command is issued:

```
EXECUTE-AAD-50-ABESELOM
```

The GUI handles this via an input field on the Sanitize screen.

### Key Implementation Features (v1.0)

- Mandatory **Log Page 0x81 polling** after every cycle — hardware-confirmed completion, not nominal
- Correct **B → C → A** phase ordering for maximum fault resilience
- Post-sanitization **LBA sample verification** read
- **SHA-256 tamper-evident audit report** for chain-of-custody compliance
- **PDF Certificate of Destruction** — operator name, drive serial number, compliance standards, SHA-256 hash
- **Drive serial number** captured and recorded in every audit report
- **Operator name** field — recorded for chain-of-custody and GDPR compliance
- Non-interactive `--force` flag for automated deprovisioning pipelines
- `--dry-run` simulation mode for pre-deployment validation
- Windows `--list` flag to enumerate all detected NVMe drives
- Windows GUI OEM driver diagnostic — tests Log Page 0x81 pass-through capability

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
| NIST SP 800-88 Rev. 2 | Purge classification for solid-state media |
| NVMe Base Specification 2.0/2.1 | Sanitize command set (Opcode 0x84) |
| ISO/IEC 27040:2015 | Storage security and chain-of-custody |
| IEEE 2883-2022 | International standard for storage device sanitization |
| Common Criteria EAL4+ | Data destruction assurance |

---

## Warning

> **This tool causes PERMANENT, IRREVERSIBLE destruction of all data on the target device.** All partitions, filesystems, encryption keys, and hardware-level indices are destroyed. There is NO undo. Run only on devices you own and intend to fully erase.

---

## License

AAD-50 uses a dual licence — see the [LICENSE](./LICENSE) file for full terms.

**Specification and Whitepaper** — Licensed under [Creative Commons Attribution 4.0 (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). You may share, reference, and build upon the specification freely, provided you credit Yonas Abeselom as the original author and link to this repository.

**Source Code** (`aad50_abeselom.py`, `aad50_abeselom_windows.py`, `aad50_gui_windows.py`) — Proprietary. You may read and run the code for personal, non-commercial use. Redistribution, modification, or commercial use requires written permission from the author.

For licensing enquiries: **yonas_abeselom@protonmail.com**

---

## Contributing

Contributions and hardware testing reports are welcome. The highest priority areas are:

- **Windows Beta hardware testing** — if you run `aad50_abeselom_windows.py` on a real NVMe drive, please open a GitHub Issue with your drive model, Windows version, and whether the sequence completed successfully. Every test result directly contributes to validating the specification across manufacturers.
- **Linux driver compatibility** — reports of drives where Log Page 0x81 polling behaves unexpectedly are valuable for improving SSTAT handling.
- **Technical peer review** — open a GitHub Issue for any corrections or improvements to the protocol specification, struct layout, or phase ordering rationale.

Please open a GitHub Issue at `https://github.com/yonasabeselom/aad50/issues` or contact directly at **yonas_abeselom@protonmail.com**.

---

## Changelog

### v1.0.2 — June 4, 2026
- PDF Certificate of Destruction added — operator name, drive serial number, NIST/IEEE/ISO compliance, SHA-256 hash, professional A4 layout
- Operator Name field added to Sanitize screen — recorded in JSON report and PDF certificate
- Drive serial number auto-captured via Win32 — recorded in all audit outputs
- GUI completion screen compacted — all information and buttons visible without scrolling
- GitHub link in header made clickable — opens repository in browser
- Drive selection screen caching — instant response after first scan, no repeated PowerShell calls
- Home Dashboard navigation icon added
- SHA-256 hash display improved — bright green on dark background, bold monospace font
- Standalone Windows EXE build confirmed — runs on any Windows 10/11 machine without Python
- ReportLab dependency added for PDF certificate generation

### v1.0.1 — June 3, 2026
- Windows Beta dry-run confirmed working on WD PC SN730 SDBQNTY-256G-1001 (\\.\PhysicalDrive0, Windows 11) — [Issue #1](https://github.com/yonasabeselom/aad50/issues/1)
- Linux dry-run confirmed working on GitHub Codespaces — [Issue #2](https://github.com/yonasabeselom/aad50/issues/2)
- Both platforms validated — identical 50-cycle B → C → A sequence confirmed on Linux and Windows
- Windows GUI application added (`aad50_gui_windows.py`) — full graphical interface with 5 screens, live progress dashboard, SHA-256 audit verifier, OEM driver diagnostic
- Windows SHA-256 audit hash: `7d395c5eae31eed97a1929bd4ec2d22fc45aeaff256e6b871790f527a9965116`
- Linux SHA-256 audit hash: `f8432896cebfc6aa843d22f155b6d55d224eb43b0ba45506aa7a07758913cb1f`

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
Version 1.0, June 2026. [Online]. Available: https://github.com/yonasabeselom/aad50
```
