# REDACT — Windows Privacy Cleaner

**Version:** 5.0  
**Author:** Yonas Abeselom  
**Platform:** Windows (Vista and later)  
**License:** See root repository LICENSE  
**Requires:** Python 3.8+ · Administrator privileges (auto-elevates via UAC)

---

## What Is REDACT?

REDACT is a Windows privacy cleaning and data redaction utility designed specifically for the modern NVMe/SSD era. It identifies and securely wipes 65 categories of privacy-sensitive data across the Windows operating system — from temporary files and browser caches to forensic traces, credential stores, and registry artefacts — using wipe standards engineered for flash-based storage rather than legacy magnetic hard disks.

REDACT is not a disk space cleaner. It is a **privacy and forensic trace elimination tool**. The distinction matters: disk space cleaners delete files to free storage. REDACT overwrites them to destroy the data they contained. On a modern NVMe SSD, those are fundamentally different operations.

---

## Who Is It For?

REDACT is designed for anyone who needs verifiable, thorough removal of digital traces on Windows — not just casual tidying:

- **Security researchers and penetration testers** who need a clean working environment between engagements
- **Legal and compliance professionals** handling sensitive case materials that must be destroyed after use
- **ITAD (IT Asset Disposition) technicians** preparing Windows systems for re-deployment or resale
- **Journalists and human rights workers** operating in environments where forensic recovery of deleted files poses a personal safety risk
- **Privacy-conscious individuals** who want genuine data destruction rather than the illusion of it
- **IT administrators** decommissioning or reassigning Windows workstations
- **Anyone preparing a system for handover** who wants to ensure previous user data cannot be recovered

If you only want to free up disk space, any standard Windows disk cleanup utility will do. REDACT is for when the data must actually be gone.

---

## Why REDACT Is Different From Every Other Windows Cleaner

### 1. NVMe/SSD-Optimised Wipe Architecture

Most Windows cleaning tools were designed in the era of spinning magnetic hard drives. Their overwrite patterns — alternating zeros, ones, and random bytes — were engineered to defeat magnetic remanence on HDD platters.

**On an NVMe SSD, those patterns do almost nothing.**

The Flash Translation Layer (FTL) inside an NVMe drive intercepts host writes and redirects them to fresh physical blocks, leaving the original data in over-provisioned zones and wear-levelling pools that no standard overwrite command can reach. Legacy cleaning tools that claim to "securely wipe" files are, on modern SSDs, simply writing new data to new locations while the old data sits untouched.

REDACT addresses this with three wipe modes specifically chosen for flash-based storage:

| Mode | Passes | Mechanism | Best For |
|------|--------|-----------|----------|
| Single-pass NVMe | 1 | Cryptographically random | Fast, everyday use on NVMe |
| 7-pass DoD | 7 | Alternating patterns + random | High-assurance, DoD-aligned contexts |
| 35-pass Gutmann-NVMe | 35 | NVMe-adapted Gutmann pattern matrix | Maximum overwrite depth |

After every cleaning run, REDACT issues a **TRIM command** (`Optimize-Volume -ReTrim`) to the C: drive, signalling the NVMe controller to physically erase the deallocated blocks at the firmware level — closing the FTL gap that standard file deletion leaves open.

### 2. Three Sensitivity Tiers — Not a Binary On/Off

Most cleaners present a flat list of things to delete. REDACT organises all 65 cleanup items into three sensitivity tiers with explicit descriptions of what each item is and what deleting it means:

| Tier | What it covers | Risk level |
|------|---------------|------------|
| **LOW** | Temp files, caches, logs — auto-rebuilt, no personal data | Safe to always clean |
| **MEDIUM** | Browser history, search queries, recently opened files, clipboard — behavioural traces | Moderate — affects usability if removed carelessly |
| **HIGH** | Saved passwords, credential stores, download history, hibernation file, Windows Hello biometrics, forensic artefacts | Irreversible — intended for decommissioning and privacy-critical contexts |

You choose exactly what gets cleaned. REDACT never silently deletes anything.

### 3. Registry Backup Before Any Cleaning

Before touching a single file or registry key, REDACT exports a full backup of both `HKCU` and `HKLM` registry hives to a timestamped folder on your Desktop. If anything goes wrong, you have a complete restore point.

No other free Windows cleaner does this automatically before every run.

### 4. A Cleaning Report for Every Run

Every REDACT session produces a full cleaning report saved to your Desktop — listing every item cleaned, every file wiped, every registry key deleted, the wipe standard used, and a summary of total data removed. This is the kind of chain-of-custody documentation that compliance and legal contexts require.

### 5. 65 Items — Including What Other Cleaners Miss

Standard cleaners handle the obvious items: temp folders, browser cache, Recycle Bin. REDACT also covers:

- Windows Search index traces and query history
- Cortana conversation logs and device usage data
- Windows Timeline and Activity History
- Jump lists and recent document lists
- Shellbag entries (which record which folders you opened, even after files are deleted)
- LNK (shortcut) files that record recently accessed documents
- Saved RDP (Remote Desktop) credentials and connection history
- Windows Credential Manager entries (saved passwords and tokens)
- Windows Hello biometric data
- Hibernation file (`hiberfil.sys`) — which contains a full memory image that can include encryption keys, open documents, and active sessions
- Windows Error Reporting crash dumps — which can contain memory snapshots of running processes
- DNS cache — which records every domain your system has resolved
- SRUM (System Resource Usage Monitor) database — a detailed log of application usage, network activity, and energy use maintained silently by Windows

---

## The NVMe Standard Difference

Legacy disk cleaning tools typically offer Gutmann 35-pass as their "maximum security" option. Peter Gutmann himself has noted that this method was designed for specific magnetic encoding formats from the mid-1990s and is largely irrelevant to modern storage.

REDACT's three wipe modes are designed around what actually matters on NVMe SSDs:

**Single-pass random** — A single pass of cryptographically random data (`secrets.token_bytes`) is sufficient to defeat software-level file carving on NVMe drives where TRIM has been issued. This is the fastest mode and appropriate for everyday cleaning on modern hardware.

**7-pass DoD** — Implements the overwrite sequence aligned with DoD 5220.22-M principles, adapted for flash storage: alternating fixed patterns interspersed with random passes, ensuring no predictable residue pattern remains in the physical cells reached by the write.

**35-pass Gutmann-NVMe** — An NVMe-adapted version of the Gutmann pattern matrix: the original fixed-pattern passes re-ordered and supplemented with 26 random passes, reflecting current understanding of what actually provides overwrite depth on flash memory. This is paired with TRIM issuance to close the FTL gap.

None of these modes claims to be equivalent to a firmware-level NVMe Sanitize command — for that level of assurance (including over-provisioned zones and wear-levelling reserves), see **AAD-50**. REDACT addresses the OS-layer data that AAD-50 does not: the files, caches, registry traces, and behavioural logs that Windows creates and maintains above the firmware level.

---

## REDACT + AAD-50: The Complete Picture

| Layer | Tool | What it addresses |
|-------|------|------------------|
| **OS layer** | REDACT | Files, caches, registry traces, browser history, credentials, forensic artefacts |
| **Firmware layer** | AAD-50 | All NAND cells including over-provisioned zones, FTL mapping tables, cryptographic keys |

For complete data destruction before drive retirement:
1. Run REDACT to eliminate OS-layer traces (HIGH sensitivity recommended)
2. Run AAD-50 to execute firmware-level 50-cycle B→C→A sanitization with Log Page 0x81 verification

Together they cover the full stack — from the Windows registry down to the raw NAND cells.

---

## Usage

```
python REDACT.py
```

REDACT will auto-elevate to administrator via Windows UAC if not already running as admin. The GUI will open. Select your items, choose a wipe mode, and click REDACT NOW.

A registry backup is created on your Desktop automatically before cleaning begins. A cleaning report is saved to your Desktop when cleaning completes.

---

## Requirements

- Windows Vista or later (Windows 10/11 recommended)
- Python 3.8+
- `tkinter` (included with standard Python on Windows)
- Administrator privileges (handled automatically via UAC)

---

*REDACT is a companion tool to AAD-50. For firmware-level NVMe sanitization, see the root repository.*  
*Author: Yonas Abeselom · yonas_abeselom@protonmail.com · https://github.com/yonasabeselom/aad50*
