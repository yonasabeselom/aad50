# REDACT — Anti-Forensic Sanitisation & Data Redaction Suite

**Version:** 1.0  
**Author:** Yonas Abeselom  
**Platform:** Windows 10/11 (Vista and later)  
**License:** See root repository LICENSE  
**Requires:** Python 3.8+ · Administrator privileges (auto-elevates via UAC)

> ⚠️ **CRITICAL DISTINCTION:** Disk space cleaners delete files to free up storage. REDACT cryptographically overwrites them to permanently destroy the data they contained. On solid-state media, these are fundamentally different operations.

---

## What Is REDACT?

REDACT is a forensic-grade Windows privacy cleaning and data redaction utility purpose-built for the modern NVMe/SSD era. Unlike standard disk cleaners that merely unlink file pointers, REDACT executes a strict **Destruction-Before-Deletion** protocol — binary-shredding, truncating, and purging 100 deep operating system artifacts, user tracking databases, and low-level filesystem journals using sanitization standards optimised for flash memory architecture.

REDACT is not a disk space cleaner. It is a **privacy and forensic trace elimination tool**. Disk space cleaners delete files to free storage. REDACT overwrites them to destroy the data they contained. On a modern NVMe SSD, those are fundamentally different operations.

---

## Who Is It For?

REDACT is engineered for environments requiring verifiable, immutable removal of digital footprints:

- **Incident Responders & SecOps** — purging engagement footprints and malware analysis remnants between volatile environment setups
- **Legal & Compliance Officers** — enforcing strict chain-of-custody data destruction mandates on case files post-engagement
- **ITAD (IT Asset Disposition) Technicians** — preparing enterprise Windows assets for secure multi-tenant re-deployment, resale, or cycle retirement
- **Operational Security (OPSEC) Specialists** — providing defence-in-depth sanitization for sensitive investigative workstation assets
- **Journalists and human rights workers** — operating in environments where forensic recovery of deleted files poses a personal safety risk
- **IT Administrators** — decommissioning or reassigning corporate workstations while ensuring historical employee telemetry is unrecoverable
- **Anyone preparing a system for handover** — who wants to ensure previous user data cannot be recovered

If you only want to free up disk space, any standard Windows disk cleanup utility will do. REDACT is for when the data must actually be gone.

---

## Why REDACT Is Different From Every Other Windows Cleaner

### 1. NVMe/SSD-Optimised Flash Sanitisation

Most Windows cleaning tools were designed in the era of spinning magnetic hard drives. Their overwrite patterns were engineered to defeat magnetic remanence on HDD platters.

**On an NVMe SSD, those patterns do almost nothing.**

The Flash Translation Layer (FTL) inside an NVMe drive intercepts host writes and redirects them to fresh physical blocks, leaving the original data in over-provisioned zones and wear-levelling pools that no standard overwrite command can reach. Legacy cleaning tools that claim to "securely wipe" files are, on modern SSDs, simply writing new data to new locations while the old data sits untouched.

REDACT bridges this FTL architectural gap:

1. **Direct Stream Scrambling** — files are opened in raw binary mode (`r+b`) and scrambled directly on the hardware sectors before pointer unlinking
2. **Forced Cache Synchronisation** — calls `os.fsync()` to force the hardware controller to permanently commit patterns to physical NAND cells immediately rather than sitting in volatile RAM caches
3. **Firmware Block Purge** — issues a hardware TRIM command (`Optimize-Volume -ReTrim`) to signal the SSD controller to aggressively clear and garbage-collect the deallocated sectors at the firmware level

### 2. Four-Mode Sanitisation Framework

| Sanitisation Standard | Passes | Execution Profile | Best Security Alignment |
|:---|:---:|:---|:---|
| **1-Pass Quick** | 1 | Cryptographically Secure Pseudo-Random Numbers (CSPRNG) | Optimised, high-speed cleaning on modern SSDs paired with immediate hardware TRIM |
| **NIST SP 800-88** | 3 | Government-aligned fixed pattern complement matrix sequence | Standard compliance audits for logical data clearance on storage blocks |
| **7-Pass DoD** | 7 | Alternating fixed hardware inversion blocks + random CSPRNG | High-assurance data remediation aligned with DoD 5220.22-M principles |
| **35-Pass Gutmann-NVMe** | 35 | NVMe-adapted Gutmann pattern matrix + 26 random block interleaves | Absolute physical cell saturation across reordered architectural passes |

None of these modes claims to be equivalent to a firmware-level NVMe Sanitize command — for that level of assurance (including over-provisioned zones and wear-levelling reserves), see **AAD-50**. REDACT addresses the OS-layer data that AAD-50 does not.

### 3. Three Sensitivity Tiers — Not a Binary On/Off

REDACT maps 100 deep-OS metadata target zones across three distinct cumulative sensitivity tiers:

| Tier | Items | What it covers | Risk |
|------|-------|---------------|------|
| 🟢 **LOW** | 25 | Temporary file loops, user temp space (`%TEMP%`), shader caches, diagnostic error logs — auto-rebuilt by Windows | Safe to always clean |
| 🟡 **MEDIUM** | 30 | Behavioural telemetry, address-bar histories, shell metadata caches, network profiles | Moderate — affects interface configuration if removed carelessly |
| 🔴 **HIGH** | 45 | Password vaults, browser SQL credentials, system snapshot backups, low-level OS tracking matrices, forensic logs | Irreversible — engineered for hardware transition and decommissioning |

You choose exactly what gets cleaned. REDACT never silently deletes anything.

### 4. Automatic Pre-Clean Registry Safeguards

Before touching a single file or registry key, REDACT forces an automated raw export of the entire `HKCU` and `HKLM` registry hives to a timestamped recovery folder (`REDACT_Recovery_Rollback_...`) on your Desktop. If anything goes wrong, you have a complete restore point. No other free Windows cleaner does this automatically before every run.

### 5. Verified Forensic Artifact Targets — What Other Cleaners Miss

Standard cleaning tools miss low-level telemetry caches intentionally preserved by the Windows kernel. REDACT systematically hunts down and destroys:

- **ShellBags** — registry entries tracking folder names, sizes, and layout paths for every directory ever accessed, including detached external USB drives
- **Kernel Execution Records** — permanent internal execution timelines hidden inside BAM (Background Activity Monitor), UserAssist, AmCache, and Shimcache (AppCompatCache) hives
- **SRUM Database** — the System Resource Usage Monitor (`SRUDB.dat`), which invisibly records historical per-application CPU cycles, data transmission, and battery metrics
- **Filesystem Journals** — complete purging of the NTFS Change Journal (`$UsnJrnl`) and best-effort overwrites of the NTFS transaction tracking `$LogFile`
- **Windows Search index traces** and query history
- **Cortana conversation logs** and device usage data
- **Windows Timeline and Activity History**
- **Jump lists and recent document lists**
- **Saved RDP credentials** and connection history
- **Windows Credential Manager** entries (saved passwords and tokens)
- **Windows Hello biometric data**
- **Hibernation file** (`hiberfil.sys`) — which contains a full memory image that can include encryption keys, open documents, and active sessions
- **Windows Error Reporting crash dumps** — which can contain memory snapshots of running processes
- **DNS cache** — which records every domain your system has resolved

### 6. Chain-of-Custody Cleaning Report

Every REDACT session produces a full cleaning report saved to your Desktop — listing every item cleaned, every file wiped, every registry key deleted, the wipe standard used, and a summary of total data removed. This is the kind of documentation that compliance and legal contexts require.

---

## How REDACT Compares to Other Windows Cleaners

| Feature | CCleaner | BleachBit | Eraser | Blancco | **REDACT** |
|---------|----------|-----------|--------|---------|------------|
| NVMe/SSD-optimised architecture | ✗ | ✗ | ✗ | Partial | ✅ |
| TRIM issued after cleaning | ✗ | ✗ | ✗ | Partial | ✅ |
| NIST SP 800-88 wipe standard | ✗ | ✗ | ✗ | ✅ | ✅ |
| DoD 5220.22-M wipe mode | ✗ | ✅ | ✅ | ✅ | ✅ |
| Gutmann-NVMe adapted wipe | ✗ | Legacy HDD only | Legacy HDD only | ✗ | ✅ |
| Automatic registry backup | ✗ | ✗ | ✗ | ✗ | ✅ |
| Rollback recovery folder | ✗ | ✗ | ✗ | ✗ | ✅ |
| ShellBag cleaning | ✗ | ✗ | ✗ | ✗ | ✅ |
| SRUM database cleaning | ✗ | ✗ | ✗ | ✗ | ✅ |
| BAM / AmCache / Shimcache | ✗ | ✗ | ✗ | ✗ | ✅ |
| NTFS journal purge | ✗ | ✗ | ✗ | ✗ | ✅ |
| Compliance-grade cleaning report | ✗ | ✗ | ✗ | ✅ | ✅ |
| 3-tier sensitivity model | ✗ | ✗ | ✗ | Partial | ✅ |
| Free and open source | Freemium | ✅ | ✅ | ✗ (enterprise pricing) | ✅ |
| Windows 11 Fluent UI | ✗ | ✗ | ✗ | ✗ | ✅ |

**Where REDACT sits in the market:**

- **vs CCleaner / Glary Utilities / Privacy Eraser** — consumer-grade tools built for HDD-era deletion. No TRIM, no forensic artifact targeting, no compliance documentation, no registry safety backup. REDACT goes significantly deeper.
- **vs BleachBit** — strong open-source cleaner with DoD/Gutmann modes, but those modes are HDD-adapted legacy patterns. No NVMe awareness, no TRIM, no ShellBag/SRUM/BAM targeting, no registry backup.
- **vs Eraser** — focused on file-level secure deletion with good wipe standards, but no system-wide forensic artifact cleaning, no TRIM, no registry backup, no compliance report.
- **vs Blancco** — the industry-standard enterprise solution. Powerful, certified, expensive, and closed-source. REDACT is the free, open-source alternative for the forensic trace elimination use case — not a full enterprise drive erasure replacement (that is AAD-50's domain).

**REDACT's unique position:** The only free, open-source Windows cleaner that is explicitly NVMe/SSD-aware, NIST SP 800-88 aligned, targets deep forensic kernel artifacts (ShellBags, SRUM, BAM, NTFS journals), and produces compliance-grade documentation — with an automatic registry safety backup before every run.

---

## REDACT + AAD-50: Full-Stack Remediation

| Layer | Tool | What it addresses |
|-------|------|------------------|
| **OS layer** | REDACT | Files, caches, registry traces, browser history, credentials, forensic artefacts |
| **Firmware layer** | AAD-50 | All NAND cells including over-provisioned zones, FTL mapping tables, cryptographic keys |

REDACT handles the logical data tier. **AAD-50** addresses the raw physical hardware blocks. Combined, they form a complete end-to-end device decommissioning pipeline.

For complete data destruction before drive retirement:
1. Run REDACT to eliminate OS-layer traces (HIGH sensitivity recommended)
2. Run AAD-50 to execute firmware-level 50-cycle B→C→A sanitization with Log Page 0x81 verification

Together they cover the full stack — from the Windows registry down to the raw NAND cells.

---

## Usage

```bash
python REDACT.py
```

REDACT auto-elevates to administrator via Windows UAC if not already running as admin. The GUI opens with all 100 items listed across their sensitivity tiers. Select your items, choose a wipe mode, and click **INITIALIZE PIPELINE CLEAN**.

A registry backup is created on your Desktop automatically before cleaning begins. A cleaning report is saved to your Desktop when cleaning completes.

---

## Requirements

- Windows 10/11 (Vista and later supported)
- Python 3.8+
- `tkinter` (included with standard Python on Windows)
- Administrator privileges (handled automatically via UAC)

---

*REDACT is a companion tool to AAD-50. For firmware-level NVMe sanitization, see the root repository.*  
*Author: Yonas Abeselom · yonas_abeselom@protonmail.com · github.com/yonasabeselom/aad50*
