# ╔══════════════════════════════════════════════════════════════════╗
# ║  REDACT  —  v1.0                                                 ║
# ║  Anti-Forensic Sanitisation & Data Redaction Suite               ║
# ╚══════════════════════════════════════════════════════════════════╝

REDACT is a forensic-grade Windows privacy cleaning and data redaction utility purpose-built for the modern NVMe/SSD era. Unlike standard disk cleaners that merely unlink file pointers, REDACT executes a strict **Destruction-Before-Deletion** protocol—binary-shredding, truncating, and purging deep operating system artifacts, user tracking databases, and low-level filesystem journals using sanitization standards optimized for flash memory architecture.

> ⚠️ **CRITICAL DISTINCTION:** Disk space cleaners delete files to free up storage. REDACT cryptographically overwrites them to permanently destroy the data they contained. On solid-state media, these are fundamentally different operations.

---

## 👥 Targeted Target Audience

REDACT is engineered for environments requiring verifiable, immutable removal of digital footprints:
*   **Incident Responders & SecOps:** Purging engagement footprints and malware analysis remnants between volatile environment setups.
*   **Legal & Compliance Officers:** Enforcing strict chain-of-custody data destruction mandates on case files post-engagement.
*   **ITAD (IT Asset Disposition) Technicians:** Preparing enterprise Windows assets for secure multi-tenant re-deployment, resale, or cycle retirement.
*   **Operational Security (OPSEC) Specialists:** Providing defense-in-depth sanitization for sensitive investigative workstation assets.
*   **IT Administrators:** Decommissioning or reassigning corporate workstations while ensuring historical employee telemetry is unrecoverable.

---

## ⚡ Technical Differentiation: Why REDACT is Different

### 1. NVMe/SSD-Optimised Flash Sanitisation
Legacy wiping tools were built for spinning magnetic hard disks (HDDs). On a modern SSD, standard overwrite patterns are intercepted by the **Flash Translation Layer (FTL)**, which transparently maps logical block addresses to shifting physical NAND cells for wear-leveling. Legacy cleaners simply write new data to new spaces, leaving the original data fully intact in over-provisioned blocks.

REDACT bridges this FTL architectural gap:
1.  **Direct Stream Scrambling:** Files are opened in raw binary mode (`r+b`) and scrambled directly on the hardware sectors before pointer unlinking.
2.  **Forced Cache Synchronization:** Calls `os.fsync()` to force the hardware controller to permanently commit patterns to physical NAND cells immediately rather than sitting in volatile RAM caches.
3.  **Firmware Block Purge:** Instantly issues a hardware **TRIM command** (`Optimize-Volume -ReTrim`) to signal the SSD controller to aggressively clear and garbage-collect the deallocated sectors at the firmware level.

### 2. Multi-Pass Sanitisation Framework

| Sanitisation Standard | Passes | Execution Profile | Best Security Alignment |
| :--- | :---: | :--- | :--- |
| **1-PASS QUICK** | 1 | Cryptographically Secure Pseudo-Random Numbers (`CSPRNG`) | Optimized, high-speed cleaning on modern SSDs paired with immediate hardware TRIM. |
| **NIST 800-88** | 3 | Government-aligned Fixed Pattern Complement Matrix Sequence | Standard compliance audits for logical data clearance on storage blocks. |
| **7-PASS SECURE** | 7 | Alternating fixed hardware inversion blocks + random CSPRNG | High-assurance data remediation aligned with legacy DoD 5220.22-M properties. |
| **35-PASS MAXIMUM** | 35 | NVMe-adapted Gutmann pattern matrix + 26 random block interleaves | Absolute physical cell saturation across reordered architectural passes. |

### 3. Granular Cumulative Sensitivity Tiers
Rather than utilizing opaque "one-click" presets that risk breaking user workflows, REDACT maps 100 deep-OS metadata target zones across three distinct cumulative sensitivity tiers:

*   🟢 **LOW SEVERITY (25 Items):** Temporary file loops, user temp space (`%TEMP%`), shader caches, and diagnostic error logs. Clean-safe; automatically rebuilt by Windows without configuration loss.
*   🟡 **MEDIUM SEVERITY (30 Items):** Behavioral telemetry, address-bar histories, VS Code storage indexes, shell metadata caches, and standard network profiles. Affects interface configurations.
*   🔴 **HIGH SEVERITY (45 Items):** Password vaults, browser SQL credentials, system snapshot backups, low-level OS tracking matrices, and forensic logs. **Irreversible;** engineered for hardware transition and decommissioning.

### 4. Automatic Pre-Clean Registry Safeguards
To guarantee system stability, REDACT forces an automated raw export of the entire `HKCU` and `HKLM` registry hives to a timestamped recovery block (`REDACT_Recovery_Rollback_...`) on your Desktop prior to executing a single delete or key modification.

### 5. Verified Forensic Artifact Targets (What Other Cleaners Miss)
Standard cleaning tools miss low-level telemetry caches intentionally preserved by the Windows kernel. REDACT systematically hunts down and destroys:
*   **ShellBags:** Registry entries tracking folder names, sizes, and layout paths for *every directory ever accessed*—including detached external USB drives.
*   **Kernel Execution Records:** Permanent internal execution timelines hidden inside **BAM (Background Activity Monitor)**, **UserAssist**, **AmCache**, and **Shimcache (AppCompatCache)** hives.
*   **The SRUM Database:** The System Resource Usage Monitor (`SRUDB.dat`), which invisibly records historical per-application CPU cycles, data transmission, and battery metrics.
*   **Filesystem Journals:** Complete purging of the **NTFS Change Journal (`$UsnJrnl`)** and raw best-effort overwrites of the NTFS transaction tracking `$LogFile`.

---

## 🛠️ REDACT + AAD-50: Full-Stack Remediation

REDACT handles the logical data tier, whereas **AAD-50** addresses the raw physical hardware blocks. Combined, they form a complete end-to-end device decommissioning pipeline.
