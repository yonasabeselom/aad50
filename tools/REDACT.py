# ╔══════════════════════════════════════════════════════════════════╗
# ║     WINDOWS PRIVACY CLEANER  —  v5.0                            ║
# ║     65 items · 3 tiers · Vista-style Matte Black UI             ║
# ║     NVMe/SSD optimised · 1 / 7 / 35-pass wipe                  ║
# ╚══════════════════════════════════════════════════════════════════╝

import sys, os, ctypes, subprocess, shutil, glob, threading, secrets
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont
from datetime import datetime

# ─── Auto-elevate ─────────────────────────────────────────────────────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if not is_admin():
    script = os.path.abspath(sys.argv[0])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}"', None, 1)
    sys.exit(0)

import winreg

# ─── Wipe Engine ──────────────────────────────────────────────────────────────
WIPE_MODE_KEY = "single"

# ── Global stats counters (reset each clean run) ──────────────────────────────
class Stats:
    def reset(self):
        self.files      = 0   # files wiped
        self.bytes      = 0   # bytes wiped (pre-deletion size)
        self.reg_keys   = 0   # registry keys deleted
        self.skipped    = 0   # locked / not found
    def __init__(self): self.reset()

STATS = Stats()

def _fmt_size(b):
    """Return human-readable size string."""
    if b < 1024:            return f"{b} B"
    if b < 1024**2:         return f"{b/1024:.1f} KB"
    if b < 1024**3:         return f"{b/1024**2:.2f} MB"
    return                         f"{b/1024**3:.3f} GB"

def _nvme_passes(size):
    p = []
    p.append(b"\x00" * size)
    p.append(b"\xFF" * size)
    p.append(b"\xAA" * size)
    p.append(b"\x55" * size)
    p.append((b"\xAA\x55" * (size // 2 + 1))[:size])
    p.append((b"\x55\xAA" * (size // 2 + 1))[:size])
    p.append((b"\x92\x49\x24" * (size // 3 + 1))[:size])
    p.append((b"\x49\x24\x92" * (size // 3 + 1))[:size])
    p.append((b"\x24\x92\x49" * (size // 3 + 1))[:size])
    for _ in range(26):
        p.append(secrets.token_bytes(size))
    return p

def _dod7_passes(size):
    return [b"\x00"*size, b"\xFF"*size, secrets.token_bytes(size),
            b"\xAA"*size, secrets.token_bytes(size), b"\x00"*size,
            secrets.token_bytes(size)]

def _single_pass(size):
    return [secrets.token_bytes(size)]

def _wipe_file(path):
    try:
        size = os.path.getsize(path)
        file_bytes = size  # capture before deletion
        if size == 0:
            os.remove(path)
            STATS.files += 1
            return f"  Wiped (empty): {path}"
        passes = {"single":_single_pass,"secure":_dod7_passes,"gutmann":_nvme_passes}[WIPE_MODE_KEY](size)
        tags   = {"single":"1-pass NVMe","secure":"7-pass NVMe","gutmann":"35-pass Gutmann"}
        with open(path, "r+b") as fh:
            for data in passes:
                fh.seek(0); fh.write(data); fh.flush(); os.fsync(fh.fileno())
            fh.seek(0); fh.truncate(0); fh.flush(); os.fsync(fh.fileno())
        os.remove(path)
        STATS.files += 1
        STATS.bytes += file_bytes
        return f"  [{tags[WIPE_MODE_KEY]}] {_fmt_size(file_bytes)}  {path}"
    except PermissionError:
        STATS.skipped += 1
        return f"  LOCKED (in use): {path}"
    except Exception as e:
        try:
            os.remove(path)
            STATS.files += 1
            return f"  Deleted (fallback): {path}"
        except:
            STATS.skipped += 1
            return f"  FAILED: {path} — {e}"

def _wipe(*patterns):
    results = []
    for pat in patterns:
        matches = glob.glob(os.path.expandvars(pat), recursive=True)
        if not matches:
            results.append(f"  Nothing found: {pat}"); continue
        for item in matches:
            if os.path.isfile(item):
                results.append(_wipe_file(item))
            elif os.path.isdir(item):
                for root, dirs, files in os.walk(item, topdown=False):
                    for f in files: results.append(_wipe_file(os.path.join(root, f)))
                    for d in dirs:
                        try: os.rmdir(os.path.join(root, d))
                        except: pass
                try: os.rmdir(item)
                except: shutil.rmtree(item, ignore_errors=True)
    results.append(_run('PowerShell -Command "Optimize-Volume -DriveLetter C -ReTrim -Confirm:$false 2>$null"', "TRIM issued"))
    return results

def _clean(*patterns): return _wipe(*patterns)

def _reg(hive_str, path):
    try:
        h = winreg.HKEY_CURRENT_USER if hive_str=="HKCU" else winreg.HKEY_LOCAL_MACHINE
        winreg.DeleteKeyEx(h, path)
        STATS.reg_keys += 1
        return f"  Deleted: {hive_str}\\{path}"
    except FileNotFoundError:
        return f"  Already clean: {hive_str}\\{path}"
    except Exception:
        r = subprocess.run(f'reg delete "{hive_str}\\{path}" /f', shell=True, capture_output=True)
        if r.returncode == 0:
            STATS.reg_keys += 1
            return f"  Deleted: {hive_str}\\{path}"
        return f"  Skip: {hive_str}\\{path}"

def _run(cmd, label=""):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return f"  {'OK' if r.returncode==0 else 'Ran'}: {label or cmd}"
    except Exception as e:
        return f"  Failed: {label or cmd} ({e})"

# ─── 65 Items in 3 tiers ──────────────────────────────────────────────────────
ALL_ITEMS = [

    # ══════════════════════════════════════════════════════════
    #  LOW  SENSITIVITY  —  20 items
    # ══════════════════════════════════════════════════════════
    ("LOW","temp_win","Windows Temp Files",
     "Cached junk in C:\\Windows\\Temp",
     lambda: _clean(r"C:\Windows\Temp\*")),

    ("LOW","temp_user","User Temp Folder (%TEMP%)",
     "Personal temp folder — app leftovers",
     lambda: _clean(r"%TEMP%\*")),

    ("LOW","recycle_bin","Recycle Bin",
     "Files waiting in Recycle Bin",
     lambda: [_run('PowerShell -Command "Clear-RecycleBin -Force -EA SilentlyContinue"',"Empty Recycle Bin")]),

    ("LOW","thumbnail_cache","Thumbnail Cache",
     "Explorer image previews — auto-rebuilt",
     lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db")),

    ("LOW","icon_cache","Icon Cache Database",
     "Cached app icons — regenerated on reboot",
     lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_*.db")),

    ("LOW","wer_reports","Windows Error Reports",
     "Crash dumps and queued error reports",
     lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue\*",
                    r"%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportQueue\*")),

    ("LOW","delivery_opt","Delivery Optimization Cache",
     "Windows Update P2P download cache",
     lambda: _clean(r"C:\Windows\SoftwareDistribution\DeliveryOptimization\*")),

    ("LOW","old_updates","Windows Update Leftovers",
     "Staged update files after successful install",
     lambda: _clean(r"C:\Windows\SoftwareDistribution\Download\*")),

    ("LOW","prefetch","Prefetch Files",
     "App launch cache — auto-rebuilt",
     lambda: _clean(r"C:\Windows\Prefetch\*")),

    ("LOW","font_cache","Font Cache",
     "Cached font data — rebuilt on reboot",
     lambda: _clean(r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache\*")),

    ("LOW","log_files","System Log Files",
     "Diagnostic .log files in C:\\Windows\\Logs",
     lambda: _clean(r"C:\Windows\Logs\*")),

    ("LOW","speech_cache","Speech Recognition Cache",
     "Speech model training cache",
     lambda: _clean(r"%USERPROFILE%\AppData\Roaming\Microsoft\Speech\Files\*")),

    ("LOW","installer_cache","MSI Installer Patch Cache",
     "Old Windows Installer packages",
     lambda: _clean(r"C:\Windows\Installer\$PatchCache$\*")),

    ("LOW","store_hist","Microsoft Store History",
     "Registry record of Store downloads",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Store")]),

    ("LOW","media_hist","Windows Media Player History",
     "Recently played files list in WMP",
     lambda: [_reg("HKCU",r"Software\Microsoft\MediaPlayer\Player\RecentFileList")]),

    ("LOW","paint_recent","MS Paint Recent Files",
     "Recently opened images in Paint",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List")]),

    ("LOW","notepad_recent","Notepad Recent Files",
     "Recently opened files in Notepad (Windows 11)",
     lambda: _clean(r"%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_*\LocalState\*")),

    ("LOW","wordpad_recent","WordPad Recent Files",
     "Recently opened files in WordPad",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List")]),

    ("LOW","directx_shader","DirectX Shader Cache",
     "GPU shader cache — rebuilt by games/apps",
     lambda: _clean(r"%LOCALAPPDATA%\D3DSCache\*")),

    ("LOW","windows_old","Windows.old Folder",
     "Previous Windows installation files (if exists)",
     lambda: _clean(r"C:\Windows.old\*")),

    # ══════════════════════════════════════════════════════════
    #  MEDIUM  SENSITIVITY  —  20 items
    # ══════════════════════════════════════════════════════════
    ("MEDIUM","recent_files","Recent Files (File Explorer)",
     "Quick Access recently opened files list",
     lambda: _clean(r"%APPDATA%\Microsoft\Windows\Recent\*")),

    ("MEDIUM","jumplists","Jump Lists (Taskbar)",
     "Per-app recent files on taskbar right-click",
     lambda: _clean(r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*",
                    r"%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*")),

    ("MEDIUM","run_history","Run Dialog History (Win+R)",
     "Commands typed in the Run box",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")]),

    ("MEDIUM","search_hist","Windows Search History",
     "Terms searched in the Start menu",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery")]),

    ("MEDIUM","clipboard","Clipboard History & Cloud Sync",
     "Everything copied including cloud sync",
     lambda: [_run("echo. | clip","Clear clipboard"),
              _reg("HKCU",r"Software\Microsoft\Clipboard")]),

    ("MEDIUM","event_logs","Windows Event Logs",
     "Application, System, Security, Setup logs",
     lambda: [_run("wevtutil cl Application","App log"),
              _run("wevtutil cl Security","Sec log"),
              _run("wevtutil cl System","Sys log"),
              _run("wevtutil cl Setup","Setup log"),
              _run("wevtutil cl Microsoft-Windows-PowerShell/Operational","PS log")]),

    ("MEDIUM","cortana","Cortana Search & Activity",
     "Cortana history, inking and typing data",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Search")]),

    ("MEDIUM","muicache","MUICache (App Name Cache)",
     "Registry map of every EXE to its name",
     lambda: [_reg("HKCU",r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")]),

    ("MEDIUM","network_hist","Network Connection History",
     "Every Wi-Fi and LAN network ever connected",
     lambda: [_reg("HKLM",r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")]),

    ("MEDIUM","chrome_cache","Chrome Cache & Cookies",
     "Temp files and login cookies in Chrome",
     lambda: _clean(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\*",
                    r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Code Cache\*",
                    r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies",
                    r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies-journal")),

    ("MEDIUM","firefox_cache","Firefox Cache & Cookies",
     "Temp files and cookies in Firefox",
     lambda: _clean(r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2\*",
                    r"%APPDATA%\Mozilla\Firefox\Profiles\*\cookies.sqlite")),

    ("MEDIUM","edge_cache","Edge Cache & Cookies",
     "Temp files and cookies in Edge",
     lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\*",
                    r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies")),

    ("MEDIUM","office_recent","Office Recent Documents",
     "Recently opened Word/Excel/PowerPoint list",
     lambda: _clean(r"%APPDATA%\Microsoft\Office\Recent\*")),

    ("MEDIUM","powershell_hist","PowerShell Command History",
     "All commands typed in PowerShell",
     lambda: _clean(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")),

    ("MEDIUM","open_save_mru","Open/Save Dialog History",
     "Files picked in Open and Save As dialogs",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"),
              _reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU")]),

    ("MEDIUM","vscode_hist","VS Code Workspace History",
     "Recently opened folders and file history",
     lambda: _clean(r"%APPDATA%\Code\User\workspaceStorage\*",
                    r"%APPDATA%\Code\User\History\*")),

    ("MEDIUM","teams_cache","Microsoft Teams Cache",
     "Teams local cache, logs and temp files",
     lambda: _clean(r"%APPDATA%\Microsoft\Teams\Cache\*",
                    r"%APPDATA%\Microsoft\Teams\blob_storage\*",
                    r"%APPDATA%\Microsoft\Teams\databases\*",
                    r"%APPDATA%\Microsoft\Teams\logs.txt")),

    ("MEDIUM","zoom_cache","Zoom Logs & Cache",
     "Zoom call logs and local cache data",
     lambda: _clean(r"%APPDATA%\Zoom\logs\*",
                    r"%LOCALAPPDATA%\Zoom\data\*")),

    ("MEDIUM","discord_cache","Discord Cache",
     "Discord local image and data cache",
     lambda: _clean(r"%APPDATA%\discord\Cache\*",
                    r"%APPDATA%\discord\Code Cache\*")),

    ("MEDIUM","steam_cache","Steam Web Cache & Logs",
     "Steam browser cache and log files",
     lambda: _clean(r"%LOCALAPPDATA%\Steam\htmlcache\*",
                    r"C:\Program Files (x86)\Steam\logs\*")),

    # ══════════════════════════════════════════════════════════
    #  HIGH  SENSITIVITY  —  25 items
    # ══════════════════════════════════════════════════════════
    ("HIGH","chrome_hist","Chrome Browsing History",
     "Every URL visited — cryptographically wiped",
     lambda: _wipe(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History",
                   r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History-journal")),

    ("HIGH","chrome_logins","Chrome Saved Passwords",
     "All Chrome password manager credentials",
     lambda: _wipe(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data",
                   r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data-journal")),

    ("HIGH","chrome_autofill","Chrome Autofill Data",
     "Names, addresses, card numbers saved in Chrome",
     lambda: _wipe(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data")),

    ("HIGH","firefox_hist","Firefox Browsing History",
     "Every URL visited in Firefox — cryptographically wiped",
     lambda: _wipe(r"%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite")),

    ("HIGH","firefox_logins","Firefox Saved Passwords",
     "Firefox password manager credentials",
     lambda: _wipe(r"%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json",
                   r"%APPDATA%\Mozilla\Firefox\Profiles\*\key4.db")),

    ("HIGH","edge_hist","Edge Browsing History",
     "Every URL visited in Edge — cryptographically wiped",
     lambda: _wipe(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History")),

    ("HIGH","edge_logins","Edge Saved Passwords",
     "All Edge password manager credentials",
     lambda: _wipe(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data")),

    ("HIGH","ie_hist","Internet Explorer Full History",
     "IE history, typed URLs, cookies and forms",
     lambda: [_run("RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255","Clear all IE")]),

    ("HIGH","typed_urls","Typed URLs Registry",
     "URLs typed directly into browser address bar",
     lambda: [_reg("HKCU",r"Software\Microsoft\Internet Explorer\TypedURLs")]),

    ("HIGH","user_assist","UserAssist Registry Keys",
     "Encrypted record of every program launched",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")]),

    ("HIGH","shellbags","Shell Bags",
     "Every folder ever opened incl. USB drives",
     lambda: [_reg("HKCU",r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"),
              _reg("HKCU",r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags")]),

    ("HIGH","lnk_files","Shortcut (.lnk) Files",
     "Auto-created shortcuts exposing file paths",
     lambda: _wipe(r"%APPDATA%\Microsoft\Windows\Recent\*.lnk")),

    ("HIGH","bam","Background Activity Monitor (BAM)",
     "Kernel timestamps of every program executed",
     lambda: [_reg("HKLM",r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings")]),

    ("HIGH","dns_cache","DNS Cache",
     "Resolved domains revealing visited sites",
     lambda: [_run("ipconfig /flushdns","Flush DNS")]),

    ("HIGH","wifi_passwords","Saved Wi-Fi Passwords",
     "All WPA/WPA2 credentials for every network",
     lambda: [_run("netsh wlan delete profile name=*","Delete Wi-Fi profiles")]),

    ("HIGH","location_hist","Windows Location History",
     "GPS and location data logged by Windows",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")]),

    ("HIGH","activity_hist","Windows Activity History",
     "Apps and files logged in Windows Timeline",
     lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\ActivityDataModel"),
              _run('PowerShell -Command "Clear-ActivityHistory -EA SilentlyContinue"',"Clear Timeline")]),

    ("HIGH","downloads_folder","Downloads Folder — ALL Files",
     "Every file in Downloads — cryptographically wiped",
     lambda: _wipe(r"%USERPROFILE%\Downloads\*")),

    ("HIGH","office_mru","Office MRU Registry",
     "Most Recently Used lists for all Office apps",
     lambda: [_reg("HKCU",r"Software\Microsoft\Office\16.0\Word\File MRU"),
              _reg("HKCU",r"Software\Microsoft\Office\16.0\Excel\File MRU"),
              _reg("HKCU",r"Software\Microsoft\Office\16.0\PowerPoint\File MRU"),
              _reg("HKCU",r"Software\Microsoft\Office\15.0\Word\File MRU"),
              _reg("HKCU",r"Software\Microsoft\Office\15.0\Excel\File MRU")]),

    ("HIGH","rdp_hist","Remote Desktop History",
     "Every server connected to via RDP",
     lambda: [_reg("HKCU",r"Software\Microsoft\Terminal Server Client\Default"),
              _reg("HKCU",r"Software\Microsoft\Terminal Server Client\Servers")]),

    ("HIGH","skype_logs","Skype / Teams Chat Logs",
     "Local message databases — wiped",
     lambda: _wipe(r"%APPDATA%\Skype\*\main.db",
                   r"%LOCALAPPDATA%\Packages\Microsoft.SkypeApp_*\LocalState\*")),

    ("HIGH","app_compat","AppCompatCache (Shimcache)",
     "Windows compatibility log of every EXE run",
     lambda: [_run(r'reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache /f',
                   "Clear Shimcache")]),

    ("HIGH","amcache","AmCache Hive",
     "Forensic record of every installed/run program",
     lambda: [_run('PowerShell -Command "Remove-Item C:\\Windows\\AppCompat\\Programs\\Amcache.hve -Force -EA SilentlyContinue"',
                   "Delete AmCache")]),

    ("HIGH","srum","SRUM Database",
     "System Resource Usage Monitor — tracks all app network/CPU usage",
     lambda: [_run('PowerShell -Command "Stop-Service diagtrack -Force -EA SilentlyContinue; Remove-Item C:\\Windows\\System32\\sru\\SRUDB.dat -Force -EA SilentlyContinue"',
                   "Clear SRUM database")]),

    ("HIGH","pagefile_wipe","Page File Zero on Shutdown",
     "Configure Windows to zero pagefile on every shutdown",
     lambda: [_run(r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f',
                   "Enable pagefile wipe")]),

    # ── New forensic-grade additions ──────────────────────────────────────────

    ("HIGH","volume_shadows","Volume Shadow Copies (VSS)",
     "Windows snapshots — investigators mount these to see files from weeks ago",
     lambda: [_run('PowerShell -Command "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"',
                   "Delete all shadow copies"),
              _run('vssadmin delete shadows /all /quiet',
                   "vssadmin shadow wipe")]),

    ("HIGH","ntfs_journal","NTFS Change Journal ($UsnJrnl)",
     "Logs every file operation ever — creation, rename, delete. Key forensic artifact.",
     lambda: [_run('fsutil usn deletejournal /d C:', "Delete USN journal drive C"),
              _run('fsutil usn deletejournal /d D: 2>nul', "Delete USN journal drive D")]),

    ("HIGH","ntfs_logfile","NTFS $LogFile (Filesystem Journal)",
     "Transaction log of all filesystem changes — used to recover deleted file names",
     lambda: [_run('PowerShell -Command "& {$vol=\'C:\'; $fs=[System.IO.File]::Open(\'C:\\$LogFile\',[System.IO.FileMode]::Open,[System.IO.FileAccess]::Write,[System.IO.FileShare]::ReadWrite); $buf=New-Object byte[] 65536; $fs.Write($buf,0,65536); $fs.Close()}" 2>nul',
                   "Overwrite $LogFile header (best-effort)"),
              _run('chkdsk C: /f /x /r 2>nul', "Force NTFS journal reset via chkdsk")]),

    ("HIGH","hiberfil","Hibernation File (hiberfil.sys)",
     "Contains full RAM dump — open docs, passwords, keys captured at sleep time",
     lambda: [_run('powercfg /hibernate off', "Disable hibernation and delete hiberfil.sys"),
              _run('PowerShell -Command "Remove-Item C:\\hiberfil.sys -Force -EA SilentlyContinue"',
                   "Force delete hiberfil.sys")]),

    ("HIGH","search_index","Windows Search Index",
     "Contains text snippets from documents you deleted — lives in ProgramData",
     lambda: [_run('net stop WSearch /y', "Stop Windows Search service"),
              _clean(r"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\*",
                     r"C:\ProgramData\Microsoft\Search\Data\Temp\*"),
              _run('net start WSearch', "Restart Windows Search")]),

    ("HIGH","evtx_backups","Event Log Backup Files (.evtx)",
     "Archived event logs Windows keeps outside the main log location",
     lambda: _clean(r"C:\Windows\System32\winevt\Logs\*.evtx",
                    r"C:\Windows\System32\winevt\Backup\*.evtx")),

    ("HIGH","browser_sessions","Browser Session Restore Files",
     "Reveal open tabs even after history cleared — Chrome, Firefox, Edge",
     lambda: _wipe(
         r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Sessions\*",
         r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Session Storage\*",
         r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Current Session",
         r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Last Session",
         r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Current Tabs",
         r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Last Tabs",
         r"%APPDATA%\Mozilla\Firefox\Profiles\*\sessionstore.jsonlz4",
         r"%APPDATA%\Mozilla\Firefox\Profiles\*\sessionstore-backups\*",
         r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Sessions\*",
         r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Session Storage\*")),

    ("HIGH","onedrive_thumbs","OneDrive / Cloud Sync Thumbnail Cache",
     "Local previews of cloud files — persist after cloud deletion",
     lambda: _clean(
         r"%LOCALAPPDATA%\Microsoft\OneDrive\logs\*",
         r"%LOCALAPPDATA%\Microsoft\OneDrive\setup\logs\*",
         r"%USERPROFILE%\AppData\Local\Microsoft\OneDrive\*\*.db",
         r"%LOCALAPPDATA%\Microsoft\Windows\INetCache\*")),

    ("HIGH","mft_slack","MFT Slack Space Wipe (Free Space)",
     "Fills drive free space with zeros so MFT carved file remnants are destroyed",
     lambda: [_run('PowerShell -Command "& { $f=\'C:\\mft_wipe_tmp.tmp\'; $s=New-Object System.IO.FileStream($f,[IO.FileMode]::Create); $b=New-Object byte[] 65536; try { while($true){$s.Write($b,0,65536)} } catch {} $s.Close(); Remove-Item $f -Force -EA SilentlyContinue }"',
                   "Fill free space with zeros to destroy MFT remnants"),
              _run('PowerShell -Command "Optimize-Volume -DriveLetter C -ReTrim -Confirm:$false 2>$null"',
                   "TRIM freed blocks")]),
]

assert len(ALL_ITEMS) == 74, f"Expected 74, got {len(ALL_ITEMS)}"

# Items excluded from "SAFE SELECT" — these delete actual user files or
# make irreversible system changes that affect usability
SAFE_EXCLUDE = {
    "downloads_folder",   # Deletes ALL files in Downloads
    "wifi_passwords",     # Removes all saved Wi-Fi credentials
    "pagefile_wipe",      # Changes system shutdown behaviour
    "hiberfil",           # Disables hibernation permanently
    "mft_slack",          # Fills entire free space — very slow & disruptive
    "ntfs_logfile",       # Runs chkdsk — may take a long time
    "volume_shadows",     # Deletes all system restore points
    "chrome_logins",      # Destroys all Chrome saved passwords
    "firefox_logins",     # Destroys all Firefox saved passwords
    "edge_logins",        # Destroys all Edge saved passwords
    "chrome_autofill",    # Destroys Chrome autofill — names, addresses, cards
}

WIPE_MODES = {
    "single":  ("1-Pass  NVMe",     "#4a9eda", "1× CSPRNG random + TRIM  ·  Fast, sufficient for NVMe/SSD"),
    "secure":  ("7-Pass  NVMe",     "#c8922a", "7× alternating + random + TRIM  ·  Recommended for sensitive data"),
    "gutmann": ("35-Pass  Gutmann", "#b03030", "35× fixed patterns + 26× CSPRNG + TRIM  ·  Maximum destruction"),
}


WIPE_MODES = {
    "single":  ("1-PASS  NVMe",     "#00d4ff", "1× CSPRNG + TRIM  ·  Fast — sufficient for NVMe/SSD"),
    "secure":  ("7-PASS  NVMe",     "#ff9500", "7× alternating + random + TRIM  ·  Recommended"),
    "gutmann": ("35-PASS  GUTMANN", "#ff3c3c", "35× fixed + 26× CSPRNG + TRIM  ·  Maximum destruction"),
}

# ─── Cyberpunk Neon Dark Palette ─────────────────────────────────────────────
BG        = "#050508"    # deepest black-blue
SURFACE   = "#0d0d14"    # card surface
SURFACE2  = "#13131f"    # hover surface
SURFACE3  = "#1a1a2e"    # selected surface
BORDER    = "#1e1e32"    # dim border
BORDER2   = "#2a2a4a"    # hover border
GLOW_C    = "#00d4ff"    # cyan neon — primary accent
GLOW_G    = "#00ff88"    # green neon — success / low
GLOW_O    = "#ff9500"    # orange neon — medium
GLOW_R    = "#ff3c3c"    # red neon — high / danger
GLOW_P    = "#bf5fff"    # purple neon — registry
TEXT      = "#e8eaf0"    # primary text
TEXT2     = "#6b6b8a"    # secondary text
TEXT3     = "#35354a"    # muted / disabled

FONT_MONO   = ("Consolas",   10)
FONT_MONO_S = ("Consolas",    9)
FONT_MONO_B = ("Consolas",   11, "bold")
FONT_UI     = ("Segoe UI",   10)
FONT_UI_S   = ("Segoe UI",    9)
FONT_UI_B   = ("Segoe UI",   11, "bold")
FONT_TITLE  = ("Segoe UI",   17, "bold")
FONT_STAT   = ("Consolas",   20, "bold")
FONT_STAT_S = ("Segoe UI",    8)
FONT_BTN    = ("Segoe UI",   13, "bold")
FONT_BADGE  = ("Consolas",    8, "bold")

TIER_CFG = {
    #          abbr    neon-color  surface-bg  border-color
    "LOW":    ("LOW",  GLOW_G,    "#050e08",  "#003318"),
    "MEDIUM": ("MED",  GLOW_O,    "#0e0900",  "#3a2200"),
    "HIGH":   ("HIGH", GLOW_R,    "#0e0505",  "#3a0808"),
}

# ─── Glowing neon checkbox ────────────────────────────────────────────────────
class NCB(tk.Canvas):
    S = 20
    def __init__(self, master, variable, command=None, bg=SURFACE, color=GLOW_C, **kw):
        super().__init__(master, width=self.S, height=self.S,
                         highlightthickness=0, bd=0, bg=bg, **kw)
        self.var   = variable
        self._cmd  = command
        self._bg   = bg
        self._col  = color
        self._hov  = False
        self._draw()
        self.var.trace_add("write", lambda *_: self._draw())
        self.bind("<Button-1>", self._click)
        self.bind("<Enter>",    lambda e: self._set_hov(True))
        self.bind("<Leave>",    lambda e: self._set_hov(False))

    def _draw(self):
        self.delete("all")
        s = self.S
        checked = self.var.get()
        # Outer glow ring when checked
        if checked:
            self.create_rectangle(0, 0, s, s,
                                  fill="", outline=self._col, width=1)
        # Inner box
        fill = SURFACE3 if checked else (SURFACE2 if self._hov else SURFACE)
        border = self._col if checked else (BORDER2 if self._hov else BORDER)
        self.create_rectangle(2, 2, s-2, s-2, fill=fill, outline=border, width=1)
        if checked:
            # Neon tick
            p = 5
            mid = s // 2
            self.create_line(p, mid, mid-1, s-p,
                             fill=self._col, width=2, capstyle="round")
            self.create_line(mid-1, s-p, s-p, p,
                             fill=self._col, width=2, capstyle="round")

    def _click(self, _=None):
        self.var.set(not self.var.get())
        if self._cmd: self._cmd()

    def _set_hov(self, v):
        self._hov = v; self._draw()


# ─── Animated scan-line canvas for header ────────────────────────────────────
class ScanlineHeader(tk.Canvas):
    """Draws a static cyberpunk header with hex grid texture and neon text."""
    def __init__(self, master, **kw):
        super().__init__(master, height=90, highlightthickness=0, bd=0,
                         bg=BG, **kw)
        self.bind("<Configure>", self._draw)

    def _draw(self, event=None):
        self.delete("all")
        w = self.winfo_width() or 1020
        h = 90

        # Subtle dot grid texture
        for x in range(0, w, 28):
            for y in range(0, h, 14):
                self.create_oval(x-1, y-1, x+1, y+1, fill=BORDER, outline="")

        # Left neon cyan bar
        self.create_rectangle(0, 0, 4, h, fill=GLOW_C, outline="")

        # REDACT — big bold name
        self.create_text(22, 32, text="REDACT",
                         font=("Consolas", 26, "bold"), fill=TEXT, anchor="w")

        # Single subtitle line
        self.create_text(22, 62, text="Anti-Forensic Sanitisation Tool  ·  v1.0  ·  74 items",
                         font=FONT_MONO_S, fill=TEXT2, anchor="w")

        # Right: admin badge
        bx = w - 180
        self.create_rectangle(bx, 20, w-14, 44, fill="#051a05", outline=GLOW_G, width=1)
        self.create_text(bx+10, 32, text="● ADMINISTRATOR",
                         font=("Consolas", 9, "bold"), fill=GLOW_G, anchor="w")

        # Right: timestamp
        self.create_rectangle(bx, 50, w-14, 70, fill="#050510", outline=BORDER2, width=1)
        self.create_text(bx+10, 60, text=f"  {datetime.now().strftime('%Y-%m-%d  %H:%M')}",
                         font=("Consolas", 8), fill=TEXT2, anchor="w")

        # Bottom neon line
        self.create_line(0, h-1, w, h-1, fill=GLOW_C, width=1)


# ─── Wipe mode selector ───────────────────────────────────────────────────────
class WipeModeBar(tk.Frame):
    def __init__(self, master, on_change, **kw):
        super().__init__(master, bg=SURFACE, pady=0, **kw)
        self._on_change = on_change
        self._cards = {}
        self._info = tk.Label(self, text="", font=FONT_MONO_S, bg=SURFACE, fg=TEXT2)
        self._build()

    def _build(self):
        tk.Label(self, text=" WIPE:", font=("Consolas", 9, "bold"),
                 bg=SURFACE, fg=TEXT3).pack(side="left", padx=(12, 8), pady=10)

        for key, (label, color, _) in WIPE_MODES.items():
            f = tk.Frame(self, bg=SURFACE, padx=2, pady=8)
            f.pack(side="left", padx=2)

            btn = tk.Label(f, text=f" {label} ",
                           font=("Consolas", 9, "bold"),
                           bg=SURFACE, fg=TEXT2,
                           padx=12, pady=5,
                           cursor="hand2", relief="flat")
            btn.pack()
            btn.bind("<Button-1>", lambda e, k=key: self._select(k))
            btn.bind("<Enter>",    lambda e, b=btn, c=color: b.config(fg=c, bg=SURFACE2))
            btn.bind("<Leave>",    lambda e, k=key, b=btn: self._restore(k, b))
            self._cards[key] = (f, btn)

        self._info.pack(side="left", padx=16)
        self._select("single")

    def _select(self, key):
        global WIPE_MODE_KEY
        WIPE_MODE_KEY = key
        _, color, desc = WIPE_MODES[key]
        for k, (f, btn) in self._cards.items():
            sel = k == key
            _, c, _ = WIPE_MODES[k]
            btn.config(bg=SURFACE3 if sel else SURFACE,
                       fg=c if sel else TEXT2)
            # Neon left border simulation via frame color
            f.config(bg=c if sel else SURFACE)
        self._info.config(text=f"  ▸  {desc}", fg=color)
        self._on_change(key)

    def _restore(self, key, btn):
        _, color, _ = WIPE_MODES[key]
        if WIPE_MODE_KEY == key:
            btn.config(fg=color, bg=SURFACE3)
        else:
            btn.config(fg=TEXT2, bg=SURFACE)

    def get(self): return WIPE_MODE_KEY


# ─── Neon separator ───────────────────────────────────────────────────────────
def NeonSep(parent, color=GLOW_C, dim=True):
    c = TEXT3 if dim else color
    tk.Frame(parent, bg=c, height=1).pack(fill="x")


# ─── Stat card widget ─────────────────────────────────────────────────────────
class StatCard(tk.Frame):
    def __init__(self, master, label, color, **kw):
        super().__init__(master, bg=SURFACE, **kw)
        # Top neon bar
        tk.Frame(self, bg=color, height=2).pack(fill="x")
        inner = tk.Frame(self, bg=SURFACE, padx=18, pady=10)
        inner.pack(fill="both", expand=True)
        self._var = tk.StringVar(value="—")
        tk.Label(inner, textvariable=self._var,
                 font=FONT_STAT, bg=SURFACE, fg=color).pack(anchor="w")
        tk.Label(inner, text=label,
                 font=("Consolas", 8), bg=SURFACE, fg=TEXT3).pack(anchor="w")

    def set(self, val): self._var.set(val)


# ─── Main App ─────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("REDACT  ·  v1.0  ·  Administrator")
        self.geometry("1020x860")
        self.minsize(860, 660)
        self.configure(bg=BG)
        self.resizable(True, True)

        self.vars      = {iid: tk.BooleanVar(value=False) for (_,iid,*_) in ALL_ITEMS}
        self.tier_vars = {t:   tk.BooleanVar(value=False) for t in TIER_CFG}
        self._wipe_mode = "single"

        self._build()
        self._update_count()

    # ── Build UI ─────────────────────────────────────────────────────────────
    def _build(self):
        self._header()
        self._wipe_section()
        self._toolbar()
        NeonSep(self, BORDER)
        self._list()
        self._stats_bar()
        self._footer()

    def _header(self):
        self._scan = ScanlineHeader(self)
        self._scan.pack(fill="x")

    def _wipe_section(self):
        # dark bar holding wipe mode selector
        bar = tk.Frame(self, bg=SURFACE)
        bar.pack(fill="x")
        NeonSep(bar, BORDER)
        # Create wipe_detail before WipeModeBar
        self.wipe_detail = tk.Label(self, text="", font=FONT_MONO_S,
                                     bg=BG, fg=TEXT2, pady=3, padx=16)
        self.wipe_bar = WipeModeBar(bar, on_change=self._on_wipe_change)
        self.wipe_bar.pack(fill="x")
        NeonSep(bar, BORDER)
        self.wipe_detail.pack(fill="x")

    def _on_wipe_change(self, key):
        global WIPE_MODE_KEY
        WIPE_MODE_KEY = key
        self._wipe_mode = key
        if hasattr(self, "wipe_detail"):
            _, color, desc = WIPE_MODES[key]
            self.wipe_detail.config(
                text=f"  [ {desc} ]", fg=color)

    def _toolbar(self):
        bar = tk.Frame(self, bg=SURFACE, pady=0)
        bar.pack(fill="x")
        NeonSep(bar, BORDER)

        inner = tk.Frame(bar, bg=SURFACE, pady=7)
        inner.pack(fill="x")

        # Tier toggles
        tk.Label(inner, text=" TIER:", font=("Consolas", 9, "bold"),
                 bg=SURFACE, fg=TEXT3).pack(side="left", padx=(12,8))

        for tier, (abbr, color, tbg, border) in TIER_CFG.items():
            cell = tk.Frame(inner, bg=SURFACE)
            cell.pack(side="left", padx=8)
            NCB(cell, variable=self.tier_vars[tier], bg=SURFACE, color=color,
                command=lambda t=tier: self._tier_toggle(t)).pack(side="left", padx=(0,6))
            # Neon-coloured label
            lbl = tk.Label(cell, text=abbr, font=("Consolas", 9, "bold"),
                           bg=SURFACE, fg=color, cursor="hand2")
            lbl.pack(side="left")
            lbl.bind("<Button-1>", lambda e, t=tier: self._tier_toggle(t))

        # Separator dot
        tk.Label(inner, text="  ·  ", font=FONT_UI_S, bg=SURFACE, fg=TEXT3).pack(side="left")

        # Quick select buttons — styled as neon text links
        for txt, cmd, col in [
            ("SELECT ALL",  self._all,  GLOW_C),
            ("SAFE SELECT", self._safe, GLOW_G),
            ("CLEAR ALL",   self._none, TEXT3),
        ]:
            b = tk.Label(inner, text=txt, font=("Consolas", 9, "bold"),
                         bg=SURFACE, fg=col, cursor="hand2", padx=8)
            b.pack(side="left", padx=2)
            b.bind("<Button-1>", lambda e, c=cmd: c())
            b.bind("<Enter>",    lambda e, lb=b, c=col: lb.config(fg=TEXT, bg=SURFACE2))
            b.bind("<Leave>",    lambda e, lb=b, c=col: lb.config(fg=c,    bg=SURFACE))

        # Counter — right aligned, neon cyan
        self.lbl_count = tk.Label(inner, text="",
                                   font=("Consolas", 10, "bold"),
                                   bg=SURFACE, fg=GLOW_C)
        self.lbl_count.pack(side="right", padx=18)

        NeonSep(bar, BORDER)

    def _list(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.inner = tk.Frame(self.canvas, bg=BG)
        win = self.canvas.create_window((0,0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>",
                         lambda e: self.canvas.itemconfig(win, width=e.width))
        self.inner.bind("<Configure>",
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind_all("<MouseWheel>",
                             lambda e: self.canvas.yview_scroll(-1*(e.delta//120),"units"))
        self.canvas.bind_all("<Prior>",  # Page Up
                             lambda e: self.canvas.yview_scroll(-10, "units"))
        self.canvas.bind_all("<Next>",   # Page Down
                             lambda e: self.canvas.yview_scroll(10, "units"))
        self.canvas.bind_all("<Home>",
                             lambda e: self.canvas.yview_moveto(0))
        self.canvas.bind_all("<End>",
                             lambda e: self.canvas.yview_moveto(1))

        s = ttk.Style(); s.theme_use("clam")
        s.configure("Vertical.TScrollbar",
                    troughcolor=SURFACE, background=BORDER2,
                    bordercolor=BG, arrowcolor=TEXT3, width=8)

        cur = None
        for (tier, iid, name, desc, _) in ALL_ITEMS:
            if tier != cur:
                cur = tier
                self._tier_hdr(tier)
            self._row(tier, iid, name, desc)

        # Bottom padding
        tk.Frame(self.inner, bg=BG, height=8).pack()

    def _tier_hdr(self, tier):
        abbr, color, tbg, border = TIER_CFG[tier]
        count = sum(1 for t,*_ in ALL_ITEMS if t==tier)

        labels = {
            "LOW":    "LOW SENSITIVITY  ──  Safe housekeeping  ·  No personal data at risk",
            "MEDIUM": "MEDIUM SENSITIVITY  ──  Usage patterns  ·  App metadata  ·  Cache",
            "HIGH":   "HIGH SENSITIVITY  ──  Personal data  ·  Passwords  ·  Forensic traces",
        }

        wrap = tk.Frame(self.inner, bg=BG)
        wrap.pack(fill="x", pady=(14, 0))

        # Left neon bar
        tk.Frame(wrap, bg=color, width=3).pack(side="left", fill="y")

        hdr = tk.Frame(wrap, bg=tbg)
        hdr.pack(side="left", fill="x", expand=True)

        # Top neon line
        tk.Frame(hdr, bg=border, height=1).pack(fill="x")

        inner = tk.Frame(hdr, bg=tbg, pady=9)
        inner.pack(fill="x")

        tk.Label(inner, text=f"  {labels[tier]}",
                 font=("Consolas", 9, "bold"), bg=tbg, fg=color).pack(side="left", padx=6)

        # Count pill
        pill = tk.Frame(inner, bg=border, padx=10, pady=2)
        pill.pack(side="right", padx=14)
        tk.Label(pill, text=f"{count} ITEMS",
                 font=("Consolas", 8, "bold"), bg=border, fg=color).pack()

        # Bottom line
        tk.Frame(hdr, bg=border, height=1).pack(fill="x")

    def _row(self, tier, iid, name, desc):
        abbr, color, tbg, border = TIER_CFG[tier]

        wrap = tk.Frame(self.inner, bg=BG)
        wrap.pack(fill="x", pady=0)

        # Left neon accent — thin, tier-coloured
        accent = tk.Frame(wrap, bg=color, width=2)
        accent.pack(side="left", fill="y")

        row = tk.Frame(wrap, bg=SURFACE)
        row.pack(side="left", fill="x", expand=True)

        # Checkbox
        cb = NCB(row, variable=self.vars[iid], command=self._update_count,
                 bg=SURFACE, color=color)
        cb.pack(side="left", padx=(14,10), pady=11)

        # Name + description
        info = tk.Frame(row, bg=SURFACE)
        info.pack(side="left", fill="x", expand=True, pady=8)
        tk.Label(info, text=name, font=("Segoe UI", 10, "bold"),
                 bg=SURFACE, fg=TEXT, anchor="w").pack(fill="x")
        tk.Label(info, text=desc, font=("Consolas", 8),
                 bg=SURFACE, fg=TEXT2, anchor="w").pack(fill="x")

        # Badge pill — neon outlined
        pill_f = tk.Frame(row, bg=tbg, padx=10, pady=3)
        pill_f.pack(side="right", padx=14, pady=10)
        tk.Label(pill_f, text=abbr, font=FONT_BADGE, bg=tbg, fg=color).pack()

        # Bottom divider
        tk.Frame(self.inner, bg=BORDER, height=1).pack(fill="x")

        # Hover — lighten row
        all_widgets = [wrap, row, info, cb, accent] + list(info.winfo_children())

        def _enter(_e):
            row.config(bg=SURFACE2)
            info.config(bg=SURFACE2)
            cb.config(bg=SURFACE2)
            for w in info.winfo_children(): w.config(bg=SURFACE2)

        def _leave(_e):
            row.config(bg=SURFACE)
            info.config(bg=SURFACE)
            cb.config(bg=SURFACE)
            for w in info.winfo_children(): w.config(bg=SURFACE)

        def _click(_e):
            self._toggle(iid)

        for w in [row, info] + list(info.winfo_children()):
            w.bind("<Enter>",    _enter)
            w.bind("<Leave>",    _leave)
            w.bind("<Button-1>", _click)

    def _stats_bar(self):
        # Built here but NOT packed yet — packed in _run_clean when cleaning starts
        self.stats_outer = tk.Frame(self, bg=BG)

        # Progress bar only — clean and minimal
        self.prog_frame = tk.Frame(self.stats_outer, bg=BG)
        self.prog_frame.pack(fill="x")
        self.pvar = tk.DoubleVar()
        s = ttk.Style()
        s.configure("N.Horizontal.TProgressbar",
                    troughcolor=SURFACE, background=GLOW_C,
                    darkcolor=GLOW_C, lightcolor=GLOW_C,
                    thickness=3, borderwidth=0)
        self.pbar = ttk.Progressbar(self.prog_frame, variable=self.pvar,
                                     maximum=100, style="N.Horizontal.TProgressbar")
        self.pbar.pack(fill="x")
        self.slbl = tk.Label(self.prog_frame, text="",
                              font=("Consolas", 9), bg=BG, fg=GLOW_C, pady=4, padx=14)
        self.slbl.pack(fill="x")

        # Hidden vars still tracked internally and shown in final popup + report
        self._var_files = tk.StringVar(value="0")
        self._var_size  = tk.StringVar(value="0 B")
        self._var_low   = tk.StringVar(value="0 files  ·  0 B")
        self._var_med   = tk.StringVar(value="0 files  ·  0 B")
        self._var_high  = tk.StringVar(value="0 files  ·  0 B")

    def _footer(self):
        foot = tk.Frame(self, bg=SURFACE)
        foot.pack(fill="x")

        NeonSep(foot, GLOW_C)

        inner = tk.Frame(foot, bg=SURFACE, pady=14)
        inner.pack(fill="x")

        self.btn = tk.Button(
            inner,
            text="  ██   R E D A C T   N O W  ",
            font=FONT_BTN,
            bg=GLOW_C, fg="#000000",
            activebackground="#00aacc", activeforeground="#000000",
            relief="flat", padx=36, pady=12,
            cursor="hand2", bd=0,
            command=self._confirm
        )
        self.btn.pack(pady=(0, 6))

        self.footer_sub = tk.Label(
            inner,
            text="NVMe · SSD · HDD  ·  CSPRNG overwrite  ·  TRIM  ·  Registry backup  ·  Desktop report",
            font=("Consolas", 8), bg=SURFACE, fg=TEXT3)
        self.footer_sub.pack()

    # ── Logic ─────────────────────────────────────────────────────────────────
    def _toggle(self, iid):
        self.vars[iid].set(not self.vars[iid].get())
        self._update_count()

    def _tier_toggle(self, tier):
        s = self.tier_vars[tier].get()
        for (t, iid, *_) in ALL_ITEMS:
            if t == tier: self.vars[iid].set(s)
        self._update_count()

    def _all(self):
        for v in self.vars.values():      v.set(True)
        for v in self.tier_vars.values(): v.set(True)
        self._update_count()

    def _none(self):
        for v in self.vars.values():      v.set(False)
        for v in self.tier_vars.values(): v.set(False)
        self._update_count()

    def _safe(self):
        """Select everything EXCEPT items that delete user files or make
        irreversible system changes (passwords, downloads, hibernation, etc.)"""
        for (_, iid, *_) in ALL_ITEMS:
            self.vars[iid].set(iid not in SAFE_EXCLUDE)
        # Sync tier checkboxes — set True only if ALL items in that tier are ticked
        for tier in TIER_CFG:
            tier_ids = [iid for (t, iid, *_) in ALL_ITEMS if t == tier]
            all_on = all(self.vars[iid].get() for iid in tier_ids)
            self.tier_vars[tier].set(all_on)
        self._update_count()

    def _update_count(self):
        n = sum(1 for v in self.vars.values() if v.get())
        self.lbl_count.config(text=f"{n:02d} / {len(ALL_ITEMS)} SELECTED")

    def _confirm(self):
        sel = [(tier,iid,name,desc,fn)
               for (tier,iid,name,desc,fn) in ALL_ITEMS
               if self.vars[iid].get()]
        if not sel:
            messagebox.showwarning("Nothing selected","Select at least one item.")
            return
        ml, color, md = WIPE_MODES[self._wipe_mode]
        hi = sum(1 for t,*_ in sel if t=="HIGH")
        warn = f"\n\n⚠  {hi} HIGH-sensitivity item(s) included.\nPasswords & forensic traces will be destroyed." if hi else ""
        if messagebox.askyesno("REDACT — Confirm",
            f"{len(sel)} items selected\nStandard: {ml}\n{md}{warn}\n\nReport saved to Desktop after clean.\n\nProceed?",
            icon="warning"):
            self._run_clean(sel)

    def _backup_registry(self):
        """Export full HKCU and HKLM registry hives to Desktop before any cleaning."""
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        os.makedirs(desktop, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = os.path.join(desktop, f"REDACT_RegBackup_{stamp}")
        os.makedirs(folder, exist_ok=True)

        hkcu = os.path.join(folder, "HKCU_backup.reg")
        hklm = os.path.join(folder, "HKLM_backup.reg")

        subprocess.run(f'reg export HKCU "{hkcu}" /y', shell=True,
                       capture_output=True, timeout=60)
        subprocess.run(f'reg export HKLM "{hklm}" /y', shell=True,
                       capture_output=True, timeout=120)
        return folder

    def _run_clean(self, sel):
        STATS.reset()
        self._var_files.set("0")
        self._var_size.set("0 B")
        self._var_low.set("0 files  ·  0 B")
        self._var_med.set("0 files  ·  0 B")
        self._var_high.set("0 files  ·  0 B")

        self.btn.config(state="disabled", text="  💾   BACKING UP REGISTRY …  ",
                        bg=SURFACE3, fg=GLOW_C)
        self.update_idletasks()

        # Back up registry before anything is touched
        try:
            backup_folder = self._backup_registry()
        except Exception as e:
            backup_folder = f"Backup failed: {e}"

        self.btn.config(text="  ⏳   R E D A C T I N G …  ")
        self.stats_outer.pack(fill="x")
        self.update_idletasks()
        threading.Thread(target=self._do_clean,
                         args=(sel, backup_folder), daemon=True).start()

    def _do_clean(self, sel, backup_folder=""):
        ml, color, md = WIPE_MODES[self._wipe_mode]
        now = datetime.now()

        lines = [
            "="*72,
            "  REDACT  —  CLEANING REPORT",
            f"  Date     : {now.strftime('%Y-%m-%d  %H:%M:%S')}",
            f"  Items    : {len(sel)} of {len(ALL_ITEMS)}",
            f"  Standard : {ml}  —  {md}",
            f"  Reg backup: {backup_folder}",
            f"  User     : {os.environ.get('USERNAME','unknown')}",
            f"  Computer : {os.environ.get('COMPUTERNAME','unknown')}",
            "="*72, "",
        ]

        buckets = {"LOW":[],"MEDIUM":[],"HIGH":[]}
        for e in sel: buckets[e[0]].append(e)

        # Per-tier tracking
        tier_files = {"LOW":0,"MEDIUM":0,"HIGH":0}
        tier_bytes = {"LOW":0,"MEDIUM":0,"HIGH":0}

        tier_var_map = {
            "LOW":    self._var_low,
            "MEDIUM": self._var_med,
            "HIGH":   self._var_high,
        }

        def _update_ui():
            self._var_files.set(f"{STATS.files:,}")
            self._var_size.set(_fmt_size(STATS.bytes))
            for t, v in tier_var_map.items():
                v.set(f"{tier_files[t]:,} files  ·  {_fmt_size(tier_bytes[t])}")
            self.update_idletasks()

        idx = 0
        for tier in ("LOW","MEDIUM","HIGH"):
            bucket = buckets[tier]
            if not bucket: continue
            abbr, neon, *_ = TIER_CFG[tier]
            lines += [f"{'─'*72}",
                      f"  {abbr} SENSITIVITY  ({len(bucket)} items)",
                      f"{'─'*72}"]
            for (_,iid,name,desc,fn) in bucket:
                idx += 1
                pct = (idx / len(sel)) * 100
                self.pvar.set(pct)
                before_files = STATS.files
                before_bytes = STATS.bytes
                self.slbl.config(
                    text=f"  ▸  [{idx:02d}/{len(sel):02d}]  {name}  ·  {_fmt_size(STATS.bytes)} freed")
                _update_ui()

                lines.append(f"\n  [{idx:02d}] {name}")
                lines.append(f"       {desc}")
                try:
                    for r in (fn() or []): lines.append(f"  {r}")
                except Exception as e:
                    lines.append(f"       ERROR: {e}")

                # Accumulate per-tier stats from what was just cleaned
                tier_files[tier] += STATS.files - before_files
                tier_bytes[tier] += STATS.bytes - before_bytes
                _update_ui()
            lines.append("")

        _update_ui()

        size_str = _fmt_size(STATS.bytes)
        lines += [
            "="*72,
            "  SUMMARY",
            f"  Files wiped          : {STATS.files:,}",
            f"  Data removed         : {size_str}",
            f"  Registry keys        : {STATS.reg_keys:,}",
            f"  Skipped / locked     : {STATS.skipped:,}",
            f"  Low sensitivity      : {tier_files['LOW']:,} files  ·  {_fmt_size(tier_bytes['LOW'])}",
            f"  Medium sensitivity   : {tier_files['MEDIUM']:,} files  ·  {_fmt_size(tier_bytes['MEDIUM'])}",
            f"  High sensitivity     : {tier_files['HIGH']:,} files  ·  {_fmt_size(tier_bytes['HIGH'])}",
            f"  Standard             : {ml}",
            "="*72,
            f"  COMPLETE  ·  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}",
            "="*72,
        ]

        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        os.makedirs(desktop, exist_ok=True)
        fname  = f"REDACT_{now.strftime('%Y%m%d_%H%M%S')}.txt"
        rpath  = os.path.join(desktop, fname)
        try:
            with open(rpath, "w", encoding="utf-8") as fp:
                fp.write("\n".join(lines))
            saved = f"Report saved to Desktop:\n{rpath}"
        except Exception as e:
            saved = f"Could not save report: {e}"

        self.pvar.set(100)
        self.slbl.config(text=f"  ✔  COMPLETE  ·  {saved.splitlines()[0]}")
        self.btn.config(state="normal",
                        text="  ██   R E D A C T   N O W  ",
                        bg=GLOW_C, fg="#000000")

        messagebox.showinfo("REDACT — Complete ✔",
            f"{'─'*42}\n"
            f"  FILES WIPED        {STATS.files:>10,}\n"
            f"  DATA REMOVED       {size_str:>10}\n"
            f"{'─'*42}\n"
            f"  Low sensitivity    {tier_files['LOW']:>8,} files\n"
            f"  Medium sensitivity {tier_files['MEDIUM']:>8,} files\n"
            f"  High sensitivity   {tier_files['HIGH']:>8,} files\n"
            f"{'─'*42}\n"
            f"  Standard : {ml}\n"
            f"{'─'*42}\n\n"
            f"  Registry backup:\n  {backup_folder}\n\n"
            f"{saved}")

if __name__ == "__main__":
    app = App()
    app.mainloop()
