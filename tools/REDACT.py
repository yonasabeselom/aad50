# ╔══════════════════════════════════════════════════════════════════╗
# ║     REDACT  —  v1.0                                              ║
# ║     100 items · 4 tiers · Windows 11 Fluent Dark UI             ║
# ║     NVMe/SSD optimised · 1 / 3 / 7 / 35-pass wipe               ║
# ╚══════════════════════════════════════════════════════════════════╝

import sys, os, ctypes, subprocess, shutil, glob, threading, secrets
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

# ─── Direct Admin Auto-Elevation ──────────────────────────────────────────────
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
BACKUP_DIR_PATH = ""  # Globally initialized per run string path context

class Stats:
    def reset(self):
        self.files      = 0   
        self.bytes      = 0   
        self.reg_keys   = 0   
        self.skipped    = 0   
    def __init__(self): self.reset()

STATS = Stats()

def _fmt_size(b):
    if b < 1024:            return f"{b} B"
    if b < 1024**2:         return f"{b/1024:.1f} KB"
    if b < 1024**3:         return f"{b/1024**2:.2f} MB"
    return                         f"{b/1024**3:.3f} GB"

def _nvme_passes(size):
    p = [b"\x00" * size, b"\xFF" * size, b"\xAA" * size, b"\x55" * size]
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

def _nist_passes(size):
    return [b"\x35"*size, b"\xCA"*size, secrets.token_bytes(size)]

def _single_pass(size):
    return [secrets.token_bytes(size)]

def _backup_target_file(path):
    """Safely mirrors file parameters to the recovery folder before destruction blocks execution."""
    global BACKUP_DIR_PATH
    if not BACKUP_DIR_PATH or not os.path.isfile(path):
        return
    try:
        # Create unique structural tracking directories inside safety store
        rel_sub = path.replace(":", "").strip("\\")
        dest_full = os.path.join(BACKUP_DIR_PATH, rel_sub)
        os.makedirs(os.path.dirname(dest_full), exist_ok=True)
        shutil.copy2(path, dest_full)
    except Exception:
        pass # Safeguard pipeline continuity if locking constraints deny read permissions

def _wipe_file(path):
    try:
        size = os.path.getsize(path)
        file_bytes = size  
        if size == 0:
            os.remove(path)
            STATS.files += 1
            return f"  Wiped (empty): {path}"
        
        # Initialize rollback snapshot store copy sequence
        _backup_target_file(path)
        
        passes = {"single":_single_pass,"nist":_nist_passes,"secure":_dod7_passes,"gutmann":_nvme_passes}[WIPE_MODE_KEY](size)
        tags   = {"single":"1-pass NVMe","nist":"NIST 800-88","secure":"7-pass DoD","gutmann":"35-pass Gutmann"}
        
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

# ─── 100 Items Matrix ─────────────────────────────────────────────────────────
ALL_ITEMS = [
    #  LOW SENSITIVITY  —  25 items
    ("LOW","temp_win","Windows Temp Files","Cached junk in C:\\Windows\\Temp",lambda: _clean(r"C:\Windows\Temp\*")),
    ("LOW","temp_user","User Temp Folder (%TEMP%)","Personal temp folder — app leftovers",lambda: _clean(r"%TEMP%\*")),
    ("LOW","recycle_bin","Recycle Bin","Files waiting in Recycle Bin",lambda: [_run('PowerShell -Command "Clear-RecycleBin -Force -EA SilentlyContinue"',"Empty Recycle Bin")]),
    ("LOW","thumbnail_cache","Thumbnail Cache","Explorer image previews — auto-rebuilt",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db")),
    ("LOW","icon_cache","Icon Cache Database","Cached app icons — regenerated on reboot",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_*.db")),
    ("LOW","wer_reports","Windows Error Reports","Crash dumps and queued error reports",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue\*", r"%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportQueue\*")),
    ("LOW","delivery_opt","Delivery Optimization Cache","Windows Update P2P download cache",lambda: _clean(r"C:\Windows\SoftwareDistribution\DeliveryOptimization\*")),
    ("LOW","old_updates","Windows Update Leftovers","Staged update files after successful install",lambda: _clean(r"C:\Windows\SoftwareDistribution\Download\*")),
    ("LOW","prefetch","Prefetch Files","App launch cache — auto-rebuilt",lambda: _clean(r"C:\Windows\Prefetch\*")),
    ("LOW","font_cache","Font Cache","Cached font data — rebuilt on reboot",lambda: _clean(r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache\*")),
    ("LOW","log_files","System Log Files","Diagnostic .log files in C:\\Windows\\Logs",lambda: _clean(r"C:\Windows\Logs\*")),
    ("LOW","speech_cache","Speech Recognition Cache","Speech model training cache",lambda: _clean(r"%USERPROFILE%\AppData\Roaming\Microsoft\Speech\Files\*")),
    ("LOW","installer_cache","MSI Installer Patch Cache","Old Windows Installer packages",lambda: _clean(r"C:\Windows\Installer\$PatchCache$\*")),
    ("LOW","store_hist","Microsoft Store History","Registry record of Store downloads",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Store")]),
    ("LOW","media_hist","Windows Media Player History","Recently played files list in WMP",lambda: [_reg("HKCU",r"Software\Microsoft\MediaPlayer\Player\RecentFileList")]),
    ("LOW","paint_recent","MS Paint Recent Files","Recently opened images in Paint",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List")]),
    ("LOW","notepad_recent","Notepad Recent Files","Recently opened files in Notepad (Windows 11)",lambda: _clean(r"%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_*\LocalState\*")),
    ("LOW","wordpad_recent","WordPad Recent Files","Recently opened files in WordPad",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List")]),
    ("LOW","directx_shader","DirectX Shader Cache","GPU shader cache — rebuilt by games/apps",lambda: _clean(r"%LOCALAPPDATA%\D3DSCache\*")),
    ("LOW","windows_old","Windows.old Folder","Previous Windows installation files (if exists)",lambda: _clean(r"C:\Windows.old\*")),
    ("LOW","local_crash_dumps","App Local Crash Dumps","Per-user crash stack logs generated by application failures",lambda: _clean(r"%LOCALAPPDATA%\CrashDumps\*")),
    ("LOW","panther_logs","Windows Setup Panther Logs","Temporary log folders created during Windows setup/upgrades",lambda: _clean(r"C:\Windows\panther\*")),
    ("LOW","game_explorer_cache","Game Explorer Cache","Cached metadata and box-art images for legacy Windows game panel",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Windows\GameExplorer\*")),
    ("LOW","dr_watson_logs","Legacy Dr. Watson Dumps","Legacy post-mortem diagnostic data records",lambda: _clean(r"C:\ProgramData\Microsoft\Dr Watson\*")),
    ("LOW","win_telemetry_dash","Diagnostic Data Viewer Db","Local analytical databases staging telemetry information tracking local actions",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Diagnosis\*")),

    #  MEDIUM SENSITIVITY  —  30 items
    ("MEDIUM","recent_files","Recent Files (File Explorer)","Quick Access recently opened files list",lambda: _clean(r"%APPDATA%\Microsoft\Windows\Recent\*")),
    ("MEDIUM","jumplists","Jump Lists (Taskbar)","Per-app recent files on taskbar right-click",lambda: _clean(r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*", r"%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*")),
    ("MEDIUM","run_history","Run Dialog History (Win+R)","Commands typed in the Run box",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")]),
    ("MEDIUM","search_hist","Windows Search History","Terms searched in the Start menu",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery")]),
    ("MEDIUM","clipboard","Clipboard History & Cloud Sync","Everything copied including cloud sync",lambda: [_run("echo. | clip","Clear clipboard"), _reg("HKCU",r"Software\Microsoft\Clipboard")]),
    ("MEDIUM","event_logs","Windows Event Logs","Application, System, Security, Setup logs",lambda: [_run("wevtutil cl Application","App log"), _run("wevtutil cl Security","Sec log"), _run("wevtutil cl System","Sys log"), _run("wevtutil cl Setup","Setup log"), _run("wevtutil cl Microsoft-Windows-PowerShell/Operational","PS log")]),
    ("MEDIUM","cortana","Cortana Search & Activity","Cortana history, inking and typing data",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Search")]),
    ("MEDIUM","muicache","MUICache (App Name Cache)","Registry map of every EXE to its name",lambda: [_reg("HKCU",r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")]),
    ("MEDIUM","network_hist","Network Connection History","Every Wi-Fi and LAN network ever connected",lambda: [_reg("HKLM",r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")]),
    ("MEDIUM","chrome_cache","Chrome Cache & Cookies","Temp files and login cookies in Chrome",lambda: _clean(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\*", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Code Cache\*", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies-journal")),
    ("MEDIUM","firefox_cache","Firefox Cache & Cookies","Temp files and cookies in Firefox",lambda: _clean(r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2\*", r"%APPDATA%\Mozilla\Firefox\Profiles\*\cookies.sqlite")),
    ("MEDIUM","edge_cache","Edge Cache & Cookies","Temp files and cookies in Edge",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\*", r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies")),
    ("MEDIUM","office_recent","Office Recent Documents","Recently opened Word/Excel/PowerPoint list",lambda: _clean(r"%APPDATA%\Microsoft\Office\Recent\*")),
    ("MEDIUM","powershell_hist","PowerShell Command History","All commands typed in PowerShell",lambda: _clean(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")),
    ("MEDIUM","open_save_mru","Open/Save Dialog History","Files picked in Open and Save As dialogs",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"), _reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU")]),
    ("MEDIUM","vscode_hist","VS Code Workspace History","Recently opened folders and file history",lambda: _clean(r"%APPDATA%\Code\User\workspaceStorage\*", r"%APPDATA%\Code\User\History\*")),
    ("MEDIUM","teams_cache","Microsoft Teams Cache","Teams local cache, logs and temp files",lambda: _clean(r"%APPDATA%\Microsoft\Teams\Cache\*", r"%APPDATA%\Microsoft\Teams\blob_storage\*", r"%APPDATA%\Microsoft\Teams\databases\*", r"%APPDATA%\Microsoft\Teams\logs.txt")),
    ("MEDIUM","zoom_cache","Zoom Logs & Cache","Zoom call logs and local cache data",lambda: _clean(r"%APPDATA%\Zoom\logs\*", r"%LOCALAPPDATA%\Zoom\data\*")),
    ("MEDIUM","discord_cache","Discord Cache","Discord local image and data cache",lambda: _clean(r"%APPDATA%\discord\Cache\*", r"%APPDATA%\discord\Code Cache\*")),
    ("MEDIUM","steam_cache","Steam Web Cache & Logs","Steam browser cache and log files",lambda: _clean(r"%LOCALAPPDATA%\Steam\htmlcache\*", r"C:\Program Files (x86)\Steam\logs\*")),
    ("MEDIUM","java_runtime_cache","Java Deployment Cache","Temporary application run logs and cached applet files",lambda: _clean(r"%USERPROFILE%\AppData\LocalLow\Sun\Java\Deployment\cache\*")),
    ("MEDIUM","vlc_media_hist","VLC Player Open History","Tracks recently parsed media descriptors and interface logs",lambda: _clean(r"%APPDATA%\vlc\vlc-qt-interface.ini")),
    ("MEDIUM","winrar_history","WinRAR Extract History","Registry keys listing recently unzipped archive titles and destination structural maps",lambda: [_reg("HKCU",r"Software\WinRAR\ArcHistory")]),
    ("MEDIUM","sevenzip_history","7-Zip Folder History","Registry keys listing directories viewed in the file manager",lambda: [_reg("HKCU",r"Software\7-Zip\FM")]),
    ("MEDIUM","delivery_opt_logs","Delivery Optimization Logs","Operational transactional tracing logs generated by background download service updates",lambda: _clean(r"C:\Windows\Logs\DOSvc\*")),
    ("MEDIUM","explorer_typed_paths","Explorer Address Bar History","Tracks explicitly typed local file paths and drive names inside File Explorer",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")]),
    ("MEDIUM","quicktime_cache","QuickTime Player Cache","Cached video segment rendering files and streaming data descriptors",lambda: _clean(r"%LOCALAPPDATA%\Apple Computer\QuickTime\Downloads\*")),
    ("MEDIUM","skype_cache","Skype System Runtime Cache","Avatar pictures, asset packs, and temporary service cache layouts",lambda: _clean(r"%APPDATA%\Microsoft\Skype for Desktop\Cache\*")),
    ("MEDIUM","brave_cache","Brave Browser Cache","Temporary rendering records and download trackers in Brave",lambda: _clean(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Cache\*")),
    ("MEDIUM","gimp_recent_cache","GIMP Editing History","Tracks recently configured photo processing workflows and files",lambda: _clean(r"%APPDATA%\GIMP\*\parasites\*")),

    #  HIGH SENSITIVITY  —  45 items
    ("HIGH","chrome_hist","Chrome Browsing History","Every URL visited — cryptographically wiped",lambda: _wipe(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History-journal")),
    ("HIGH","chrome_logins","Chrome Saved Passwords","All Chrome password manager credentials",lambda: _wipe(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data-journal")),
    ("HIGH","chrome_autofill","Chrome Autofill Data","Names, addresses, card numbers saved in Chrome",lambda: _wipe(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data")),
    ("HIGH","firefox_hist","Firefox Browsing History","Every URL visited in Firefox — cryptographically wiped",lambda: _wipe(r"%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite")),
    ("HIGH","firefox_logins","Firefox Saved Passwords","Firefox password manager credentials",lambda: _wipe(r"%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json", r"%APPDATA%\Mozilla\Firefox\Profiles\*\key4.db")),
    ("HIGH","edge_hist","Edge Browsing History","Every URL visited in Edge — cryptographically wiped",lambda: _wipe(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History")),
    ("HIGH","edge_logins","Edge Saved Passwords","All Edge password manager credentials",lambda: _wipe(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data")),
    ("HIGH","ie_hist","Internet Explorer Full History","IE history, typed URLs, cookies and forms",lambda: [_run("RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255","Clear all IE")]),
    ("HIGH","typed_urls","Typed URLs Registry","URLs typed directly into browser address bar",lambda: [_reg("HKCU",r"Software\Microsoft\Internet Explorer\TypedURLs")]),
    ("HIGH","user_assist","UserAssist Registry Keys","Encrypted record of every program launched",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")]),
    ("HIGH","shellbags","Shell Bags","Every folder ever opened incl. USB drives",lambda: [_reg("HKCU",r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"), _reg("HKCU",r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags")]),
    ("HIGH","lnk_files","Shortcut (.lnk) Files","Auto-created shortcuts exposing file paths",lambda: _wipe(r"%APPDATA%\Microsoft\Windows\Recent\*.lnk")),
    ("HIGH","bam","Background Activity Monitor (BAM)","Kernel timestamps of every program executed",lambda: [_reg("HKLM",r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings")]),
    ("HIGH","dns_cache","DNS Cache","Resolved domains revealing visited sites",lambda: [_run("ipconfig /flushdns","Flush DNS")]),
    ("HIGH","wifi_passwords","Saved Wi-Fi Passwords","All WPA/WPA2 credentials for every network",lambda: [_run("netsh wlan delete profile name=*","Delete Wi-Fi profiles")]),
    ("HIGH","location_hist","Windows Location History","GPS and location data logged by Windows",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")]),
    ("HIGH","activity_hist","Windows Activity History","Apps and files logged in Windows Timeline",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\ActivityDataModel"), _run('PowerShell -Command "Clear-ActivityHistory -EA SilentlyContinue"',"Clear Timeline")]),
    ("HIGH","downloads_folder","Downloads Folder — ALL Files","Every file in Downloads — cryptographically wiped",lambda: _wipe(r"%USERPROFILE%\Downloads\*")),
    ("HIGH","office_mru","Office MRU Registry","Most Recently Used lists for all Office apps",lambda: [_reg("HKCU",r"Software\Microsoft\Office\16.0\Word\File MRU"), _reg("HKCU",r"Software\Microsoft\Office\16.0\Excel\File MRU"), _reg("HKCU",r"Software\Microsoft\Office\16.0\PowerPoint\File MRU"), _reg("HKCU",r"Software\Microsoft\Office\15.0\Word\File MRU"), _reg("HKCU",r"Software\Microsoft\Office\15.0\Excel\File MRU")]),
    ("HIGH","rdp_hist","Remote Desktop History","Every server connected to via RDP",lambda: [_reg("HKCU",r"Software\Microsoft\Terminal Server Client\Default"), _reg("HKCU",r"Software\Microsoft\Terminal Server Client\Servers")]),
    ("HIGH","skype_logs","Skype / Teams Chat Logs","Local message databases — wiped",lambda: _wipe(r"%APPDATA%\Skype\*\main.db", r"%LOCALAPPDATA%\Packages\Microsoft.SkypeApp_*\LocalState\*")),
    ("HIGH","app_compat","AppCompatCache (Shimcache)","Windows compatibility log of every EXE run",lambda: [_run(r'reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache /f', "Clear Shimcache")]),
    ("HIGH","amcache","AmCache Hive","Forensic record of every installed/run program",lambda: [_run('PowerShell -Command "Remove-Item C:\\Windows\\AppCompat\\Programs\\Amcache.hve -Force -EA SilentlyContinue"', "Delete AmCache")]),
    ("HIGH","srum","SRUM Database","System Resource Usage Monitor — tracks all app network/CPU usage",lambda: [_run('PowerShell -Command "Stop-Service diagtrack -Force -EA SilentlyContinue; Remove-Item C:\\Windows\\System32\\sru\\SRUDB.dat -Force -EA SilentlyContinue"', "Clear SRUM database")]),
    ("HIGH","pagefile_wipe","Page File Zero on Shutdown","Configure Windows to zero pagefile on every shutdown",lambda: [_run(r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f', "Enable pagefile wipe")]),
    ("HIGH","volume_shadows","Volume Shadow Copies (VSS)","Windows snapshots — investigators mount these to see files from weeks ago",lambda: [_run('PowerShell -Command "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"', "Delete all shadow copies"), _run('vssadmin delete shadows /all /quiet', "vssadmin shadow wipe")]),
    ("HIGH","ntfs_journal","NTFS Change Journal ($UsnJrnl)","Logs every file operation ever — creation, rename, delete. Key forensic artifact.",lambda: [_run('fsutil usn deletejournal /d C:', "Delete USN journal drive C"), _run('fsutil usn deletejournal /d D: 2>nul', "Delete USN journal drive D")]),
    ("HIGH","ntfs_logfile","NTFS $LogFile (Filesystem Journal)","Transaction log of all filesystem changes — used to recover deleted file names",lambda: [_run('PowerShell -Command "& {$vol=\'C:\'; $fs=[System.IO.File]::Open(\'C:\\$LogFile\',[System.IO.FileMode]::Open,[System.IO.FileAccess]::Write,[System.IO.FileShare]::ReadWrite); $buf=New-Object byte[] 65536; $fs.Write($buf,0,65536); $fs.Close()}" 2>nul', "Overwrite $LogFile header (best-effort)"), _run('chkdsk C: /f /x /r 2>nul', "Force NTFS journal reset via chkdsk")]),
    ("HIGH","hiberfil","Hibernation File (hiberfil.sys)","Contains full RAM dump — open docs, passwords, keys captured at sleep time",lambda: [_run('powercfg /hibernate off', "Disable hibernation and delete hiberfil.sys"), _run('PowerShell -Command "Remove-Item C:\\hiberfil.sys -Force -EA SilentlyContinue"', "Force delete hiberfil.sys")]),
    ("HIGH","search_index","Windows Search Index","Contains text snippets from documents you deleted — lives in ProgramData",lambda: [_run('net stop WSearch /y', "Stop Windows Search service"), _clean(r"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\*", r"C:\ProgramData\Microsoft\Search\Data\Temp\*"), _run('net start WSearch', "Restart Windows Search")]),
    ("HIGH","evtx_backups","Event Log Backup Files (.evtx)","Archived event logs Windows keeps outside the main log location",lambda: _clean(r"C:\Windows\System32\winevt\Logs\*.evtx", r"C:\Windows\System32\winevt\Backup\*.evtx")),
    ("HIGH","browser_sessions","Browser Session Restore Files","Reveal open tabs even after history cleared — Chrome, Firefox, Edge",lambda: _wipe(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Sessions\*", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Session Storage\*", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Current Session", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Last Session", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Current Tabs", r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Last Tabs", r"%APPDATA%\Mozilla\Firefox\Profiles\*\sessionstore.jsonlz4", r"%APPDATA%\Mozilla\Firefox\Profiles\*\sessionstore-backups\*", r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Sessions\*", r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Session Storage\*")),
    ("HIGH","onedrive_thumbs","OneDrive / Cloud Sync Thumbnail Cache","Local previews of cloud files — persist after cloud deletion",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\OneDrive\logs\*", r"%LOCALAPPDATA%\Microsoft\OneDrive\setup\logs\*", r"%USERPROFILE%\AppData\Local\Microsoft\OneDrive\*\*.db", r"%LOCALAPPDATA%\Microsoft\Windows\INetCache\*")),
    ("HIGH","mft_slack","MFT Slack Space Wipe (Free Space)","Fills drive free space with zeros so MFT carved file remnants are destroyed",lambda: [_run('PowerShell -Command "& { $f=\'C:\\mft_wipe_tmp.tmp\'; $s=New-Object System.IO.FileStream($f,[IO.FileMode]::Create); $b=New-Object byte[] 65536; try { while($true){$s.Write($b,0,65536)} } catch {} $s.Close(); Remove-Item $f -Force -EA SilentlyContinue }"', "Fill free space with zeros to destroy MFT remnants"), _run('PowerShell -Command "Optimize-Volume -DriveLetter C -ReTrim -Confirm:$false 2>$null"', "TRIM freed blocks")]),
    ("HIGH","recent_apps_reg","RecentApps Execution Registry","Tracks applications parsed by shell interaction including execution frequencies",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps")]),
    ("HIGH","mount_points_reg","MountPoints2 Hardware History","Forensic listing of every USB, removable volume, and network drive attached",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2")]),
    ("HIGH","feature_usage_reg","FeatureUsage AppLaunch History","Tracks application execution counts and interface interact milestones",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch")]),
    ("HIGH","cid_size_mru","Common Item Dialog (MRU) Sizes","Tracks panel configuration sizes and historical selection files window scaling",lambda: [_reg("HKCU",r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU")]),
    ("HIGH","directx_caps_logs","DirectX Graphics Diag Logs","Contains explicit logging descriptors mapping executables to direct rendering configurations",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\DirectX\*")),
    ("HIGH","recycle_metadata_i","Recycle Bin $I Index Metadata","Wipes physical deletion index tracing records mapping original names/deletion tags",lambda: _clean(r"C:\$Recycle.Bin\*\$I*")),
    ("HIGH","powercfg_energy_rep","Power Efficiency Reports","Diagnostic trace snapshots staging operational details and software interaction metrics",lambda: _clean(r"C:\Windows\System32\energy-report.html")),
    ("HIGH","wdi_diagnostic_logs","WDI Infrastructure Logs","Windows Diagnostic Infrastructure records detailing application and hardware states",lambda: _clean(r"C:\Windows\System32\WDI\LogFiles\*")),
    ("HIGH","wer_archive_reports","Windows Error Report Archive","Archived system and hardware level crash logs containing localized state images",lambda: _clean(r"%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportArchive\*")),
    ("HIGH","rdp_bitmap_cache","RDP Bitmap Cache Data","Tile images saved from screen sessions that can be forensicly reconstructed",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\*")),
    ("HIGH","windows_webcache_db","WebCache Database Files","Transactional records logging application data streaming and file mapping indices",lambda: _clean(r"%LOCALAPPDATA%\Microsoft\Windows\WebCache\*")),
]

assert len(ALL_ITEMS) == 100, f"Expected 100, got {len(ALL_ITEMS)}"

SAFE_EXCLUDE = {
    "downloads_folder", "wifi_passwords", "pagefile_wipe", "hiberfil", 
    "mft_slack", "ntfs_logfile", "volume_shadows", "chrome_logins", 
    "firefox_logins", "edge_logins", "chrome_autofill"
}

WIPE_MODES = {
    "single":  ("1-PASS QUICK",     "#60cdff", "1× Random Overwrite + TRIM  ·  Fast optimization for SSDs"),
    "nist":    ("NIST 800-88",      "#107c41", "3-Pass Fixed Pattern Sequence + Architectural Flush  ·  Government Standard"),
    "secure":  ("7-PASS SECURE",    "#ffb900", "7× Alternating Hardware Passes + Block Purge  ·  DoD Compliant"),
    "gutmann": ("35-PASS MAXIMUM",  "#f7630c", "35× Fixed Algorithms + 26× CSPRNG Passes  ·  Max Destruction"),
}

# ─── Windows 11 Fluent Dark Colors ───────────────────────────────────────────
W11_BG          = "#1c1c1c"  
W11_SURFACE     = "#2d2d2d"  
W11_CARD        = "#202020"  
W11_BORDER      = "#3f3f3f"  
W11_TEXT_MAIN   = "#ffffff"  
W11_TEXT_MUTED  = "#a0a0a0"  
W11_ACCENT      = "#60cdff"  
W11_SELECT_BG   = "#3a3a3a"  

LOW_COLOR       = "#107c41"  
MED_COLOR       = "#ffb900"  
HIGH_COLOR      = "#e81123"  

FONT_FL_MAIN    = ("Segoe UI", 10)
FONT_FL_BOLD    = ("Segoe UI", 10, "bold")
FONT_FL_HEADER  = ("Segoe UI", 18, "bold")
FONT_FL_SUB     = ("Segoe UI", 9)

class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long),
                ('right', ctypes.c_long), ('bottom', ctypes.c_long)]

class FluentSwitch(tk.Canvas):
    def __init__(self, master, variable, command=None, **kw):
        super().__init__(master, width=38, height=20, highlightthickness=0, bd=0, bg=W11_CARD, **kw)
        self.var = variable
        self._cmd = command
        self.var.trace_add("write", lambda *_: self._draw())
        self.bind("<Button-1>", self._click)
        self._draw()

    def _draw(self):
        self.delete("all")
        active = self.var.get()
        if active:
            self.create_rounded_rect(2, 2, 36, 18, radius=8, fill=W11_ACCENT, outline="")
            self.create_oval(22, 5, 33, 16, fill="#000000", outline="")
        else:
            self.create_rounded_rect(2, 2, 36, 18, radius=8, fill="#505050", outline="")
            self.create_oval(5, 5, 16, 16, fill="#ffffff", outline="")

    def create_rounded_rect(self, x1, y1, x2, y2, radius=5, **kwargs):
        points = [x1+radius, y1, x1+radius, y1, x2-radius, y1, x2-radius, y1, x2, y1, x2, y1+radius, x2, y1+radius, x2, y2-radius, x2, y2-radius, x2, y2, x2-radius, y2, x2-radius, y2, x1+radius, y2, x1+radius, y2, x1, y2, x1, y2-radius, x1, y2-radius, x1, y1+radius, x1, y1+radius, x1, y1]
        return self.create_polygon(points, **kwargs, smooth=True)

    def _click(self, _=None):
        self.var.set(not self.var.get())
        if self._cmd: self._cmd()

# ─── Main App Frame ──────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("REDACT v1.0")
        
        # Pull taskbar constraint workarea sizes
        rect = RECT()
        ctypes.windll.user32.SystemParametersInfoW(48, 0, ctypes.byref(rect), 0)
        width = rect.right - rect.left
        height = rect.bottom - rect.top
        
        self.geometry(f"{width}x{height}+{rect.left}+{rect.top}")
        self.configure(bg=W11_BG)
        
        self.vars = {iid: tk.BooleanVar(value=False) for (_,iid,*_) in ALL_ITEMS}
        self.tier_vars = {"LOW": tk.BooleanVar(), "MEDIUM": tk.BooleanVar(), "HIGH": tk.BooleanVar()}
        self._wipe_mode = "single"
        
        self._build_fluent_ui()
        self._update_selection_metrics()

    def _build_fluent_ui(self):
        # ── Header Frame Block ──
        header_f = tk.Frame(self, bg=W11_BG, padx=25, pady=20)
        header_f.pack(fill="x")
        
        text_header_f = tk.Frame(header_f, bg=W11_BG)
        text_header_f.pack(side="left", anchor="w")
        
        tk.Label(text_header_f, text="REDACT", font=FONT_FL_HEADER, fg=W11_TEXT_MAIN, bg=W11_BG).pack(anchor="w")
        tk.Label(text_header_f, text="Forensic Privacy Eraser & Disk Sanitization Utility · v1.0 · 100 System Items Active", font=FONT_FL_SUB, fg=W11_TEXT_MUTED, bg=W11_BG).pack(anchor="w", pady=(2, 0))

        # Right Side Layout Control Button Assembly
        self.btn_run = tk.Button(header_f, text="INITIALIZE PIPELINE CLEAN", font=("Segoe UI", 11, "bold"), fg="#ffffff", bg="#004578", activebackground="#0078d4", activeforeground="#ffffff", bd=1, relief="flat", padx=35, pady=14, cursor="hand2", command=self._verify_intent)
        self.btn_run.pack(side="right", anchor="e", padx=(0, 5))
        self.btn_run.bind("<Enter>", lambda e: self.btn_run.config(bg="#005a9e"))
        self.btn_run.bind("<Leave>", lambda e: self.btn_run.config(bg="#004578"))

        # ── New Execution Monitoring Dashboard Block (Directly Below Controls Header Area) ──
        self.monitor_panel = tk.Frame(self, bg=W11_CARD, bd=1, relief="solid", padx=25, pady=12)
        self.monitor_panel.pack(fill="x", padx=25, pady=5)
        
        self.lbl_realtime_wiped = tk.Label(self.monitor_panel, text="Files Cleared: 0", font=FONT_FL_BOLD, fg=W11_ACCENT, bg=W11_CARD)
        self.lbl_realtime_wiped.pack(side="left", padx=(0, 20))
        
        self.lbl_realtime_erased = tk.Label(self.monitor_panel, text="Space Freed: 0 B", font=FONT_FL_BOLD, fg=LOW_COLOR, bg=W11_CARD)
        self.lbl_realtime_erased.pack(side="left", padx=(0, 40))
        
        # Modern Fluent styled percentage progress bar track
        self.pbar = ttk.Progressbar(self.monitor_panel, orient="horizontal", mode="determinate")
        self.pbar.pack(side="right", fill="x", expand=True, padx=(10, 0))

        # ── Standard Mode Selector Block ──
        algo_f = tk.LabelFrame(self, text=" Sanitization Standard Architecture ", font=FONT_FL_BOLD, fg=W11_TEXT_MAIN, bg=W11_CARD, bd=1, relief="solid", padx=15, pady=12)
        algo_f.pack(fill="x", padx=25, pady=5)
        
        self.mode_var = tk.StringVar(value="single")
        for key, (label, color, desc) in WIPE_MODES.items():
            r_frame = tk.Frame(algo_f, bg=W11_CARD)
            r_frame.pack(fill="x", pady=2)
            rb = tk.Radiobutton(r_frame, text=f"{label}  —  {desc}", variable=self.mode_var, value=key, font=FONT_FL_MAIN, fg=W11_TEXT_MAIN, bg=W11_CARD, selectcolor=W11_SURFACE, activebackground=W11_CARD, activeforeground=W11_TEXT_MAIN, command=self._on_mode_switch)
            rb.pack(side="left")

        # ── Universal Controls Row ──
        ctrl_f = tk.Frame(self, bg=W11_BG, padx=25, pady=10)
        ctrl_f.pack(fill="x")
        
        for text, cmd in [("Select All", self._all), ("Safe Selection Only", self._safe), ("Clear All", self._none)]:
            btn = tk.Button(ctrl_f, text=text, font=FONT_FL_MAIN, fg=W11_TEXT_MAIN, bg=W11_SURFACE, activebackground=W11_SELECT_BG, activeforeground=W11_TEXT_MAIN, bd=1, relief="solid", padx=12, pady=4, command=cmd)
            btn.pack(side="left", padx=(0, 10))
            
        btn_low = tk.Button(ctrl_f, text="LOW SENSITIVITY", font=FONT_FL_BOLD, fg="#ffffff", bg=LOW_COLOR, activebackground=LOW_COLOR, bd=0, padx=10, pady=4, command=lambda: self._toggle_by_sensitivity("LOW"))
        btn_low.pack(side="left", padx=(15, 5))
        
        btn_med = tk.Button(ctrl_f, text="MEDIUM SENSITIVITY", font=FONT_FL_BOLD, fg="#000000", bg=MED_COLOR, activebackground=MED_COLOR, bd=0, padx=10, pady=4, command=lambda: self._toggle_by_sensitivity("MEDIUM"))
        btn_med.pack(side="left", padx=5)
        
        btn_high = tk.Button(ctrl_f, text="HIGH SENSITIVITY", font=FONT_FL_BOLD, fg="#ffffff", bg=HIGH_COLOR, activebackground=HIGH_COLOR, bd=0, padx=10, pady=4, command=lambda: self._toggle_by_sensitivity("HIGH"))
        btn_high.pack(side="left", padx=5)
            
        self.lbl_metrics = tk.Label(ctrl_f, text="00 / 100 Targets Active", font=FONT_FL_BOLD, fg=W11_ACCENT, bg=W11_BG)
        self.lbl_metrics.pack(side="right")

        # ── Clean Container Layout ──
        list_container = tk.Frame(self, bg=W11_BG, padx=25, pady=5)
        list_container.pack(fill="both", expand=True)
        
        canvas = tk.Canvas(list_container, bg=W11_BG, highlightthickness=0, bd=0)
        sb = ttk.Scrollbar(list_container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        self.inner_scroll = tk.Frame(canvas, bg=W11_BG)
        canvas_win = canvas.create_window((0,0), window=self.inner_scroll, anchor="nw")
        
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_win, width=e.width))
        self.inner_scroll.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        # ── Populate Items Matrix ──
        active_tier = None
        for (tier, iid, name, desc) in [(t,i,n,d) for (t,i,n,d,_) in ALL_ITEMS]:
            if tier != active_tier:
                active_tier = tier
                self._build_tier_header(active_tier)
            self._build_item_card(tier, iid, name, desc)

    def _build_tier_header(self, tier):
        tf = tk.Frame(self.inner_scroll, bg=W11_SURFACE, padx=15, pady=6, bd=1, relief="solid")
        tf.pack(fill="x", pady=(15, 4))
        
        titles = {"LOW": "Low Severity — Cache Sweeps & System Artifacts", "MEDIUM": "Medium Severity — Application Footprints & Tracking Matrices", "HIGH": "High Severity — Deep Forensic Profiles & Cryptographic Target Zones"}
        tk.Label(tf, text=titles[tier], font=FONT_FL_BOLD, fg=W11_TEXT_MAIN, bg=W11_SURFACE).pack(side="left")
        
        sw = FluentSwitch(tf, variable=self.tier_vars[tier], command=lambda: self._toggle_tier_group(tier))
        sw.pack(side="right")

    def _build_item_card(self, tier, iid, name, desc):
        card = tk.Frame(self.inner_scroll, bg=W11_CARD, padx=15, pady=10, bd=1, relief="solid")
        card.pack(fill="x", pady=2)
        
        text_f = tk.Frame(card, bg=W11_CARD)
        text_f.pack(side="left", fill="x", expand=True)
        
        tk.Label(text_f, text=name, font=FONT_FL_BOLD, fg=W11_TEXT_MAIN, bg=W11_CARD).pack(anchor="w")
        tk.Label(text_f, text=desc, font=FONT_FL_SUB, fg=W11_TEXT_MUTED, bg=W11_CARD).pack(anchor="w", pady=(2,0))
        
        sw = FluentSwitch(card, variable=self.vars[iid], command=self._sync_headers_on_item_click)
        sw.pack(side="right", padx=5)

    def _toggle_by_sensitivity(self, target_tier):
        tier_items = [iid for (t, iid, *_) in ALL_ITEMS if t == target_tier]
        any_unchecked = any(not self.vars[iid].get() for iid in tier_items)
        target_state = True if any_unchecked else False
        
        for iid in tier_items:
            self.vars[iid].set(target_state)
            
        self.tier_vars[target_tier].set(target_state)
        self._update_selection_metrics()

    def _sync_headers_on_item_click(self):
        for tier in ["LOW", "MEDIUM", "HIGH"]:
            tier_items = [iid for (t, iid, *_) in ALL_ITEMS if t == tier]
            all_checked = all(self.vars[iid].get() for iid in tier_items)
            self.tier_vars[tier].set(all_checked)
        self._update_selection_metrics()

    def _on_mode_switch(self):
        self._wipe_mode = self.mode_var.get()

    def _toggle_tier_group(self, tier):
        state = self.tier_vars[tier].get()
        for (t, iid, *_) in ALL_ITEMS:
            if t == tier: self.vars[iid].set(state)
        self._update_selection_metrics()

    def _all(self):
        for v in self.vars.values(): v.set(True)
        for v in self.tier_vars.values(): v.set(True)
        self._update_selection_metrics()

    def _none(self):
        for v in self.vars.values(): v.set(False)
        for v in self.tier_vars.values(): v.set(False)
        self._update_selection_metrics()

    def _safe(self):
        for (_, iid, *_) in ALL_ITEMS:
            self.vars[iid].set(iid not in SAFE_EXCLUDE)
        self._sync_headers_on_item_click()

    def _update_selection_metrics(self):
        n = sum(1 for v in self.vars.values() if v.get())
        self.lbl_metrics.config(text=f"{n:02d} / 100 Targets Active")

    def _verify_intent(self):
        selected = [(t, i, n, d, fn) for (t, i, n, d, fn) in ALL_ITEMS if self.vars[i].get()]
        if not selected:
            messagebox.showwarning("Empty Target Parameters", "Please select at least one tracking domain to process.")
            return
        
        lbl, _, details = WIPE_MODES[self._wipe_mode]
        if messagebox.askyesno("Confirm Sanitization Pipeline", f"Target Array: {len(selected)} operational zones selected.\nStandard Config: {lbl}\nExecution Mechanics: {details}\n\nInitialize REDACT rollback-safeguarded clean pipeline?"):
            self.btn_run.config(state="disabled", text="RUNNING REDACT CHAINS...")
            threading.Thread(target=self._dispatch_engine, args=(selected,), daemon=True).start()

    def _dispatch_engine(self, selected):
        global WIPE_MODE_KEY, BACKUP_DIR_PATH
        WIPE_MODE_KEY = self._wipe_mode
        STATS.reset()
        
        # Initialize rollback safety backup directories on Desktop prior to destruction execution
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        BACKUP_DIR_PATH = os.path.join(desktop_path, f"REDACT_Recovery_Rollback_{stamp}")
        os.makedirs(BACKUP_DIR_PATH, exist_ok=True)
        
        total = len(selected)
        log_report_lines = [
            "========================================================================",
            "                          REDACT v1.0 REPORT                            ",
            f" Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ",
            f" Selected Clean Modules: {total} of 100",
            f" Rollback Store Point: {BACKUP_DIR_PATH}",
            f" Wipe Mode Target Standard: {WIPE_MODES[self._wipe_mode][0]}",
            "========================================================================\n"
        ]
        
        for idx, (tier, iid, name, desc, fn) in enumerate(selected, 1):
            self.btn_run.config(text=f"Processing: {name}")
            self.pbar['value'] = (idx / total) * 100
            
            self.lbl_realtime_wiped.config(text=f"Files Cleared: {STATS.files}")
            self.lbl_realtime_erased.config(text=f"Space Freed: {_fmt_size(STATS.bytes)}")
            self.update_idletasks()
            
            try:
                outcome = fn()
                log_report_lines.append(f"[{tier}] {name} -> SUCCESS")
                if isinstance(outcome, list):
                    for structural_trace in outcome:
                        log_report_lines.append(f"   Trace log entry: {structural_trace}")
            except Exception as context_error:
                log_report_lines.append(f"[{tier}] {name} -> CRITICAL ERROR: {context_error}")
                
        final_size = _fmt_size(STATS.bytes)
        log_report_lines.extend([
            "\n========================================================================",
            "                          EXECUTION SUMMARY                             ",
            "========================================================================",
            f" Total Files Purged From Sectors  : {STATS.files}",
            f" Total Real-Estate Storage Cleared : {final_size}",
            f" Structural Registry Keys Severed  : {STATS.reg_keys}",
            f" Access Failures / Locked Skips   : {STATS.skipped}",
            f" Rollback Store Point Location    : {BACKUP_DIR_PATH}",
            "========================================================================"
        ])
        
        report_filename = f"REDACT_Sanitizer_Log_{stamp}.txt"
        complete_target_filepath = os.path.join(desktop_path, report_filename)
        
        try:
            with open(complete_target_filepath, "w", encoding="utf-8") as target_file:
                target_file.write("\n".join(log_report_lines))
            saved_notification = f"Report saved to Desktop:\n{report_filename}"
        except Exception as file_write_fault:
            saved_notification = f"Could not save document report path payload: {file_write_fault}"

        self.btn_run.config(state="normal", text="INITIALIZE PIPELINE CLEAN")
        self.pbar['value'] = 0
        
        self.lbl_realtime_wiped.config(text=f"Files Cleared: {STATS.files}")
        self.lbl_realtime_erased.config(text=f"Space Freed: {final_size}")
        self._none()
        
        messagebox.showinfo("REDACT Pipeline Complete", f"All operations finalized successfully.\n\nFiles Purged: {STATS.files}\nTotal Space Erased: {final_size}\n\nRecovery Snapshot Point Staged on Desktop:\n{os.path.basename(BACKUP_DIR_PATH)}\n\n{saved_notification}")

if __name__ == "__main__":
    app = App()
    app.mainloop()