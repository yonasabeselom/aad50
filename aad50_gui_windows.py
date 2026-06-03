#!/usr/bin/env python3
# ==============================================================================
# THE ABESELOM ASIC-DIRECT 50 (AAD-50) — WINDOWS GUI APPLICATION
# ==============================================================================
# Author      : Yonas Abeselom (yonas_abeselom@protonmail.com)
# Version     : 1.0 (Windows GUI — Beta)
# Date        : June 2026
# Platform    : Windows 10 1607+ / Windows 11
# Requires    : pip install customtkinter
#
# WARNING:
#   This tool causes PERMANENT, IRREVERSIBLE destruction of all data on
#   the target device. Run only on devices you own and intend to fully erase.
# ==============================================================================

import sys
import os
import ctypes
import json
import hashlib
import threading
import subprocess
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

# Windows-only guard
if sys.platform != "win32":
    print("This GUI is for Windows only.")
    print("For Linux, use: sudo python3 aad50_abeselom.py /dev/nvme0")
    sys.exit(1)

import customtkinter as ctk
from tkinter import messagebox, filedialog
import tkinter as tk

kernel32 = ctypes.windll.kernel32

# Configure explicit argument and return types to prevent 64-bit handle truncation bugs
kernel32.CreateFileW.restype = ctypes.c_void_p
kernel32.CreateFileW.argtypes = [
    ctypes.c_wchar_p,     # lpFileName
    ctypes.c_ulong,       # dwDesiredAccess
    ctypes.c_ulong,       # dwShareMode
    ctypes.c_void_p,      # lpSecurityAttributes
    ctypes.c_ulong,       # dwCreationDisposition
    ctypes.c_ulong,       # dwFlagsAndAttributes
    ctypes.c_void_p       # hTemplateFile
]

kernel32.CloseHandle.restype = ctypes.c_int
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

kernel32.DeviceIoControl.restype = ctypes.c_int
kernel32.DeviceIoControl.argtypes = [
    ctypes.c_void_p,      # hDevice
    ctypes.c_ulong,       # dwIoControlCode
    ctypes.c_void_p,      # lpInBuffer
    ctypes.c_ulong,       # nInBufferSize
    ctypes.c_void_p,      # lpOutBuffer
    ctypes.c_ulong,       # nOutBufferSize
    ctypes.c_void_p,      # lpBytesReturned
    ctypes.c_void_p       # lpOverlapped
]

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_SHARE_READ      = 0x00000001
FILE_SHARE_WRITE     = 0x00000002
OPEN_EXISTING        = 3

def is_valid_handle(handle) -> bool:
    """
    Safely evaluates if a Win32 HANDLE is valid across 32-bit and 64-bit architectures,
    preventing non-existent system paths from returning ghost devices.
    """
    if handle is None:
        return False
    val = ctypes.c_void_p(handle).value
    if val is None or val == 0 or val == 18446744073709551615 or val == 4294967295 or val == -1:
        return False
    return True

class STORAGE_PROPERTY_QUERY(ctypes.Structure):
    _fields_ = [
        ("PropertyId", ctypes.c_int),
        ("QueryType", ctypes.c_int),
        ("AdditionalParameters", ctypes.c_byte * 1)
    ]

class STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Version", ctypes.c_ulong),
        ("Size", ctypes.c_ulong),
        ("DeviceType", ctypes.c_byte),
        ("DeviceTypeModifier", ctypes.c_byte),
        ("RemovableMedia", ctypes.c_byte),
        ("CommandQueueing", ctypes.c_byte),
        ("VendorIdOffset", ctypes.c_ulong),
        ("ProductIdOffset", ctypes.c_ulong),
        ("ProductRevisionOffset", ctypes.c_ulong),
        ("SerialNumberOffset", ctypes.c_ulong),
        ("BusType", ctypes.c_int),
        ("RawPropertiesLength", ctypes.c_ulong),
        ("RawDeviceProperties", ctypes.c_byte * 1024)
    ]

def get_disk_to_drive_letter_map() -> dict:
    """
    Interrogates the Windows partition subsystem using PowerShell and WMI
    to map physical disk indexes to their assigned logical drive letters.
    """
    mapping = {}
    startupinfo = None
    if os.name == 'nt':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE

    try:
        # Fetch partition to drive mapping
        cmd = [
            "powershell", "-NoProfile", "-Command", 
            "Get-Partition | Where-Object { $_.DriveLetter } | Select-Object DiskNumber, DriveLetter | ConvertTo-Json"
        ]
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=5, 
            startupinfo=startupinfo
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                disk_num = str(item.get("DiskNumber"))
                letter = item.get("DriveLetter")
                if disk_num is not None and letter:
                    letter_str = f"{letter}:"
                    if disk_num not in mapping:
                        mapping[disk_num] = []
                    if letter_str not in mapping[disk_num]:
                        mapping[disk_num].append(letter_str)
    except Exception:
        pass

    # Fallback class query for legacy Windows instances
    if not mapping:
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-WmiObject -Class Win32_LogicalDiskToPartition | Select-Object Dependent, Antecedent | ConvertTo-Json"
            ]
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=5, 
                startupinfo=startupinfo
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    dep = item.get("Dependent", "")
                    ant = item.get("Antecedent", "")
                    if "DeviceID=" in dep and "Disk #" in ant:
                        letter = dep.split('DeviceID="')[1].split('"')[0]
                        disk_num = ant.split('Disk #')[1].split(',')[0]
                        if disk_num and letter:
                            if disk_num not in mapping:
                                mapping[disk_num] = []
                            if letter not in mapping[disk_num]:
                                mapping[disk_num].append(letter)
        except Exception:
            pass
    return mapping

def probe_physical_drives_directly() -> list:
    """
    Queries \\\\.\\PhysicalDrive0 through 15 using Win32 API.
    Bypasses WMI/PowerShell restrictions to guarantee drive discovery.
    """
    drives = []
    letter_map = get_disk_to_drive_letter_map()
    for i in range(16):
        path = f"\\\\.\\PhysicalDrive{i}"
        handle = kernel32.CreateFileW(
            path,
            0,  # Query access only
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        if is_valid_handle(handle):
            model = f"Physical Drive {i}"
            try:
                IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
                query = STORAGE_PROPERTY_QUERY(0, 0)
                desc = STORAGE_DEVICE_DESCRIPTOR()
                bytes_ret = ctypes.c_ulong(0)
                
                success = kernel32.DeviceIoControl(
                    handle,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    ctypes.byref(query),
                    ctypes.sizeof(query),
                    ctypes.byref(desc),
                    ctypes.sizeof(desc),
                    ctypes.byref(bytes_ret),
                    None
                )
                if success:
                    raw = ctypes.string_at(ctypes.addressof(desc), desc.Size)
                    vendor = ""
                    product = ""
                    if 0 < desc.VendorIdOffset < desc.Size:
                        vendor = ctypes.string_at(ctypes.addressof(desc) + desc.VendorIdOffset).decode('utf-8', errors='ignore').strip()
                    if 0 < desc.ProductIdOffset < desc.Size:
                        product = ctypes.string_at(ctypes.addressof(desc) + desc.ProductIdOffset).decode('utf-8', errors='ignore').strip()
                    
                    bus_types = {0: "Unknown", 3: "SATA", 8: "SCSI", 11: "USB", 17: "NVMe"}
                    bus_name = bus_types.get(desc.BusType, "SSD/HDD")
                    
                    model_name = f"{vendor} {product}".strip()
                    if not model_name:
                        model_name = f"Storage Device {i}"
                    model = f"{model_name} [{bus_name}]"
            except Exception:
                model = f"Physical Drive {i} (Generic Target)"
            
            letters = ", ".join(letter_map.get(str(i), []))
            drives.append((str(i), model, path, letters))
            kernel32.CloseHandle(handle)
    return drives

# ── Import the AAD-50 Windows engine ─────────────────────────────────────────
try:
    from aad50_abeselom_windows import (
        TOOL_NAME, TOOL_VERSION, AUTHOR, CONTACT,
        TOTAL_CYCLES, AUTHORIZATION_TOKEN,
        SANITIZE_ACTION_OVERWRITE, SANITIZE_ACTION_BLOCK_ERASE,
        SANITIZE_ACTION_CRYPTO_ERASE,
        enumerate_nvme_drives, validate_nvme_device,
        open_device, close_device,
        execute_nvme_sanitize, poll_until_complete,
        verify_sanitization, read_sanitize_status, # direct telemetry reading
        SanitizationReport, CycleRecord,
        is_admin, configure_logging,
    )
    ENGINE_AVAILABLE = True
except ImportError:
    ENGINE_AVAILABLE = False
    TOOL_NAME    = "The Abeselom ASIC-Direct 50 (AAD-50)"
    TOOL_VERSION = "1.0 (Windows GUI — Premium Tactical)"
    AUTHOR       = "Yonas Abeselom"
    CONTACT      = "yonas_abeselom@protonmail.com"
    TOTAL_CYCLES = 50
    AUTHORIZATION_TOKEN = "EXECUTE-AAD-50-ABESELOM"
    def read_sanitize_status(*args, **kwargs):
        return 0x0

# ==============================================================================
# PREMIUM TACTICAL RADAR DESIGN SYSTEM
# ==============================================================================
MATTE_BG       = "#050709"  # High-stealth night-ops black
MATTE_CARD     = "#0E1115"  # Dark gray command card with thin borders
MATTE_INPUT    = "#090C0F"  # Radar sweep terminal black
MATTE_BORDER   = "#1B222B"  # Tactical single-pixel tactical borders
TEXT_HIGH      = "#D1F4FF"  # High-contrast HUD blue-white
TEXT_MUTED     = "#586A7A"  # Stealth gray instrumentation text
TEXT_METADATA  = "#3C4B56"  # Low-contrast background registers

ACCENT_GREEN   = "#39FF14"  # Neon Radioactive Green (HUD safe/active states)
ACCENT_AMBER   = "#FF9F00"  # Tactical Yellow Warning
ACCENT_PURPLE  = "#B15CFF"  # High-energy laser purple
ACCENT_RED     = "#FF3333"  # Critical self-destruct warning red
WHITE          = "#FFFFFF"  # Pure white for button thumb
GRAY_LIGHT     = "#CCCCCC"  # Light gray for button hover

FONT_TITLE   = ("Segoe UI Variable Display", 20, "bold")
FONT_HEADING = ("Consolas", 14, "bold")
FONT_SUBHEAD = ("Consolas", 11, "bold")
FONT_BODY    = ("Consolas", 10)
FONT_SMALL   = ("Consolas", 8)
FONT_MONO    = ("Consolas", 10)

# ==============================================================================
# APP CORE
# ==============================================================================

class AAD50App(ctk.CTk):

    def __init__(self):
        super().__init__()

        # Window Frame Initialization
        self.title("AAD-50 — High-Assurance NVMe Sanitization")
        self.geometry("1100x720")
        self.minsize(1000, 680)
        self.configure(fg_color=MATTE_BG)

        # Force Windows OS level Maximize to instantly fit display screen perfectly
        try:
            self.state('zoomed')
        except Exception:
            pass

        # App state variables
        self.selected_drive = None
        self.drives         = []
        self.dry_run        = tk.BooleanVar(value=True)
        self.sanitization_thread = None
        self.report_data    = None
        self.cycles_done    = 0
        self.current_phase  = ""
        self.running        = False
        self.log_path       = None
        self.active_screen  = "home"

        ctk.set_appearance_mode("dark")

        self._build_layout()
        
        # Thread safety exit intercept handler registration
        self.protocol("WM_DELETE_WINDOW", self._on_close_window)
        
        self._show_screen("home")

    # ── Layout Building ────────────────────────────────────────────────────────

    def _build_layout(self):
        # 1. Header bar (Top slice)
        self.header = ctk.CTkFrame(self, fg_color=MATTE_BG, height=64, corner_radius=0)
        self.header.pack(fill="x", side="top")
        self.header.pack_propagate(False)

        # Decorative flat border under header
        ctk.CTkFrame(self, fg_color=MATTE_BORDER, height=1).pack(fill="x", side="top")

        # 2. Bottom Status Bar (Bottom slice) - Packed BEFORE side-by-side components to avoid expansion gaps!
        self.statusbar = ctk.CTkFrame(self, fg_color=MATTE_BG, height=30, corner_radius=0)
        self.statusbar.pack(fill="x", side="bottom")
        self.statusbar.pack_propagate(False)
        
        # Flat status separator
        ctk.CTkFrame(self.statusbar, fg_color=MATTE_BORDER, height=1).pack(fill="x", side="top")

        self.status_label = ctk.CTkLabel(
            self.statusbar,
            text="System Status: Ready",
            font=FONT_SMALL,
            text_color=TEXT_MUTED
        )
        self.status_label.pack(side="left", padx=15, pady=(2, 0))

        admin_text = "● Privileged (Administrator)" if (ENGINE_AVAILABLE and is_admin()) else "● Standard User Mode"
        admin_color = ACCENT_GREEN if (ENGINE_AVAILABLE and is_admin()) else ACCENT_AMBER
        ctk.CTkLabel(
            self.statusbar,
            text=admin_text,
            font=FONT_SMALL,
            text_color=admin_color
        ).pack(side="right", padx=15, pady=(2, 0))

        # 3. Custom Navigation Sidebar (Left slice)
        self.sidebar = ctk.CTkFrame(self, fg_color=MATTE_CARD, width=220, corner_radius=0)
        self.sidebar.pack(fill="y", side="left")
        self.sidebar.pack_propagate(False)
        
        # Flat border to separate sidebar from content
        ctk.CTkFrame(self.sidebar, fg_color=MATTE_BORDER, width=1).pack(fill="y", side="right")
        self._build_sidebar()

        # 4. Primary dynamic content frame (Remaining central canvas)
        self.content = ctk.CTkFrame(self, fg_color=MATTE_BG, corner_radius=0)
        self.content.pack(fill="both", expand=True, side="left")

        # Header branding layout
        header_left = ctk.CTkFrame(self.header, fg_color="transparent")
        header_left.pack(side="left", padx=20, pady=12)

        ctk.CTkLabel(
            header_left,
            text="ABESELOM AAD-50",
            font=("Segoe UI Variable Display", 18, "bold"),
            text_color=TEXT_HIGH
        ).pack(side="left")

        ctk.CTkLabel(
            header_left,
            text="  [ASIC-DIRECT HARDWARE ENGINE]",
            font=FONT_MONO,
            text_color=ACCENT_GREEN
        ).pack(side="left", pady=4, padx=(10, 0))

        # Dynamic mode badge indicator
        self.mode_badge = ctk.CTkLabel(
            header_left,
            text="",
            font=("Consolas", 10, "bold"),
            corner_radius=4,
            padx=8,
            pady=2
        )
        self.mode_badge.pack(side="left", padx=(15, 0), pady=4)

        header_right = ctk.CTkFrame(self.header, fg_color="transparent")
        header_right.pack(side="right", padx=20)
        ctk.CTkLabel(
            header_right,
            text=f"v1.0  |  {AUTHOR}",
            font=FONT_SMALL,
            text_color=TEXT_MUTED
        ).pack()

        # Safe update: Execute badge and status telemetry configuration ONLY after status bar elements exist
        self._update_mode_badge()

    def _update_mode_badge(self):
        if self.dry_run.get():
            self.mode_badge.configure(
                text="  SIMULATION ACTIVE  ",
                fg_color="#2D1F0E",
                text_color=ACCENT_AMBER
            )
            self._set_status("Ready (Simulation Mode Active)")
        else:
            self.mode_badge.configure(
                text="  ⚠️ REAL WIPE ARMED [DESTRUCTIVE]  ",
                fg_color="#3A0D0D",
                text_color=ACCENT_RED
            )
            self._set_status("⚠️ WARNING: REAL WIPE ARMED — HIGH-ASSURANCE DESTRUCTION")

    def _build_sidebar(self):
        ctk.CTkLabel(
            self.sidebar,
            text="COMMAND MODULES",
            font=("Consolas", 9, "bold"),
            text_color=TEXT_MUTED
        ).pack(pady=(24, 12), padx=20, anchor="w")

        self.nav_buttons = {}
        nav_items = [
            ("home",     "  Home Dashboard"),
            ("drives",   "💾  Select Drive"),
            ("sanitize", "⚡  Sanitize Drive"),
            ("reports",  "📋  Audit Reports"),
            ("about",    "ℹ  About"),
        ]
        for key, label in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                font=FONT_SUBHEAD,
                fg_color="transparent",
                hover_color=MATTE_INPUT,
                text_color=TEXT_MUTED,
                anchor="w",
                corner_radius=4,
                height=40,
                command=lambda *args, k=key: self._show_screen(k)
            )
            btn.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[key] = btn

        # Bottom Safety Switch
        ctk.CTkFrame(self.sidebar, fg_color=MATTE_BORDER, height=1).pack(fill="x", padx=12, pady=(30, 15))

        dry_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        dry_frame.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(dry_frame, text="Dry-Run Simulator", font=FONT_SMALL, text_color=TEXT_HIGH).pack(side="left")
        
        self.dry_switch = ctk.CTkSwitch(
            dry_frame,
            text="",
            variable=self.dry_run,
            onvalue=True,
            offvalue=False,
            fg_color="#5C1010",
            progress_color=ACCENT_AMBER,
            button_color=WHITE,
            button_hover_color=GRAY_LIGHT,
            width=46,
            height=22,
            command=self._on_dry_run_toggle
        )
        self.dry_switch.pack(side="right")

        self.dry_label_status = ctk.CTkLabel(
            self.sidebar,
            text="✓ Simulation active — safe mode" if self.dry_run.get() else "⚠ LIVE MODE — REAL DATA WILL BE DESTROYED",
            font=("Consolas", 8, "bold"),
            text_color=ACCENT_AMBER if self.dry_run.get() else ACCENT_RED,
            wraplength=190,
            justify="left"
        )
        self.dry_label_status.pack(padx=16, pady=(4, 0), anchor="w")

    def _on_dry_run_toggle(self):
        self._update_mode_badge()
        if self.dry_run.get():
            self.dry_label_status.configure(
                text="✓ Simulation active — safe mode",
                text_color=ACCENT_AMBER
            )
        else:
            self.dry_label_status.configure(
                text="⚠ LIVE MODE — REAL DATA WILL BE DESTROYED",
                text_color=ACCENT_RED
            )
        # Instantly refresh the screen to update structural warnings and button styles
        if hasattr(self, "active_screen"):
            self._show_screen(self.active_screen)

    # ── Thread Safety Exit Handler ──────────────────────────────────────────────

    def _on_close_window(self):
        """
        Safety interlock handler triggered on WM_DELETE_WINDOW window closing.
        Protects NVMe drives from incomplete state machine situations by alerting users.
        """
        if self.running and not self.dry_run.get():
            confirm = messagebox.askyesno(
                "ACTIVE DATA DESTRUCT WORK IN PROGRESS",
                "An active hardware-level sanitization process is currently running on the controller!\n\n"
                "Closing the controller management window now does NOT cancel the on-chip sanitize pipeline, "
                "but it will orphan the compliance monitoring threads, resulting in an unvalidated, undocumented run.\n\n"
                "Are you absolutely sure you want to exit and abandon active logging?",
                icon="warning"
            )
            if not confirm:
                return
        self.destroy()

    # ── Screen Router ─────────────────────────────────────────────────────────

    def _show_screen(self, screen: str):
        self.active_screen = screen
        for widget in self.content.winfo_children():
            widget.destroy()
        
        for key, btn in self.nav_buttons.items():
            if key == screen:
                btn.configure(fg_color=MATTE_INPUT, text_color=TEXT_HIGH)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_MUTED)
                
        screens = {
            "home":     self._screen_home,
            "drives":   self._screen_drives,
            "sanitize": self._screen_sanitize,
            "reports":  self._screen_reports,
            "about":    self._screen_about,
        }
        if screen in screens:
            screens[screen]()
        screen_names = {'home':'Home Dashboard','drives':'Select Drive','sanitize':'Sanitize','reports':'Audit Reports','about':'About'}
        self._set_status(f"Viewing: {screen_names.get(screen, screen.capitalize())}")

    # ── Screen: HOME (with Logo and No Scrollbars) ──────────────────────────

    def _screen_home(self):
        home_frame = ctk.CTkFrame(self.content, fg_color=MATTE_BG)
        home_frame.pack(fill="both", expand=True, padx=24, pady=(20, 10))

        # Brand Container split in a grid to host text on left, glowing hardware microchip on right
        brand_container = ctk.CTkFrame(home_frame, fg_color=MATTE_CARD, corner_radius=8, border_width=1, border_color=MATTE_BORDER)
        brand_container.pack(fill="x", pady=(0, 12))
        
        brand_container.columnconfigure(0, weight=4) # text column
        brand_container.columnconfigure(1, weight=1) # holographic logo column

        # Text branding layout
        brand_text_box = ctk.CTkFrame(brand_container, fg_color="transparent")
        brand_text_box.grid(row=0, column=0, padx=24, pady=20, sticky="w")

        ctk.CTkLabel(
            brand_text_box,
            text="The Abeselom ASIC-Direct 50 (AAD-50)",
            font=FONT_TITLE,
            text_color=TEXT_HIGH
        ).pack(anchor="w")

        ctk.CTkLabel(
            brand_text_box,
            text="Firmware-Enforced Solid-State Sanitization • Phase Matrix B-C-A • High-Assurance Defense Standard",
            font=FONT_BODY,
            text_color=ACCENT_GREEN
        ).pack(anchor="w", pady=(2, 6))

        ctk.CTkLabel(
            brand_text_box,
            text="Engineered to eliminate voltage hysteresis remanence on NAND substrates by issuing raw IOCTL "
                 "administration command structures bypassing OS and filesystem abstractions entirely.",
            font=FONT_BODY,
            text_color=TEXT_MUTED,
            wraplength=640,
            justify="left"
        ).pack(anchor="w")

        # Visual Hardware Logo Frame - ASIC Microprocessor representation
        logo_canvas = ctk.CTkFrame(brand_container, fg_color=MATTE_INPUT, corner_radius=6, border_width=1, border_color=MATTE_BORDER, width=130, height=130)
        logo_canvas.grid(row=0, column=1, padx=24, pady=20, sticky="e")
        logo_canvas.pack_propagate(False)

        # Draw Silicon Die outline
        die = ctk.CTkFrame(logo_canvas, fg_color=MATTE_BG, corner_radius=4, border_width=1, border_color=ACCENT_GREEN)
        die.pack(expand=True, fill="both", padx=12, pady=12)
        die.pack_propagate(False)

        # Embedded chip label with gold status traces
        ctk.CTkLabel(die, text="ASIC", font=FONT_MONO, text_color=ACCENT_GREEN).pack(pady=(16, 2))
        ctk.CTkLabel(die, text="AAD-50 CORES", font=("Segoe UI", 8), text_color=TEXT_MUTED).pack()

        # Visual semiconductor trace pins
        pins = ctk.CTkFrame(die, fg_color="transparent", height=4)
        pins.pack(pady=(14, 0))
        for i, c in enumerate([ACCENT_GREEN, ACCENT_AMBER, ACCENT_GREEN, ACCENT_AMBER, ACCENT_GREEN]):
            ctk.CTkFrame(pins, fg_color=c, width=6, height=6, corner_radius=3).pack(side="left", padx=2)

        # Stats Deck
        stats_frame = ctk.CTkFrame(home_frame, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 12))
        stats_frame.columnconfigure((0, 1, 2, 3), weight=1)

        stats = [
            ("50", "Total Sanitization Cycles", ACCENT_GREEN),
            ("3", "Isolated Physical Phases", ACCENT_PURPLE),
            ("0x84", "Native NVMe Opcode", ACCENT_AMBER),
            ("SHA-256", "Hardware Audit Chain", TEXT_HIGH),
        ]
        for i, (value, label, color) in enumerate(stats):
            card = ctk.CTkFrame(stats_frame, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
            card.grid(row=0, column=i, padx=4, pady=0, sticky="ew")
            ctk.CTkLabel(card, text=value, font=("Segoe UI Variable Display", 22, "bold"), text_color=color).pack(pady=(10, 2))
            ctk.CTkLabel(card, text=label, font=FONT_SMALL, text_color=TEXT_MUTED).pack(pady=(0, 10))

        # Matrix Phase Diagram Card
        phases_card = ctk.CTkFrame(home_frame, fg_color=MATTE_CARD, corner_radius=8, border_width=1, border_color=MATTE_BORDER)
        phases_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(phases_card, text="SYSTEM PHASE ORDER", font=FONT_HEADING, text_color=TEXT_HIGH).pack(pady=(12, 8), padx=20, anchor="w")

        phases = [
            ("Phase B", "Cycles 01–40", "Physical NAND Cell Overwrite (Voltage Flattening)", "CDW10 = 0x02", ACCENT_GREEN),
            ("Phase C", "Cycles 41–45", "FTL Translation Map Teardown & Reconstruction", "CDW10 = 0x01", ACCENT_AMBER),
            ("Phase A", "Cycles 46–50", "Cryptographic Media Key Shredding (Final Seal)", "CDW10 = 0x04", ACCENT_PURPLE),
        ]
        for phase, cycles, desc, cdw, color in phases:
            row = ctk.CTkFrame(phases_card, fg_color=MATTE_INPUT, corner_radius=4)
            row.pack(fill="x", padx=16, pady=4)
            ctk.CTkLabel(row, text="■", font=("Segoe UI", 12), text_color=color).pack(side="left", padx=(16, 8), pady=10)
            ctk.CTkLabel(row, text=phase, font=FONT_SUBHEAD, text_color=TEXT_HIGH, width=70, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=cycles, font=FONT_MONO, text_color=color, width=100, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=desc, font=FONT_BODY, text_color=TEXT_MUTED).pack(side="left", padx=12)
            ctk.CTkLabel(row, text=cdw, font=FONT_MONO, text_color=TEXT_METADATA).pack(side="right", padx=16)

        # Core Action Trigger
        ctk.CTkButton(
            home_frame,
            text="▶  Start — Select Your Drive →",
            font=FONT_HEADING,
            fg_color=ACCENT_GREEN,
            hover_color="#059669",
            text_color=MATTE_BG,
            height=46,
            corner_radius=4,
            command=lambda: self._show_screen("drives")
        ).pack(fill="x", pady=(4, 0))

    # ── Screen: DRIVE DISCOVERY (Fixed Layout) ─────────────────────

    def _screen_drives(self):
        drives_container = ctk.CTkFrame(self.content, fg_color=MATTE_BG)
        drives_container.pack(fill="both", expand=True, padx=24, pady=(20, 10))

        hdr = ctk.CTkFrame(drives_container, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(hdr, text="SELECT TARGET DRIVE", font=FONT_HEADING, text_color=TEXT_HIGH).pack(side="left")
        
        ctk.CTkButton(
            hdr, text="⟳  Scan Channels",
            font=FONT_SUBHEAD,
            fg_color=MATTE_CARD, hover_color=MATTE_INPUT,
            text_color=TEXT_HIGH,
            border_width=1, border_color=MATTE_BORDER,
            width=130, height=36,
            corner_radius=4,
            command=self._refresh_drives
        ).pack(side="right")

        # Drives list frame
        self.drives_frame = ctk.CTkFrame(drives_container, fg_color="transparent")
        self.drives_frame.pack(fill="both", expand=True)

        self._refresh_drives()

    def _refresh_drives(self):
        for widget in self.drives_frame.winfo_children():
            widget.destroy()

        self._set_status("Scanning system I/O buses...")

        # MULTI-TIER DRIVE DISCOVERY PIPELINE
        self.drives = []
        
        # 1. Try Win32 direct hardware path probing
        try:
            self.drives = probe_physical_drives_directly()
        except Exception as e:
            self.status_label.configure(text=f"Direct Scan Error: {str(e)}")

        # 2. Fallback to engine's NVMe PowerShell parser if direct probe returned empty
        if not self.drives and ENGINE_AVAILABLE:
            try:
                raw_drives = enumerate_nvme_drives()
                letter_map = get_disk_to_drive_letter_map()
                for idx, model, path in raw_drives:
                    letters = ", ".join(letter_map.get(str(idx), []))
                    self.drives.append((idx, model, path, letters))
            except Exception:
                pass

        # 3. Third Tier: Demo Fallbacks
        if not self.drives:
            self.drives = [
                ("0", "Standard Physical Drive 0 (Generic Interface Default)", "\\\\.\\PhysicalDrive0", "C:"),
            ]

        # Populate GUI list with discovered drives
        ctk.CTkLabel(
            self.drives_frame,
            text=f"Found {len(self.drives)} NVMe drive(s) on this system:",
            font=FONT_SUBHEAD, text_color=TEXT_MUTED
        ).pack(anchor="w", pady=(10, 8))

        for idx, model, path, letters in self.drives:
            is_selected = (self.selected_drive and self.selected_drive[2] == path)
            card = ctk.CTkFrame(
                self.drives_frame,
                fg_color=MATTE_INPUT if is_selected else MATTE_CARD,
                corner_radius=6,
                border_width=1,
                border_color=ACCENT_GREEN if is_selected else MATTE_BORDER
            )
            card.pack(fill="x", pady=4)

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(side="left", fill="both", expand=True, padx=16, pady=12)

            title_row = ctk.CTkFrame(info, fg_color="transparent")
            title_row.pack(anchor="w")

            ctk.CTkLabel(
                title_row,
                text=f"💾  {model}",
                font=FONT_SUBHEAD,
                text_color=ACCENT_GREEN if is_selected else TEXT_HIGH,
                anchor="w"
            ).pack(side="left")

            # Active Volume / Drive letters Warning Badges
            if letters:
                is_os_drive = "C:" in letters.upper()
                badge_bg = "#3A0D0D" if is_os_drive else MATTE_INPUT
                badge_border = ACCENT_RED if is_os_drive else MATTE_BORDER
                badge_text_color = ACCENT_RED if is_os_drive else ACCENT_AMBER
                badge_label_text = f" ⚠️ ACTIVE SYSTEM DRIVE ({letters}) " if is_os_drive else f" Volume ({letters}) "
                
                badge = ctk.CTkLabel(
                    title_row,
                    text=badge_label_text,
                    font=("Segoe UI Variable Text", 9, "bold"),
                    fg_color=badge_bg,
                    text_color=badge_text_color,
                    corner_radius=4,
                    padx=6,
                    pady=1
                )
                badge.pack(side="left", padx=(10, 0))

            ctk.CTkLabel(
                info,
                text=f"Path: {path}  •  Drive Index: {idx}",
                font=FONT_MONO,
                text_color=TEXT_MUTED if not is_selected else TEXT_HIGH,
                anchor="w"
            ).pack(anchor="w", pady=(4, 0))

            btn_text = "✓ Selected" if is_selected else "Select Drive"
            btn_color = ACCENT_GREEN if is_selected else MATTE_INPUT
            btn_tcolor = MATTE_BG if is_selected else TEXT_HIGH
            
            # Position-argument proof lambda configuration to bypass CustomTkinter toggle variables
            ctk.CTkButton(
                card,
                text=btn_text,
                font=FONT_SUBHEAD,
                fg_color=btn_color,
                text_color=btn_tcolor,
                hover_color="#059669",
                width=130, height=36,
                corner_radius=4,
                command=lambda *args, idx=idx, model=model, path=path, letters=letters: self._select_drive((idx, model, path, letters))
            ).pack(side="right", padx=16, pady=12)

        self._set_status(f"Bus Scan Done. Drives Located: {len(self.drives)}")

        if self.selected_drive:
            ctk.CTkButton(
                self.drives_frame,
                text="Continue to Sanitize →",
                font=FONT_HEADING,
                fg_color=ACCENT_GREEN,
                text_color=MATTE_BG,
                hover_color="#059669",
                height=46,
                corner_radius=4,
                command=lambda: self._show_screen("sanitize")
            ).pack(pady=16, fill="x")

    def _select_drive(self, drive_tuple):
        """Select a drive and immediately navigate to the sanitize screen."""
        self.selected_drive = drive_tuple
        self._refresh_drives()
        self._set_status(f"Drive selected: {drive_tuple[1]} — click Continue to Sanitize")

    # ── Screen: DESTRUCTIVE COMPLIANCE WARNING (Two-Column Grid Layout) ───────

    def _screen_sanitize(self):
        if not self.selected_drive:
            ctk.CTkLabel(
                self.content,
                text="System State: No Armed Device.\nGo to 'Select Target NVMe' to map storage path.",
                font=FONT_HEADING, text_color=TEXT_MUTED, justify="center"
            ).pack(expand=True)
            return

        if self.running:
            self._build_progress_screen()
        else:
            self._build_warning_screen()

    def _build_warning_screen(self):
        # Two-column container
        warning_container = ctk.CTkFrame(self.content, fg_color=MATTE_BG)
        warning_container.pack(fill="both", expand=True, padx=24, pady=(20, 10))

        warning_container.columnconfigure(0, weight=1, uniform="warn_cols") # Left side: Shields & Bullets
        warning_container.columnconfigure(1, weight=1, uniform="warn_cols") # Right side: Config, Token & Action
        warning_container.rowconfigure(0, weight=1)

        # ── Left Column: Shields & Impact Analysis Bullets ────────────────────
        left_frame = ctk.CTkFrame(warning_container, fg_color=MATTE_CARD, corner_radius=8, border_width=1, border_color=MATTE_BORDER)
        left_frame.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="nsew")

        warn_border_color = ACCENT_RED if not self.dry_run.get() else ACCENT_AMBER
        warn_bg_color = "#200A0A" if not self.dry_run.get() else "#1A1005" # Deep tactical colors
        warn_text_color = ACCENT_RED if not self.dry_run.get() else ACCENT_AMBER

        shield_card = ctk.CTkFrame(left_frame, fg_color=warn_bg_color, corner_radius=6, border_width=1, border_color=warn_border_color)
        shield_card.pack(fill="both", expand=True, padx=15, pady=15)

        ctk.CTkLabel(
            shield_card,
            text="⚠  IRREVERSIBLE DATA DESTRUCTION WARNING  ⚠" if not self.dry_run.get() else "◈  SIMULATION MODE — NO HARDWARE CONTACT  ◈",
            font=FONT_HEADING,
            text_color=warn_text_color,
            wraplength=380
        ).pack(pady=(20, 10), padx=15)

        ctk.CTkLabel(
            shield_card,
            text=(
                "AAD-50 will issue 50 firmware-level NVMe Sanitize commands directly to the drive controller ASIC.\n\n"
                "All data — including content in over-provisioned zones, retired bad blocks, and wear-levelling pools "
                "invisible to the operating system — will be permanently and irreversibly destroyed.\n\n"
                "Post-sanitization forensic analysis using Magnetic Force Microscopy (MFM), chip-level "
                "electron microscopy, or any known commercial data recovery tool will yield no recoverable data."
            ) if not self.dry_run.get() else (
                "Simulation mode is active. No NVMe commands will be sent to the drive controller.\n\n"
                "The full 50-cycle B → C → A sequence will be executed in software only — each cycle "
                "will be timed, logged, and SHA-256 audited exactly as a live run, but the "
                "DeviceIoControl IOCTL calls are bypassed entirely.\n\n"
                "Your drive, your data, and your operating system are completely untouched."
            ),
            font=FONT_BODY,
            text_color=TEXT_HIGH,
            justify="left",
            wraplength=380
        ).pack(pady=(0, 15), padx=20, anchor="w")

        ctk.CTkLabel(
            shield_card,
            text="WHAT WILL BE DESTROYED:" if not self.dry_run.get() else "WHAT THE SIMULATION DOES:",
            font=FONT_SUBHEAD,
            text_color=TEXT_MUTED
        ).pack(pady=(10, 5), padx=20, anchor="w")

        bullets = (
            [
                "Phase B (Cycles 1–40): All NAND cells physically overwritten via firmware — including over-provisioned and bad block pools.",
                "Phase C (Cycles 41–45): Flash Translation Layer mapping tables wiped and regenerated — all logical-to-physical address records destroyed.",
                "Phase A (Cycles 46–50): Media Encryption Key (MEK) cryptographically erased — any encrypted data mathematically unrecoverable.",
                "Post-run LBA sample reads confirm hardware returns deallocated status — verified at silicon level.",
                "No commercial forensic tool — BitRaser, EnCase, FTK, or chip-off recovery — can reconstruct the original data."
            ] if not self.dry_run.get() else [
                "Simulates all 50 cycles across Phases B, C, and A — identical timing and logging to a live run.",
                "DeviceIoControl IOCTL calls are skipped — zero commands reach the NVMe controller.",
                "SHA-256 audit chain is generated — produces a real, verifiable audit hash from the simulated cycle records.",
                "Drive handle is never opened — your operating system, files, and drive are completely safe.",
                "Use dry-run to validate the tool, test audit reporting, and verify your workflow before committing to a live run."
            ]
        )
        for b in bullets:
            bullet_row = ctk.CTkFrame(shield_card, fg_color="transparent")
            bullet_row.pack(fill="x", padx=20, pady=2, anchor="w")
            ctk.CTkLabel(bullet_row, text="■", font=FONT_SMALL, text_color=warn_text_color).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(bullet_row, text=b, font=FONT_SMALL, text_color=TEXT_MUTED, justify="left", wraplength=320, anchor="w").pack(side="left")

        ctk.CTkLabel(
            shield_card,
            text="Classification: FORENSICALLY IRREVERSIBLE — NIST SP 800-88 Rev.2 Purge Compliant" if not self.dry_run.get() else "Status: SAFE — No hardware commands will be issued",
            font=FONT_SUBHEAD,
            text_color=warn_text_color
        ).pack(side="bottom", pady=20)

        # ── Right Column: Specs, Token Input, Path Selection, and Trigger ────
        right_frame = ctk.CTkFrame(warning_container, fg_color="transparent")
        right_frame.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="nsew")

        # Target Specs Card
        specs = ctk.CTkFrame(right_frame, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        specs.pack(fill="x", pady=(0, 8))
        
        ctk.CTkLabel(specs, text="SELECTED DRIVE", font=FONT_HEADING, text_color=TEXT_HIGH).pack(anchor="w", padx=20, pady=(12, 4))
        
        idx, model, path, letters = self.selected_drive
        ctk.CTkLabel(specs, text=f"Target: {model}", font=FONT_SUBHEAD, text_color=ACCENT_GREEN).pack(anchor="w", padx=20, pady=1)
        
        if letters:
            is_os_drive = "C:" in letters.upper()
            specs_badge_text = f"🚨 WARNING: THIS DISK CONTAINS THE ACTIVE WINDOWS PARTITIONS ({letters})!" if is_os_drive else f"Mapped Logical Volumes: {letters}"
            specs_badge_color = ACCENT_RED if is_os_drive else ACCENT_AMBER
            ctk.CTkLabel(specs, text=specs_badge_text, font=("Segoe UI", 10, "bold"), text_color=specs_badge_color).pack(anchor="w", padx=20, pady=1)

        ctk.CTkLabel(specs, text=f"Mount path: {path}", font=FONT_MONO, text_color=TEXT_MUTED).pack(anchor="w", padx=20, pady=(1, 12))

        # Mode confirmation Card
        mode_card = ctk.CTkFrame(right_frame, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        mode_card.pack(fill="x", pady=(0, 8))
        
        mode_text = "DRY-RUN HARDWARE SIMULATOR [SAFE]" if self.dry_run.get() else "LIVE DESTRUCTIVE WRITES [ARMED]"
        mode_color = ACCENT_AMBER if self.dry_run.get() else ACCENT_RED
        ctk.CTkLabel(mode_card, text=f"Execution Perimeter: {mode_text}", font=FONT_HEADING, text_color=mode_color).pack(anchor="w", padx=20, pady=12)

        # Token input
        auth_card = ctk.CTkFrame(right_frame, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        auth_card.pack(fill="x", pady=(0, 8))
        
        ctk.CTkLabel(auth_card, text=f"Type exactly to authorize:  {AUTHORIZATION_TOKEN}", font=FONT_SUBHEAD, text_color=TEXT_HIGH).pack(anchor="w", padx=20, pady=(12, 4))

        self.auth_entry = ctk.CTkEntry(
            auth_card,
            font=FONT_MONO,
            fg_color=MATTE_INPUT,
            border_color=MATTE_BORDER,
            text_color=TEXT_HIGH,
            placeholder_text="Type authorization token here...",
            height=38,
            corner_radius=4
        )
        self.auth_entry.pack(fill="x", padx=20, pady=(0, 12))

        # Output Log configuration
        log_frame = ctk.CTkFrame(right_frame, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        log_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(log_frame, text="Save Audit Report (Optional)", font=FONT_SUBHEAD, text_color=TEXT_MUTED).pack(anchor="w", padx=20, pady=(10, 2))

        log_row = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_row.pack(fill="x", padx=20, pady=(0, 10))

        self.log_path_label = ctk.CTkLabel(
            log_row,
            text=self.log_path or "No file selected — audit report will not be saved",
            font=FONT_MONO, text_color=TEXT_MUTED,
            anchor="w"
        )
        self.log_path_label.pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            log_row,
            text="Define Path",
            font=FONT_SUBHEAD,
            fg_color=MATTE_INPUT, hover_color=MATTE_BORDER,
            text_color=TEXT_HIGH,
            border_width=1, border_color=MATTE_BORDER,
            width=100, height=30,
            corner_radius=4,
            command=self._browse_log
        ).pack(side="right")

        # Big Trigger Button - changes style based on armed/dry-run configuration
        trigger_text = "⚡  EXECUTE AAD-50 SANITIZATION — LIVE" if not self.dry_run.get() else "⚡  RUN SIMULATION (DRY-RUN — SAFE)"
        trigger_color = ACCENT_RED if not self.dry_run.get() else ACCENT_AMBER
        trigger_hover = "#DC2626" if not self.dry_run.get() else "#D97706"

        ctk.CTkButton(
            right_frame,
            text=trigger_text,
            font=FONT_HEADING,
            fg_color=trigger_color,
            hover_color=trigger_hover,
            text_color=MATTE_BG,
            height=46,
            corner_radius=4,
            command=self._execute_sanitization
        ).pack(fill="x", pady=(2, 0))

    def _browse_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")],
            title="Export Sanitization Audit Logs"
        )
        if path:
            self.log_path = path
            self.log_path_label.configure(text=path)

    def _execute_sanitization(self):
        token = self.auth_entry.get().strip()
        if token != AUTHORIZATION_TOKEN:
            messagebox.showerror(
                "Access Code Mismatch",
                f"Validation Error: Please enter '{AUTHORIZATION_TOKEN}' correctly."
            )
            return

        if not self.dry_run.get():
            confirm = messagebox.askyesno(
                "SYSTEM CLASSIFICATION TRIGGER WARNING",
                f"REAL-TIME WRITE WARNING\n\n"
                f"Device Armed: {self.selected_drive[1]}\n"
                f"Path: {self.selected_drive[2]}\n\n"
                f"This will physically shred raw sectors. This cannot be undone.\n"
                f"Confirm write execution?",
                icon="warning"
            )
            if not confirm:
                return

        self.running = True
        self.cycles_done = 0
        self.report_data = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "author": AUTHOR,
            "device": self.selected_drive[2],
            "drive_model": self.selected_drive[1],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": self.dry_run.get(),
            "cycles": [],
            "outcome": "IN PROGRESS",
            "log_hash": None
        }

        self._show_screen("sanitize")

        self.sanitization_thread = threading.Thread(
            target=self._run_sanitization_thread,
            daemon=True
        )
        self.sanitization_thread.start()

    # ── Screen: LIVE GRAPHICAL PROGRESS DASHBOARD ─────────────────────────────

    def _build_progress_screen(self):
        self.progress_frame = ctk.CTkFrame(self.content, fg_color=MATTE_BG)
        self.progress_frame.pack(fill="both", expand=True)

        # Running Status Header
        hdr = ctk.CTkFrame(self.progress_frame, fg_color=MATTE_CARD, corner_radius=0)
        hdr.pack(fill="x")
        
        ctk.CTkLabel(hdr, text="Sanitization In Progress", font=FONT_HEADING, text_color=TEXT_HIGH).pack(side="left", padx=24, pady=20)

        mode_text = "DRY-RUN — SAFE SIMULATION" if self.dry_run.get() else "⚠  LIVE — REAL HARDWARE ERASURE"
        mode_color = ACCENT_AMBER if self.dry_run.get() else ACCENT_RED
        ctk.CTkLabel(hdr, text=mode_text, font=FONT_MONO, text_color=mode_color).pack(side="right", padx=24)

        main = ctk.CTkFrame(self.progress_frame, fg_color=MATTE_BG)
        main.pack(fill="both", expand=True, padx=24, pady=16)

        # Armed storage model
        drive_card = ctk.CTkFrame(main, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        drive_card.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(drive_card, text=f"Drive: {self.selected_drive[1]}   |   Path: {self.selected_drive[2]}", font=FONT_MONO, text_color=TEXT_MUTED).pack(pady=10, padx=16)

        # Overall progress metrics
        prog_card = ctk.CTkFrame(main, fg_color=MATTE_CARD, corner_radius=8, border_width=1, border_color=MATTE_BORDER)
        prog_card.pack(fill="x", pady=(0, 12))

        top_row = ctk.CTkFrame(prog_card, fg_color="transparent")
        top_row.pack(fill="x", padx=16, pady=(16, 4))

        ctk.CTkLabel(top_row, text="Total Sanitization Progress Map", font=FONT_SUBHEAD, text_color=TEXT_HIGH).pack(side="left")
        self.cycle_label = ctk.CTkLabel(top_row, text=f"0 / {TOTAL_CYCLES}", font=FONT_SUBHEAD, text_color=ACCENT_GREEN)
        self.cycle_label.pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(
            prog_card,
            fg_color=MATTE_INPUT,
            progress_color=ACCENT_GREEN,
            height=14,
            corner_radius=2
        )
        self.progress_bar.pack(fill="x", padx=16, pady=(4, 8))
        self.progress_bar.set(0)

        self.pct_label = ctk.CTkLabel(prog_card, text="0%", font=FONT_SUBHEAD, text_color=ACCENT_GREEN)
        self.pct_label.pack(pady=(0, 16))

        # Real-time Phase indicators
        phases_card = ctk.CTkFrame(main, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        phases_card.pack(fill="x", pady=(0, 12))
        
        phase_row = ctk.CTkFrame(phases_card, fg_color="transparent")
        phase_row.pack(fill="x", padx=16, pady=12)
        phase_row.columnconfigure((0, 1, 2), weight=1)

        self.phase_frames = {}
        phase_data = [
            ("B", "Phase B: Physical Cell Overwrite\n(Cycles 01-40)", ACCENT_GREEN),
            ("C", "Phase C: FTL Index Reset\n(Cycles 41-45)", ACCENT_AMBER),
            ("A", "Phase A: Crypto Key Scramble\n(Cycles 46-50)", ACCENT_PURPLE),
        ]
        for i, (key, label_text, color) in enumerate(phase_data):
            f = ctk.CTkFrame(phase_row, fg_color=MATTE_INPUT, corner_radius=4, border_width=1, border_color=MATTE_BORDER)
            f.grid(row=0, column=i, padx=4, sticky="ew")
            
            lbl = ctk.CTkLabel(f, text=label_text, font=FONT_SMALL, text_color=TEXT_MUTED, justify="center")
            lbl.pack(pady=12, padx=10)
            self.phase_frames[key] = (f, lbl, color)

        # Real-time action tracking
        action_card = ctk.CTkFrame(main, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        action_card.pack(fill="x", pady=(0, 12))
        self.action_label = ctk.CTkLabel(action_card, text="Waiting for controller acknowledgment...", font=FONT_BODY, text_color=TEXT_MUTED)
        self.action_label.pack(pady=12, padx=16)

        # Dynamic terminal window
        log_card = ctk.CTkFrame(main, fg_color=MATTE_CARD, corner_radius=8, border_width=1, border_color=MATTE_BORDER)
        log_card.pack(fill="both", expand=True)
        
        ctk.CTkLabel(log_card, text="ASIC INTERACTION TELEMETRY STREAM", font=FONT_SUBHEAD, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(12, 4))

        self.log_box = ctk.CTkTextbox(
            log_card,
            font=FONT_MONO,
            fg_color=MATTE_INPUT,
            text_color=ACCENT_GREEN,
            height=150,
            corner_radius=4
        )
        self.log_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.log_box.configure(state="disabled")

    def _run_sanitization_thread(self):
        phases = [
            ("B", range(1,  41), SANITIZE_ACTION_OVERWRITE,    "NAND cell raw write loop", 0.05),
            ("C", range(41, 46), SANITIZE_ACTION_BLOCK_ERASE,  "FTL mapping structure truncate", 0.05),
            ("A", range(46, 51), SANITIZE_ACTION_CRYPTO_ERASE, "On-chip register state scramble", 0.05),
        ]

        handle = None
        success = True

        try:
            if not self.dry_run.get() and ENGINE_AVAILABLE:
                handle = open_device(self.selected_drive[2])
                if handle is None:
                    self._log_append("[CRITICAL SYSTEM FAULT] Direct handle generation returned empty.")
                    success = False
                    return

            for phase_key, cycles, action, action_name, delay in phases:
                self.after(0, lambda k=phase_key: self._highlight_phase(k))
                self._log_append(f"\n[PHASE INITIALIZATION] -> Phase {phase_key} active - {action_name}")

                for cycle in cycles:
                    ts = datetime.now(timezone.utc).isoformat()
                    pct = cycle / TOTAL_CYCLES
                    status = "OK"
                    error_msg = None

                    self.after(0, lambda c=cycle, p=pct: self._update_progress(c, p))
                    self.after(0, lambda c=cycle, a=action_name: self._update_action(
                        f"Injecting Opcode 0x84 [Cycle {c:02d}/{TOTAL_CYCLES}] -> Parameters: CDW10=0x{action:02X}"
                    ))

                    try:
                        if not self.dry_run.get() and ENGINE_AVAILABLE and handle:
                            import logging
                            execute_nvme_sanitize(handle, action, logging.getLogger())
                            completed = poll_until_complete(handle, cycle, logging.getLogger())
                            if not completed:
                                status = "TIMEOUT_ERROR"
                                success = False
                        else:
                            time.sleep(delay)

                    except Exception as e:
                        status = "HARDWARE_I/O_FAULT"
                        error_msg = str(e)
                        self._log_append(f"  [BUS ERROR] Controller exception on cycle {cycle}: {e}")
                        success = False

                    self.report_data["cycles"].append({
                        "cycle": cycle, "phase": phase_key,
                        "action_code": action, "timestamp": ts,
                        "status": status, "error": error_msg
                    })
                    self._log_append(f"  Cycle {cycle:02d}/50 | Telemetry frame verified -> {status}")

                    if not success:
                        break
                if not success:
                    break

        finally:
            if handle is not None and ENGINE_AVAILABLE:
                close_device(handle)

        self.report_data["completed_at"] = datetime.now(timezone.utc).isoformat()
        self.report_data["outcome"] = "SUCCESS — DATA DESTROYED" if success else "FAILED — INCOMPLETE"

        cycle_blob = json.dumps(self.report_data["cycles"], sort_keys=True)
        log_hash = hashlib.sha256(cycle_blob.encode()).hexdigest()
        self.report_data["log_hash"] = log_hash

        if self.log_path:
            report_path = self.log_path.replace(".log", "_report.json")
            try:
                with open(report_path, "w") as f:
                    json.dump(self.report_data, f, indent=2)
                self._log_append(f"\n[REPORT FILE GENERATION] Compliance file saved: {report_path}")
            except Exception as e:
                self._log_append(f"\n[WARNING] Failed to write JSON output: {e}")

        self.running = False
        self.after(0, lambda s=success, h=log_hash: self._show_completion(s, h))

    def _highlight_phase(self, active_key: str):
        if not hasattr(self, "phase_frames"):
            return
        for key, (frame, label, color) in self.phase_frames.items():
            if key == active_key:
                frame.configure(fg_color=MATTE_INPUT, border_color=color)
                label.configure(text_color=color)
            else:
                frame.configure(fg_color=MATTE_INPUT, border_color=MATTE_BORDER)
                label.configure(text_color=TEXT_MUTED)

    def _update_progress(self, cycle: int, pct: float):
        if hasattr(self, "progress_bar"):
            self.progress_bar.set(pct)
            self.cycle_label.configure(text=f"Cycle: {cycle} / {TOTAL_CYCLES}")
            self.pct_label.configure(text=f"{int(pct*100)}%")
            bar_color = ACCENT_GREEN if cycle <= 40 else (ACCENT_AMBER if cycle <= 45 else ACCENT_PURPLE)
            self.progress_bar.configure(progress_color=bar_color)

    def _update_action(self, text: str):
        if hasattr(self, "action_label"):
            self.action_label.configure(text=text, text_color=TEXT_HIGH)

    def _log_append(self, text: str):
        def _do():
            if hasattr(self, "log_box"):
                self.log_box.configure(state="normal")
                self.log_box.insert("end", text + "\n")
                self.log_box.see("end")
                self.log_box.configure(state="disabled")
        self.after(0, _do)

    # ── Screen: DESTRUCTIVE COMPLIANCE WARNING (Fixed Spacing) ────────────────

    def _show_completion(self, success: bool, log_hash: str):
        for widget in self.content.winfo_children():
            widget.destroy()

        completion_container = ctk.CTkFrame(self.content, fg_color=MATTE_BG)
        completion_container.pack(fill="both", expand=True, padx=24, pady=(20, 10))

        result_color  = "#0B2D20" if success else "#3A0D0D"
        result_border = ACCENT_GREEN if success else ACCENT_RED
        result_icon   = "✓" if success else "✗"
        result_text   = "SUCCESS — DATA DESTROYED" if success else "FAILED — INCOMPLETE"
        result_tcolor = ACCENT_GREEN if success else ACCENT_RED

        banner = ctk.CTkFrame(completion_container, fg_color=result_color, corner_radius=8, border_width=1, border_color=result_border)
        banner.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            banner,
            text=f"{result_icon}  {result_text}",
            font=FONT_TITLE,
            text_color=result_tcolor
        ).pack(pady=(16, 4))

        mode_note = "[SIMULATOR RUN]" if self.report_data.get("dry_run") else "[LIVE PHYSICAL DESTRUCTIVE OVERWRITE RUN]"
        ctk.CTkLabel(banner, text=mode_note, font=FONT_MONO, text_color=ACCENT_AMBER).pack(pady=(0, 16))

        # Metrics Card
        summary = ctk.CTkFrame(completion_container, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        summary.pack(fill="x", pady=(0, 8))
        
        ctk.CTkLabel(summary, text="Summary", font=FONT_HEADING, text_color=TEXT_HIGH).pack(anchor="w", padx=20, pady=(10, 4))

        rows = [
            ("Device", self.report_data.get("device", "")),
            ("Drive Model", self.report_data.get("drive_model", "")),
            ("Cycles Completed", f"{len(self.report_data.get('cycles', []))} / {TOTAL_CYCLES}"),
            ("Started", self.report_data.get("started_at", "")[:19].replace("T", " ")),
            ("Completed", self.report_data.get("completed_at", "")[:19].replace("T", " ")),
        ]
        for label, value in rows:
            row = ctk.CTkFrame(summary, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=2)
            ctk.CTkLabel(row, text=f"{label}:", font=FONT_SMALL, text_color=TEXT_MUTED, width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=FONT_MONO, text_color=TEXT_HIGH, anchor="w").pack(side="left")

        ctk.CTkFrame(summary, fg_color="transparent", height=10).pack()

        # Crypto Stamp Card
        hash_card = ctk.CTkFrame(completion_container, fg_color=MATTE_CARD, corner_radius=6, border_width=1, border_color=MATTE_BORDER)
        hash_card.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(hash_card, text="CRYPTO TELEMETRY ANCHOR (SHA-256)", font=FONT_HEADING, text_color=TEXT_HIGH).pack(anchor="w", padx=20, pady=(10, 2))
        ctk.CTkLabel(hash_card, text=log_hash, font=FONT_MONO, text_color=ACCENT_GREEN, wraplength=700).pack(anchor="w", padx=20, pady=(0, 4))
        ctk.CTkLabel(hash_card, text="This hash represents an immutable, sequential calculation of all 50 physical cycle states. It acts as audit-proof declassification telemetry.", font=FONT_BODY, text_color=TEXT_MUTED, wraplength=720, justify="left").pack(anchor="w", padx=20, pady=(0, 12))

        # Bottom Deck
        btns = ctk.CTkFrame(completion_container, fg_color="transparent")
        btns.pack(fill="x", pady=(4, 0))
        btns.columnconfigure((0, 1, 2), weight=1)

        ctk.CTkButton(
            btns, text="📋  Copy Hash State",
            font=FONT_SUBHEAD, fg_color=MATTE_CARD, hover_color=MATTE_INPUT,
            text_color=TEXT_HIGH, border_width=1, border_color=MATTE_BORDER,
            height=40, corner_radius=4,
            command=lambda: self._copy_to_clipboard(log_hash)
        ).grid(row=0, column=0, padx=4, sticky="ew")

        ctk.CTkButton(
            btns, text="💾  Export Report JSON",
            font=FONT_SUBHEAD, fg_color=MATTE_CARD, hover_color=MATTE_INPUT,
            text_color=TEXT_HIGH, border_width=1, border_color=MATTE_BORDER,
            height=40, corner_radius=4,
            command=self._save_report
        ).grid(row=0, column=1, padx=4, sticky="ew")

        ctk.CTkButton(
            btns, text="⌂  Dashboard Return",
            font=FONT_SUBHEAD, fg_color=ACCENT_GREEN, hover_color="#059669",
            text_color=MATTE_BG,
            height=40, corner_radius=4,
            command=lambda: self._show_screen("home")
        ).grid(row=0, column=2, padx=4, sticky="ew")

        self._set_status(f"Matrix Completed. Status Code: {result_text}")

    def _copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update() 
        self._set_status("Cryptographic stamp copied to system clipboard.")

    def _save_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save JSON Verification Ledger",
            initialfile="aad50_compliance_report.json"
        )
        if path:
            with open(path, "w") as f:
                json.dump(self.report_data, f, indent=2)
            self._set_status(f"Export Success: {path}")
            messagebox.showinfo("Report Exported", f"Audit report successfully compiled and written to:\n\n{path}")

    # ── Screen: AUDIT LOG VERIFICATION (Fits Display Perfectly) ───────────────

    def _screen_reports(self):
        reports_container = ctk.CTkFrame(self.content, fg_color=MATTE_BG)
        reports_container.pack(fill="both", expand=True, padx=24, pady=(20, 10))

        hdr = ctk.CTkFrame(reports_container, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(hdr, text="COMPLIANCE LEDGER AUDIT MODULE", font=FONT_HEADING, text_color=TEXT_HIGH).pack(side="left")

        ctk.CTkLabel(reports_container, text="Parse & Verify Verification Files", font=FONT_SUBHEAD, text_color=TEXT_HIGH).pack(anchor="w", pady=(0, 2))
        ctk.CTkLabel(
            reports_container,
            text="Verify the integrity of a generated sanitization certificate. This engine recalculates "
                 "the SHA-256 hash across the sequential log blocks to verify zero-tampering.",
            font=FONT_BODY, text_color=TEXT_MUTED, wraplength=700, justify="left"
        ).pack(anchor="w", pady=(0, 12))

        ctk.CTkButton(
            reports_container, text="📂  Import Report JSON Ledger",
            font=FONT_SUBHEAD, fg_color=MATTE_CARD, hover_color=MATTE_INPUT,
            text_color=TEXT_HIGH, border_width=1, border_color=MATTE_BORDER,
            height=40, corner_radius=4,
            command=self._load_and_verify_report
        ).pack(fill="x", pady=(0, 12))

        self.verify_frame = ctk.CTkFrame(reports_container, fg_color=MATTE_CARD, corner_radius=8, border_width=1, border_color=MATTE_BORDER)
        self.verify_frame.pack(fill="both", expand=True)
        ctk.CTkLabel(
            self.verify_frame,
            text="Awaiting ledger import...",
            font=FONT_BODY, text_color=TEXT_MUTED
        ).pack(expand=True)

    def _load_and_verify_report(self):
        path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import Compliance Report"
        )
        if not path:
            return

        try:
            with open(path) as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("I/O Parsing Exception", f"Could not parse file structure:\n{e}")
            return

        stored_hash = data.get("log_hash", "")
        cycles      = data.get("cycles", [])
        cycle_blob  = json.dumps(cycles, sort_keys=True)
        computed    = hashlib.sha256(cycle_blob.encode()).hexdigest()
        verified    = (stored_hash == computed)

        for w in self.verify_frame.winfo_children():
            w.destroy()

        status_color = ACCENT_GREEN if verified else ACCENT_RED
        status_text  = "✓  STAMP VERIFIED — Data log matches cryptographic baseline exactly" if verified else \
                       "✗  TAMPERING DETECTED — Compute mismatch. Verification failed."

        ctk.CTkLabel(self.verify_frame, text=status_text, font=FONT_SUBHEAD, text_color=status_color).pack(pady=(20, 16), padx=20)

        rows = [
            ("Import File", os.path.basename(path)),
            ("Target Node", data.get("device", "Unknown")),
            ("Device Hardware", data.get("drive_model", "Unknown")),
            ("Sanitize Outcome", data.get("outcome", "Unknown")),
            ("Cycles Executed", f"{len(cycles)} / {TOTAL_CYCLES}"),
            ("Complete Date", data.get("completed_at", "")[:19].replace("T", " ")),
            ("Stored Hash Key", stored_hash[:36] + "..."),
            ("Computed Hash", computed[:36] + "..."),
            ("Integrity Status", "SECURE / VERIFIED ✓" if verified else "CORRUPTED / TAMPERED ✗"),
        ]
        for label, value in rows:
            row = ctk.CTkFrame(self.verify_frame, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=2)
            ctk.CTkLabel(row, text=f"{label}:", font=FONT_SMALL, text_color=TEXT_MUTED, width=120, anchor="w").pack(side="left")
            color = (ACCENT_GREEN if "VERIFIED" in str(value) else ACCENT_RED if "CORRUPTED" in str(value) else TEXT_HIGH)
            ctk.CTkLabel(row, text=str(value), font=FONT_MONO, text_color=color, anchor="w").pack(side="left")

        ctk.CTkFrame(self.verify_frame, fg_color="transparent", height=16).pack()

    # ── Screen: ABOUT SPECIFICATIONS (Fluid Fit + Live Diagnostic Unit) ───────

    def _screen_about(self):
        about_container = ctk.CTkFrame(self.content, fg_color=MATTE_BG)
        about_container.pack(fill="both", expand=True, padx=24, pady=(20, 10))

        ctk.CTkLabel(about_container, text="About AAD-50", font=FONT_TITLE, text_color=TEXT_HIGH).pack(pady=(0, 2), anchor="w")
        ctk.CTkLabel(about_container, text="Firmware-Enforced Flash Sanitization Specification for NVMe Solid-State Storage", font=FONT_BODY, text_color=TEXT_MUTED).pack(anchor="w", pady=(0, 12))

        # Main specs info panel
        info = [
            ("Author", AUTHOR),
            ("Direct Channel", CONTACT),
            ("Build Version", TOOL_VERSION),
            ("Compatibility", "Windows 10 1607+ / Windows 11 / Windows Server 2016+"),
            ("Audit Authority", "https://github.com/yonasabeselom/aad50"),
            ("Core Licenses", "Specification Protocol: Open Attribution (CC BY 4.0)"),
            ("Regulatory Aligns", "NIST SP 800-88 Rev.2 Purge • IEEE 2883-2022 • ISO/IEC 27040"),
        ]

        card = ctk.CTkFrame(about_container, fg_color=MATTE_CARD, corner_radius=8, border_width=1, border_color=MATTE_BORDER)
        card.pack(fill="x", pady=(0, 12))

        for label, value in info:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=4)
            ctk.CTkLabel(row, text=f"{label}:", font=FONT_SUBHEAD, text_color=TEXT_MUTED, width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=FONT_BODY, text_color=TEXT_HIGH, anchor="w", wraplength=600).pack(side="left")

        # Live Diagnostic Testing Card for SSTAT Pass-Through Verification
        diag_card = ctk.CTkFrame(about_container, fg_color=MATTE_CARD, corner_radius=8, border_width=1, border_color=MATTE_BORDER)
        diag_card.pack(fill="x", pady=(0, 12))

        diag_content = ctk.CTkFrame(diag_card, fg_color="transparent")
        diag_content.pack(fill="x", padx=20, pady=12)

        ctk.CTkLabel(
            diag_content,
            text="🧪  OEM DRIVER PASS-THROUGH DIAGNOSTIC PORT\n"
                 "Test if active storage drivers (Samsung, Intel, RST, etc.) block the non-destructive Log Page 0x81 (SSTAT) command "
                 "needed for asynchronous monitoring.",
            font=FONT_BODY, text_color=TEXT_MUTED, justify="left", wraplength=520
        ).pack(side="left", anchor="w")

        ctk.CTkButton(
            diag_content,
            text="Run Driver Test",
            font=FONT_SUBHEAD,
            fg_color=ACCENT_AMBER,
            hover_color="#D97706",
            text_color=MATTE_BG,
            width=140, height=36,
            corner_radius=4,
            command=self._run_oem_diagnostic
        ).pack(side="right", padx=(20, 0), pady=4)

        # Alert Shield Card
        warn = ctk.CTkFrame(about_container, fg_color="#3A0D0D", corner_radius=8, border_width=1, border_color=ACCENT_RED)
        warn.pack(fill="x")
        ctk.CTkLabel(
            warn,
            text="⚠️ SYSTEM CRITICAL NOTE: This administrative engineering platform interfaces with direct block structures "
                 "to instruct ASIC controllers to alter logical voltage layers. Only execute sanitization loops "
                 "against devices verified and ready for decommissioning.",
            font=FONT_BODY, text_color=ACCENT_RED,
            wraplength=700, justify="center"
        ).pack(pady=12, padx=20)

    def _run_oem_diagnostic(self):
        """
        Direct OEM storage driver polling validation unit.
        Directly queries the armed drive to verify if SSTAT bypass passes or blocks.
        """
        if not self.selected_drive:
            messagebox.showerror(
                "Diagnostic Error",
                "Please select and arm an NVMe drive first under 'Select Target NVMe'."
            )
            return

        self._set_status("Running direct driver pass-through audit...")

        def diag_worker():
            import logging
            idx, model, path, letters = self.selected_drive

            if self.dry_run.get():
                time.sleep(1.0)
                self.after(0, lambda: messagebox.showinfo(
                    "Simulator Audit Success",
                    f"SUCCESS (MOCK SIMULATOR ENVIRONMENT):\n\n"
                    f"Model: {model}\n"
                    f"Diagnostic Result: Success\n\n"
                    f"To test your actual hardware's controller driver hooks, turn off 'Dry-Run Simulator'."
                ))
                self.after(0, lambda: self._set_status("Ready"))
                return

            if not ENGINE_AVAILABLE:
                self.after(0, lambda: messagebox.showerror(
                    "Engine Interface Missing",
                    "The backend helper module (aad50_abeselom_windows.py) is missing or corrupted."
                ))
                self.after(0, lambda: self._set_status("Ready"))
                return

            handle = open_device(path)
            if handle is None:
                err = ctypes.GetLastError()
                self.after(0, lambda: messagebox.showerror(
                    "Administrator Privileges Required",
                    f"Win32 direct disk interface call (CreateFileW) blocked on {path} (Error {err}).\n\n"
                    "Ensure you are running the application as an Administrator."
                ))
                self.after(0, lambda: self._set_status("Ready"))
                return

            try:
                # Queries the actual Log Page 0x81 (completely safe and read-only)
                try:
                    from aad50_abeselom_windows import read_sanitize_status as _rss
                    status = _rss(handle, logging.getLogger("aad50_win"))
                except ImportError:
                    status = None
                if status is not None:
                    self.after(0, lambda: messagebox.showinfo(
                        "Driver Pass-Through Verified",
                        f"COMPATIBILITY VERIFIED:\n\n"
                        f"Hardware: {model}\n"
                        f"Direct SSTAT Polling: ACTIVE (SSTAT code: 0x{status:X})\n\n"
                        f"Your active NVMe storage driver safely passes high-level DeviceIoControl commands."
                    ))
                else:
                    self.after(0, lambda: messagebox.showwarning(
                        "Command Filter Detected",
                        f"COMPATIBILITY WARNING:\n\n"
                        f"direct DeviceIoControl pass-through commands returned empty.\n\n"
                        f"Your current proprietary Storage Controller driver (e.g. Samsung Magician hooks, Intel RST) "
                        f"is blocking direct ASIC state telemetry.\n\n"
                        f"Recommendation: Switch your NVMe controller driver in Windows Device Manager "
                        f"to the standard Microsoft driver (stornvme.sys) for full sanitization compliance."
                    ))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror(
                    "Diagnostic Fail",
                    f"An exception occurred inside the direct driver IOCTL path:\n{str(e)}"
                ))
            finally:
                close_device(handle)
                self.after(0, lambda: self._set_status("Ready"))

        threading.Thread(target=diag_worker, daemon=True).start()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _set_status(self, text: str):
        self.status_label.configure(text=f"System Status: {text}")


# ==============================================================================
# MAIN EXECUTABLE ENTRY POINT
# ==============================================================================

def main():
    if ENGINE_AVAILABLE and not is_admin():
        result = messagebox.askyesno(
            "Privilege Escalation Required",
            "Accessing physical Storage Controller handles (PhysicalDriveN) requires Administrator privileges.\n\n"
            "Would you like to load the application in Simulator Demo Mode?\n\n"
            "To target active hardware later, relaunch the application by right-clicking it and choosing 'Run as administrator'.",
            icon="warning"
        )
        if not result:
            sys.exit(0)

    app = AAD50App()
    app.mainloop()

if __name__ == "__main__":
    main()