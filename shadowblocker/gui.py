import os
import sys
import threading
import queue
import logging
import json
import webbrowser
from typing import List, Dict, Any, Optional
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .discovery import discover_all_browser_extensions, scan_directory_recursively
from .scanner import Scanner
from .models import ScanResult, FindingSeverity, AnalysisFinding

# Configure customtkinter parameters
ctk.set_appearance_mode("dark")  # "light", "dark", or "system"
ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"

logger = logging.getLogger("shadowblocker.gui")

# Harmony palette colors - CustomTkinter dynamic tuples (light_mode_color, dark_mode_color)
COLOR_SAFE = "#2ec4b6"       # Premium Teal
COLOR_WARNING = "#ffb703"    # Vivid Amber
COLOR_CRITICAL = "#e63946"   # Deep Coral Red
COLOR_CARD_BG = ("#f8f9fa", "#1d242e")    # Dark slate card / Light grey card
COLOR_SIDEBAR_BG = ("#e9ecef", "#0f141c") # Deeper dark background / Light silver sidebar
COLOR_MAIN_BG = ("#ffffff", "#131922")    # Dark main canvas background / pure white canvas
COLOR_TEXT_MUTED = ("#6c757d", "#8d99ae") # Monospace/muted grey
COLOR_LIST_BG = ("#f1f3f5", "#181f2a")    # Left extension container background
COLOR_DETAIL_BG = ("#f8f9fa", "#161b24")  # Right audit detail frame background
COLOR_DESC_BG = ("#e9ecef", "#1b222c")    # Description card block background
COLOR_SNIPPET_BG = ("#e9ecef", "#0f141a") # Code snippet card outer background
COLOR_CODE_BG = ("#f1f3f5", "#0a0d10")    # Code block textbox background
COLOR_TEXT_MAIN = ("#212529", "#ffffff")  # Main readable headings
COLOR_TEXT_SUB = ("#495057", "#cfd2d6")   # Finding row description lines
COLOR_SEPARATOR = ("#dee2e6", "#2b3543")  # Separation margins

class ShadowBlockerApp(ctk.CTk):
    """The main desktop application class built on CustomTkinter."""
    
    def __init__(self):
        super().__init__()
        
        # Configure Main Window
        self.title("ShadowBlocker - Local Browser Extension Forensic Auditor")
        self.geometry("1280x800")
        self.minsize(1020, 650)
        
        # Grid Configuration
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0) # Sidebar
        self.grid_columnconfigure(1, weight=1) # Main area
        
        # Application State
        self.all_results: List[ScanResult] = []
        self.filtered_results: List[ScanResult] = []
        self.selected_result: Optional[ScanResult] = None
        self.scan_queue = queue.Queue()
        self.is_scanning = False
        
        # Initialize UI Components
        self.build_sidebar()
        self.build_main_view()
        
        # Load Welcome State
        self.show_welcome_state()
        
        # Start Queue Polling
        self.poll_queue()
        
        # Automatically run an initial scan of the mock extensions folder to demonstrate capability!
        self.auto_scan_mock_extensions()

    def auto_scan_mock_extensions(self):
        """Scans the test_extensions directory automatically on launch to pre-populate the UI."""
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        mock_path = os.path.join(base_dir, "test_extensions")
        if os.path.isdir(mock_path):
            self.start_scan(mock_path, is_custom=True)

    def build_sidebar(self):
        """Creates the premium looking left sidebar for stats and scan actions."""
        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=COLOR_SIDEBAR_BG)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1) # Spacer
        
        # App Title & Shield Icon (represented by premium typography)
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="🛡️ SHADOWBLOCKER", 
            font=ctk.CTkFont(size=22, weight="bold", family="Inter")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 5))
        
        self.subtitle_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Local Extension Auditor",
            font=ctk.CTkFont(size=12, slant="italic"),
            text_color=COLOR_TEXT_MUTED
        )
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 25))
        
        # Horizontal separator
        self.separator = ctk.CTkFrame(self.sidebar_frame, height=2, fg_color=COLOR_SEPARATOR)
        self.separator.grid(row=2, column=0, sticky="ew", padx=20, pady=5)
        
        # Action Buttons Section
        self.actions_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="ACTIONS", 
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLOR_TEXT_MUTED
        )
        self.actions_label.grid(row=3, column=0, padx=20, pady=(15, 5), sticky="w")

        self.scan_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🔍 Full Browser Scan",
            font=ctk.CTkFont(weight="bold"),
            height=35,
            command=self.on_full_scan_clicked
        )
        self.scan_btn.grid(row=4, column=0, padx=20, pady=8, sticky="ew")

        self.custom_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="📁 Select Custom Folder...",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#343a40",
            hover_color="#495057",
            height=35,
            command=self.on_custom_scan_clicked
        )
        self.custom_btn.grid(row=5, column=0, padx=20, pady=8, sticky="ew")
        
        self.export_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="📤 Export HTML Report",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#1d2d44",
            hover_color="#0d1b2a",
            height=35,
            command=self.on_export_clicked
        )
        self.export_btn.grid(row=6, column=0, padx=20, pady=8, sticky="ew")
        
        self.theme_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🌓 Toggle UI Theme",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#3d348b",
            hover_color="#4c3b9b",
            height=35,
            command=self.toggle_theme
        )
        self.theme_btn.grid(row=7, column=0, padx=20, pady=8, sticky="ew")

        # Stats counters section
        self.stats_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.stats_frame.grid(row=9, column=0, padx=20, pady=20, sticky="ew")
        self.stats_frame.grid_columnconfigure(0, weight=1)
        self.stats_frame.grid_columnconfigure(1, weight=1)
        
        self.stat_total = self.create_stat_card(self.stats_frame, 0, 0, "Total", "0", "#e2eafc")
        self.stat_safe = self.create_stat_card(self.stats_frame, 0, 1, "Safe", "0", COLOR_SAFE)
        self.stat_warning = self.create_stat_card(self.stats_frame, 1, 0, "Warning", "0", COLOR_WARNING)
        self.stat_critical = self.create_stat_card(self.stats_frame, 1, 1, "Critical", "0", COLOR_CRITICAL)

        # Scanning Progress Widgets (Initially hidden)
        self.progress_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.progress_frame.grid(row=10, column=0, padx=20, pady=(0, 20), sticky="ew")
        self.progress_frame.grid_columnconfigure(0, weight=1)
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(
            self.progress_frame, 
            text="Scanning extensions...", 
            font=ctk.CTkFont(size=11), 
            text_color=COLOR_TEXT_MUTED
        )
        
    def create_stat_card(self, parent, row, col, title, initial_val, color) -> ctk.CTkLabel:
        """Helper to create a small aesthetic stat display."""
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD_BG, height=75, corner_radius=8)
        card.grid(row=row, column=col, padx=4, pady=4, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        
        num_label = ctk.CTkLabel(
            card, 
            text=initial_val, 
            font=ctk.CTkFont(size=22, weight="bold"), 
            text_color=color
        )
        num_label.grid(row=0, column=0, pady=(8, 0))
        
        title_label = ctk.CTkLabel(
            card, 
            text=title, 
            font=ctk.CTkFont(size=10, weight="bold"), 
            text_color=COLOR_TEXT_MUTED
        )
        title_label.grid(row=1, column=0, pady=(0, 8))
        
        # Save reference to return the label we actually update (the number)
        return num_label

    def build_main_view(self):
        """Creates the primary browser list and split detail audit panel."""
        self.main_container = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_MAIN_BG)
        self.main_container.grid(row=0, column=1, sticky="nsew")
        
        self.main_container.grid_rowconfigure(1, weight=1)
        self.main_container.grid_columnconfigure(0, weight=6) # List View
        self.main_container.grid_columnconfigure(1, weight=4) # Detail View
        
        # --- Top Filter & Search Bar ---
        self.filter_bar = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.filter_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=20, pady=(20, 10))
        self.filter_bar.grid_columnconfigure(0, weight=1) # Search entry takes full space
        
        self.search_entry = ctk.CTkEntry(
            self.filter_bar, 
            placeholder_text="🔍 Search extensions by name or ID...",
            height=35
        )
        self.search_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda event: self.apply_filters())
        
        self.risk_filter_menu = ctk.CTkOptionMenu(
            self.filter_bar,
            values=["All Risks", "Critical Only", "Warning Only", "Safe Only"],
            width=130,
            height=35,
            command=lambda v: self.apply_filters()
        )
        self.risk_filter_menu.grid(row=0, column=1, padx=5)
        
        self.browser_filter_menu = ctk.CTkOptionMenu(
            self.filter_bar,
            values=["All Browsers", "Chrome Only", "Edge Only", "Brave Only", "Custom Only"],
            width=130,
            height=35,
            command=lambda v: self.apply_filters()
        )
        self.browser_filter_menu.grid(row=0, column=2, padx=(5, 0))
        
        # --- Left Column: Extension Scrollable List ---
        self.list_container = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.list_container.grid(row=1, column=0, sticky="nsew", padx=(20, 10), pady=(0, 20))
        self.list_container.grid_rowconfigure(0, weight=1)
        self.list_container.grid_columnconfigure(0, weight=1)
        
        self.scrollable_list = ctk.CTkScrollableFrame(
            self.list_container, 
            label_text="INSTALLED EXTENSIONS",
            label_font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLOR_LIST_BG
        )
        self.scrollable_list.grid(row=0, column=0, sticky="nsew")
        
        # --- Right Column: Audit Detail Panel ---
        self.detail_frame = ctk.CTkFrame(self.main_container, fg_color=COLOR_DETAIL_BG, corner_radius=12)
        self.detail_frame.grid(row=1, column=1, sticky="nsew", padx=(10, 20), pady=(0, 20))
        self.detail_frame.grid_rowconfigure(0, weight=1)
        self.detail_frame.grid_columnconfigure(0, weight=1)
        
        # Detail scroll container
        self.detail_scroll = ctk.CTkScrollableFrame(self.detail_frame, fg_color="transparent")
        self.detail_scroll.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

    def show_welcome_state(self):
        """Displays a clean welcome layout in the detail panel before any extension is clicked."""
        # Clear detail panel
        for child in self.detail_scroll.winfo_children():
            child.destroy()
            
        welcome_frame = ctk.CTkFrame(self.detail_scroll, fg_color="transparent")
        welcome_frame.pack(fill="both", expand=True, pady=150)
        
        shield_label = ctk.CTkLabel(welcome_frame, text="🛡️", font=ctk.CTkFont(size=80))
        shield_label.pack()
        
        title_label = ctk.CTkLabel(
            welcome_frame, 
            text="ShadowBlocker Forensic Auditor", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title_label.pack(pady=10)
        
        desc_label = ctk.CTkLabel(
            welcome_frame,
            text="Select an extension from the list to audit its permissions, inspect signature triggers, and view static code snippet analysis.",
            font=ctk.CTkFont(size=12),
            text_color=COLOR_TEXT_MUTED,
            wraplength=300,
            justify="center"
        )
        desc_label.pack()

    def update_sidebar_stats(self):
        """Recalculates counts and updates sidebar stat cards."""
        total = len(self.all_results)
        safe = sum(1 for r in self.all_results if r.risk_level == "Safe")
        warning = sum(1 for r in self.all_results if r.risk_level == "Warning")
        critical = sum(1 for r in self.all_results if r.risk_level == "Critical")
        
        self.stat_total.configure(text=str(total))
        self.stat_safe.configure(text=str(safe))
        self.stat_warning.configure(text=str(warning))
        self.stat_critical.configure(text=str(critical))

    def on_full_scan_clicked(self):
        """Triggers asynchronous scanning of standard Chrome, Edge, and Brave extensions."""
        self.start_scan(None, is_custom=False)

    def on_custom_scan_clicked(self):
        """Prompts the user to pick a folder and triggers scanning on that path."""
        target_dir = filedialog.askdirectory(title="Select Extension Directory to Scan")
        if target_dir:
            self.start_scan(target_dir, is_custom=True)

    def start_scan(self, path: Optional[str], is_custom: bool):
        """Initializes scanning progress widgets and spawns the background worker thread."""
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.scan_btn.configure(state="disabled")
        self.custom_btn.configure(state="disabled")
        
        # Show progress bar
        self.progress_bar.grid(row=0, column=0, pady=(5, 5), sticky="ew")
        self.progress_label.grid(row=1, column=0, sticky="ew")
        self.progress_bar.set(0.0)
        self.progress_label.configure(text="Searching directories...")
        
        # Clear lists
        for child in self.scrollable_list.winfo_children():
            child.destroy()
        self.show_welcome_state()

        # Spawn Thread
        threading.Thread(
            target=self.scan_worker_thread,
            args=(path, is_custom),
            daemon=True
        ).start()

    def scan_worker_thread(self, target_path: Optional[str], is_custom: bool):
        """Worker thread executing the directory search and static file scanning."""
        try:
            if is_custom and target_path:
                self.scan_queue.put(("status", "Searching files recursively..."))
                extensions = scan_directory_recursively(target_path)
            else:
                self.scan_queue.put(("status", "Locating Chromium directories..."))
                extensions = discover_all_browser_extensions()

            total_exts = len(extensions)
            self.scan_queue.put(("count", total_exts))

            results = []
            for idx, ext in enumerate(extensions):
                self.scan_queue.put(("progress", (idx / max(1, total_exts), f"Auditing: {ext['id'][:10]}...")))
                
                # Perform deep forensic scanning
                scan_res = Scanner.analyze_extension(ext["path"], ext["browser"], ext["id"])
                results.append(scan_res)
                
            self.scan_queue.put(("complete", results))
        except Exception as e:
            logger.exception("Error in scanning worker thread")
            self.scan_queue.put(("error", str(e)))

    def poll_queue(self):
        """Polls the queue every 100ms for status/completion updates from the scan thread."""
        try:
            while True:
                msg_type, data = self.scan_queue.get_nowait()
                if msg_type == "status":
                    self.progress_label.configure(text=data)
                elif msg_type == "count":
                    pass # Handled inside progress
                elif msg_type == "progress":
                    ratio, txt = data
                    self.progress_bar.set(ratio)
                    self.progress_label.configure(text=txt)
                elif msg_type == "error":
                    self.is_scanning = False
                    self.hide_progress()
                    messagebox.showerror("Scan Error", f"An error occurred during the scan:\n{data}")
                elif msg_type == "complete":
                    self.is_scanning = False
                    self.hide_progress()
                    self.all_results = data
                    self.apply_filters()
                    self.update_sidebar_stats()
                    messagebox.showinfo("Scan Complete", f"Successfully audited {len(self.all_results)} extension directories.")
        except queue.Empty:
            pass
        
        # Schedule next poll
        self.after(100, self.poll_queue)

    def hide_progress(self):
        """Cleans up and hides the progress widgets after scanning terminates."""
        self.progress_bar.grid_forget()
        self.progress_label.grid_forget()
        self.scan_btn.configure(state="normal")
        self.custom_btn.configure(state="normal")

    def apply_filters(self):
        """Filters extension scrollable view based on search query, browser selection, and risk severity."""
        query = self.search_entry.get().lower()
        risk_filter = self.risk_filter_menu.get()
        browser_filter = self.browser_filter_menu.get()

        self.filtered_results = []
        for res in self.all_results:
            name_match = query in res.extension.name.lower() or query in res.extension.id.lower()
            
            # Risk match
            risk_match = True
            if risk_filter == "Critical Only" and res.risk_level != "Critical":
                risk_match = False
            elif risk_filter == "Warning Only" and res.risk_level != "Warning":
                risk_match = False
            elif risk_filter == "Safe Only" and res.risk_level != "Safe":
                risk_match = False
                
            # Browser match
            browser_match = True
            if browser_filter == "Chrome Only" and res.extension.browser != "Chrome":
                browser_match = False
            elif browser_filter == "Edge Only" and res.extension.browser != "Edge":
                browser_match = False
            elif browser_filter == "Brave Only" and res.extension.browser != "Brave":
                browser_match = False
            elif browser_filter == "Custom Only" and res.extension.browser != "Custom / Unpacked":
                browser_match = False

            if name_match and risk_match and browser_match:
                self.filtered_results.append(res)

        self.render_extension_cards()

    def render_extension_cards(self):
        """Draws the list cards in the scrollable extension frame."""
        # Clear list
        for child in self.scrollable_list.winfo_children():
            child.destroy()
            
        if not self.filtered_results:
            no_lbl = ctk.CTkLabel(
                self.scrollable_list, 
                text="No extensions found matching criteria.", 
                font=ctk.CTkFont(size=12, slant="italic"),
                text_color=COLOR_TEXT_MUTED
            )
            no_lbl.pack(pady=40)
            return

        for idx, res in enumerate(self.filtered_results):
            self.create_extension_card(res, idx)

    def create_extension_card(self, res: ScanResult, index: int):
        """Creates a stylized CTkFrame card representing an extension."""
        # Setup card frame
        card = ctk.CTkFrame(self.scrollable_list, fg_color=COLOR_CARD_BG, height=90, corner_radius=8)
        card.pack(fill="x", padx=10, pady=6)
        
        # Grid Configuration inside Card
        card.grid_columnconfigure(0, weight=1)
        card.grid_columnconfigure(1, weight=0)
        
        # Text details container
        text_container = ctk.CTkFrame(card, fg_color="transparent")
        text_container.grid(row=0, column=0, padx=15, pady=10, sticky="w")
        
        # Browser tag and title
        browser_colors = {"Chrome": "#90e0ef", "Brave": "#f77f00", "Edge": "#4ea8de"}
        b_color = browser_colors.get(res.extension.browser, COLOR_TEXT_MUTED)
        
        header_text = f"[{res.extension.browser}]"
        header_label = ctk.CTkLabel(
            text_container, 
            text=header_text, 
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=b_color
        )
        header_label.pack(anchor="w")

        name_label = ctk.CTkLabel(
            text_container, 
            text=res.extension.name, 
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
            wraplength=350,
            justify="left"
        )
        name_label.pack(anchor="w", pady=(2, 2))

        sub_label = ctk.CTkLabel(
            text_container, 
            text=f"Version: {res.extension.version}  |  ID: {res.extension.id[:16]}...", 
            font=ctk.CTkFont(size=10),
            text_color=COLOR_TEXT_MUTED,
            anchor="w"
        )
        sub_label.pack(anchor="w")

        # Risk Level Badge Container
        badge_container = ctk.CTkFrame(card, fg_color="transparent")
        badge_container.grid(row=0, column=1, padx=15, pady=10, sticky="e")
        
        badge_bg = COLOR_SAFE
        if res.risk_level == "Warning":
            badge_bg = COLOR_WARNING
        elif res.risk_level == "Critical":
            badge_bg = COLOR_CRITICAL
            
        badge = ctk.CTkFrame(badge_container, fg_color=badge_bg, corner_radius=6)
        badge.pack(padx=5, pady=2)
        
        badge_label = ctk.CTkLabel(
            badge, 
            text=res.risk_level.upper(), 
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#121820" if res.risk_level == "Warning" else "#ffffff",
            padx=10,
            pady=4
        )
        badge_label.pack()
        
        score_label = ctk.CTkLabel(
            badge_container,
            text=f"Score: {int(res.risk_score)}/100",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=COLOR_TEXT_MUTED
        )
        score_label.pack()

        # Bind clicks to entire card recursively
        def on_click(event):
            self.on_extension_selected(res)
            
        card.bind("<Button-1>", on_click)
        text_container.bind("<Button-1>", on_click)
        name_label.bind("<Button-1>", on_click)
        sub_label.bind("<Button-1>", on_click)
        header_label.bind("<Button-1>", on_click)
        badge_container.bind("<Button-1>", on_click)
        badge.bind("<Button-1>", on_click)
        badge_label.bind("<Button-1>", on_click)
        score_label.bind("<Button-1>", on_click)

    def on_extension_selected(self, res: ScanResult):
        """Displays audit findings in the detail pane when an extension is clicked."""
        self.selected_result = res
        
        # Clear detail panel
        for child in self.detail_scroll.winfo_children():
            child.destroy()
            
        # Extension Main Header
        header = ctk.CTkFrame(self.detail_scroll, fg_color="transparent")
        header.pack(fill="x", pady=(10, 15))
        
        title = ctk.CTkLabel(
            header, 
            text=res.extension.name, 
            font=ctk.CTkFont(size=20, weight="bold"),
            wraplength=350,
            justify="left"
        )
        title.pack(anchor="w")

        meta_lbl = ctk.CTkLabel(
            header,
            text=f"Browser: {res.extension.browser}  |  Version: {res.extension.version}\nID: {res.extension.id}",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_MUTED,
            justify="left"
        )
        meta_lbl.pack(anchor="w", pady=(5, 5))
        
        # Big Risk Score Banner
        badge_bg = COLOR_SAFE
        if res.risk_level == "Warning":
            badge_bg = COLOR_WARNING
        elif res.risk_level == "Critical":
            badge_bg = COLOR_CRITICAL
            
        score_banner = ctk.CTkFrame(self.detail_scroll, fg_color=badge_bg, corner_radius=8, height=60)
        score_banner.pack(fill="x", pady=(0, 15))
        
        score_text = f"RISK AUDIT: {res.risk_level.upper()} ({int(res.risk_score)}/100)"
        score_lbl = ctk.CTkLabel(
            score_banner,
            text=score_text,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#121820" if res.risk_level == "Warning" else "#ffffff",
            pady=10
        )
        score_lbl.pack(fill="both")

        # Description
        desc_box = ctk.CTkFrame(self.detail_scroll, fg_color=COLOR_DESC_BG)
        desc_box.pack(fill="x", pady=(0, 15))
        desc_lbl = ctk.CTkLabel(
            desc_box,
            text=res.extension.description,
            font=ctk.CTkFont(size=12),
            text_color=COLOR_TEXT_SUB,
            wraplength=330,
            justify="left",
            padx=10,
            pady=8
        )
        desc_lbl.pack(fill="both")

        # Path info
        path_box = ctk.CTkFrame(self.detail_scroll, fg_color="transparent")
        path_box.pack(fill="x", pady=(0, 15))
        path_title = ctk.CTkLabel(path_box, text="📁 Local File Path", font=ctk.CTkFont(size=11, weight="bold"), text_color=COLOR_TEXT_MUTED)
        path_title.pack(anchor="w")
        
        path_val = ctk.CTkTextbox(path_box, height=45, font=ctk.CTkFont(size=10, family="Consolas"), fg_color=COLOR_CODE_BG, text_color=COLOR_TEXT_SUB)
        path_val.insert("1.0", res.extension.path)
        path_val.configure(state="disabled")
        path_val.pack(fill="x", pady=2)

        # Separator
        ctk.CTkFrame(self.detail_scroll, height=1, fg_color=COLOR_SEPARATOR).pack(fill="x", pady=10)

        # Parse findings by type
        permissions = [f for f in res.findings if f.finding_type == "permission"]
        signatures = [f for f in res.findings if f.finding_type == "signature"]
        errors = [f for f in res.findings if f.finding_type == "error"]

        # 1. Manifest Error Section
        if errors:
            self.render_detail_section_title("⚠️ CONFIGURATION ISSUES")
            for err in errors:
                self.render_finding_row(err)

        # 2. Permissions Section
        if permissions:
            self.render_detail_section_title("🔑 AUDITED PERMISSIONS")
            for perm in permissions:
                self.render_finding_row(perm)
        else:
            self.render_detail_section_title("🔑 AUDITED PERMISSIONS")
            no_perm_lbl = ctk.CTkLabel(
                self.detail_scroll, 
                text="No high-risk permissions declared in manifest.",
                font=ctk.CTkFont(size=11, slant="italic"),
                text_color=COLOR_TEXT_MUTED
            )
            no_perm_lbl.pack(anchor="w", pady=5)

        # Separator
        ctk.CTkFrame(self.detail_scroll, height=1, fg_color=COLOR_SEPARATOR).pack(fill="x", pady=10)

        # 3. Static Analysis Section
        if signatures:
            self.render_detail_section_title("🔍 STATIC ANALYSIS FINDINGS")
            for sig in signatures:
                self.render_finding_row(sig)
        else:
            self.render_detail_section_title("🔍 STATIC ANALYSIS FINDINGS")
            no_sig_lbl = ctk.CTkLabel(
                self.detail_scroll, 
                text="Static signature scanner completed without findings.",
                font=ctk.CTkFont(size=11, slant="italic"),
                text_color=COLOR_TEXT_MUTED
            )
            no_sig_lbl.pack(anchor="w", pady=5)

    def render_detail_section_title(self, text: str):
        """Helper to render standard header strings in detail panel."""
        lbl = ctk.CTkLabel(
            self.detail_scroll,
            text=text,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLOR_TEXT_MAIN
        )
        lbl.pack(anchor="w", pady=(10, 5))

    def render_finding_row(self, finding: AnalysisFinding):
        """Renders detailed card row for a specific flag, including file snippets if applicable."""
        row_color = COLOR_SAFE
        if finding.severity == FindingSeverity.WARNING:
            row_color = COLOR_WARNING
        elif finding.severity == FindingSeverity.CRITICAL:
            row_color = COLOR_CRITICAL
            
        row_frame = ctk.CTkFrame(self.detail_scroll, fg_color=COLOR_DESC_BG, corner_radius=6)
        row_frame.pack(fill="x", pady=4)
        
        # Grid Configuration for Row
        row_frame.grid_columnconfigure(0, weight=1)
        
        title_bar = ctk.CTkFrame(row_frame, fg_color="transparent")
        title_bar.pack(fill="x", padx=10, pady=(8, 2))
        
        # Left severity tag
        tag = ctk.CTkFrame(title_bar, fg_color=row_color, width=8, height=8, corner_radius=4)
        tag.pack(side="left", padx=(0, 6))
        
        title = ctk.CTkLabel(
            title_bar, 
            text=finding.name, 
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLOR_TEXT_MAIN
        )
        title.pack(side="left")
        
        severity_val = ctk.CTkLabel(
            title_bar, 
            text=finding.severity.value.upper(), 
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=row_color
        )
        severity_val.pack(side="right")

        desc = ctk.CTkLabel(
            row_frame, 
            text=finding.description, 
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_SUB,
            wraplength=310,
            justify="left"
        )
        desc.pack(fill="x", padx=10, pady=(2, 6))

        # Render File Code Snippet if signature finding
        if finding.file_path and finding.snippet:
            snippet_box = ctk.CTkFrame(row_frame, fg_color=COLOR_SNIPPET_BG, corner_radius=4)
            snippet_box.pack(fill="x", padx=10, pady=(0, 8))
            
            # Script Path details
            meta_txt = f"File: {finding.file_path} (Line {finding.line_number})"
            meta_lbl = ctk.CTkLabel(
                snippet_box, 
                text=meta_txt, 
                font=ctk.CTkFont(size=9, family="Consolas"),
                text_color=COLOR_TEXT_MUTED,
                padx=8,
                pady=4
            )
            meta_lbl.pack(anchor="w")
            
            # Exact line code snippet
            code_textbox = ctk.CTkTextbox(
                snippet_box, 
                height=50, 
                font=ctk.CTkFont(size=10, family="Consolas"),
                fg_color=COLOR_CODE_BG,
                text_color=COLOR_TEXT_SUB
            )
            code_textbox.insert("1.0", finding.snippet)
            code_textbox.configure(state="disabled")
            code_textbox.pack(fill="x", padx=6, pady=(0, 6))

    def on_export_clicked(self):
        """Generates a highly aesthetic HTML report of current forensic audit."""
        if not self.all_results:
            messagebox.showwarning("Export Warning", "No extension data available to export. Please run a scan first.")
            return

        target_file = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html")],
            title="Export Forensic Audit Report"
        )
        
        if not target_file:
            return

        try:
            # HTML generation
            html_content = self.generate_audit_html()
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            messagebox.showinfo("Export Successful", f"Forensic report exported successfully to:\n{target_file}")
            
            # Auto-open in standard browser
            webbrowser.open(f"file:///{os.path.abspath(target_file)}")
        except Exception as e:
            logger.exception("Error exporting HTML report")
            messagebox.showerror("Export Error", f"Failed to export report:\n{str(e)}")

    def generate_audit_html(self) -> str:
        """Constructs a responsive, beautifully styled dashboard report in HTML."""
        total = len(self.all_results)
        safe = sum(1 for r in self.all_results if r.risk_level == "Safe")
        warning = sum(1 for r in self.all_results if r.risk_level == "Warning")
        critical = sum(1 for r in self.all_results if r.risk_level == "Critical")
        
        cards_html = ""
        for res in self.all_results:
            findings_html = ""
            for f in res.findings:
                sev_color = "#2ec4b6"
                if f.severity == FindingSeverity.WARNING:
                    sev_color = "#ffb703"
                elif f.severity == FindingSeverity.CRITICAL:
                    sev_color = "#e63946"

                snippet_section = ""
                if f.file_path and f.snippet:
                    snippet_section = f"""
                    <div class="snippet-box">
                        <div class="snippet-meta">File: {f.file_path} (Line {f.line_number})</div>
                        <pre><code>{f.snippet}</code></pre>
                    </div>
                    """
                
                findings_html += f"""
                <div class="finding-row" style="border-left: 4px solid {sev_color};">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 5px;">
                        <span class="finding-name">{f.name}</span>
                        <span class="finding-severity" style="color: {sev_color}; font-weight: bold; font-size: 11px;">{f.severity.value.upper()}</span>
                    </div>
                    <div class="finding-desc">{f.description}</div>
                    {snippet_section}
                </div>
                """
            
            if not findings_html:
                findings_html = "<p class='no-findings'>No risk elements detected in permissions or scripts.</p>"

            badge_color = "#2ec4b6"
            if res.risk_level == "Warning":
                badge_color = "#ffb703"
            elif res.risk_level == "Critical":
                badge_color = "#e63946"

            cards_html += f"""
            <div class="ext-card">
                <div class="ext-header">
                    <div>
                        <span class="browser-badge">{res.extension.browser}</span>
                        <span class="ext-name">{res.extension.name}</span>
                        <div class="ext-id">ID: {res.extension.id}  |  Version: {res.extension.version}</div>
                    </div>
                    <div style="text-align: right;">
                        <span class="risk-badge" style="background-color: {badge_color};">{res.risk_level.upper()}</span>
                        <div class="risk-score">Score: {int(res.risk_score)}/100</div>
                    </div>
                </div>
                <div class="ext-details">
                    <p><strong>Local Path:</strong> <code>{res.extension.path}</code></p>
                    <h4 style="margin-top: 15px; border-bottom: 1px solid #2b3543; padding-bottom: 5px;">Audit Details</h4>
                    {findings_html}
                </div>
            </div>
            """

        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ShadowBlocker Forensic Audit Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #0b0f19;
                    color: #f1f3f5;
                    margin: 0;
                    padding: 0;
                }}
                .header-banner {{
                    background-color: #0f1422;
                    border-bottom: 2px solid #2b3543;
                    padding: 30px 40px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .logo-text {{
                    font-size: 28px;
                    font-weight: bold;
                    color: #ffffff;
                    letter-spacing: 1px;
                }}
                .stats-panel {{
                    display: flex;
                    gap: 15px;
                }}
                .stat-box {{
                    background-color: #171e30;
                    border-radius: 8px;
                    padding: 12px 20px;
                    text-align: center;
                    min-width: 80px;
                }}
                .stat-num {{
                    font-size: 22px;
                    font-weight: bold;
                    margin-bottom: 2px;
                }}
                .stat-lbl {{
                    font-size: 10px;
                    color: #8d99ae;
                    text-transform: uppercase;
                    font-weight: bold;
                }}
                .content-container {{
                    max-width: 1000px;
                    margin: 30px auto;
                    padding: 0 20px;
                }}
                .ext-card {{
                    background-color: #121824;
                    border-radius: 12px;
                    border: 1px solid #1f2738;
                    margin-bottom: 25px;
                    overflow: hidden;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
                }}
                .ext-header {{
                    background-color: #182030;
                    padding: 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    border-bottom: 1px solid #26334d;
                }}
                .ext-name {{
                    font-size: 18px;
                    font-weight: bold;
                    color: #ffffff;
                }}
                .browser-badge {{
                    background-color: #343a40;
                    color: #ced4da;
                    font-size: 10px;
                    font-weight: bold;
                    padding: 3px 8px;
                    border-radius: 4px;
                    margin-right: 8px;
                    vertical-align: middle;
                }}
                .ext-id {{
                    font-size: 12px;
                    color: #8d99ae;
                    margin-top: 5px;
                }}
                .risk-badge {{
                    color: #ffffff;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 6px 14px;
                    border-radius: 6px;
                    display: inline-block;
                }}
                .risk-score {{
                    font-size: 12px;
                    color: #8d99ae;
                    font-weight: bold;
                    margin-top: 5px;
                }}
                .ext-details {{
                    padding: 25px;
                }}
                .finding-row {{
                    background-color: #171f30;
                    border-radius: 6px;
                    padding: 15px;
                    margin-bottom: 12px;
                }}
                .finding-name {{
                    font-weight: bold;
                    font-size: 14px;
                    color: #ffffff;
                }}
                .finding-desc {{
                    font-size: 12px;
                    color: #cbd5e1;
                    margin-top: 6px;
                }}
                .snippet-box {{
                    background-color: #0c0f17;
                    border-radius: 4px;
                    margin-top: 10px;
                    padding: 10px;
                }}
                .snippet-meta {{
                    font-size: 10px;
                    color: #64748b;
                    font-family: monospace;
                    margin-bottom: 5px;
                }}
                pre {{
                    margin: 0;
                    overflow-x: auto;
                }}
                code {{
                    font-family: 'Consolas', 'Courier New', monospace;
                    font-size: 12px;
                    color: #cbd5e1;
                }}
                .no-findings {{
                    color: #2ec4b6;
                    font-style: italic;
                    font-size: 13px;
                }}
            </style>
        </head>
        <body>
            <div class="header-banner">
                <div>
                    <span class="logo-text">🛡️ SHADOWBLOCKER</span>
                    <div style="font-size: 12px; color: #8d99ae; margin-top: 4px;">Forensic Browser Extension Audit Report</div>
                </div>
                <div class="stats-panel">
                    <div class="stat-box">
                        <div class="stat-num" style="color: #ffffff;">{total}</div>
                        <div class="stat-lbl">TOTAL</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-num" style="color: #2ec4b6;">{safe}</div>
                        <div class="stat-lbl">SAFE</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-num" style="color: #ffb703;">{warning}</div>
                        <div class="stat-lbl">WARNING</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-num" style="color: #e63946;">{critical}</div>
                        <div class="stat-lbl">CRITICAL</div>
                    </div>
                </div>
            </div>
            
            <div class="content-container">
                <h2 style="margin-bottom: 20px;">Audited Extensions ({total})</h2>
                {cards_html}
            </div>
        </body>
        </html>
        """
        return html_template

    def toggle_theme(self):
        """Switches between dark and light CustomTkinter color states."""
        current = ctk.get_appearance_mode()
        new_mode = "Light" if current == "Dark" else "Dark"
        ctk.set_appearance_mode(new_mode)
