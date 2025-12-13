import customtkinter as ctk
import threading
import sys
import os
import time
import random
from collections import deque
from datetime import datetime

# --- PATH SETUP ---
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
sys.path.append(project_root)

# Import Independent Modules
from src.alert_system.alert_manager import AlertManager

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# --- MOCK BACKEND (Simulating Real-Time Stream) ---
class DashboardBackend:
    def __init__(self):
        # We use a deque with a maxlen to act as a rolling buffer
        # This automatically discards old logs when new ones arrive
        self.logs = deque(maxlen=25)
        self.add_log("System Dashboard Initialized", "Info")
        
        # Start the background thread that listens for "real" events
        threading.Thread(target=self.simulate_incoming_logs, daemon=True).start()

    def get_live_stats(self):
        return {
            "files_scanned": f"{14200 + random.randint(1, 100):,}", 
            "threats_blocked": "3",
            "active_processes": f"{90 + random.randint(1, 5)}",
            "cpu_usage": f"{random.randint(2, 8)}%"
        }

    def get_logs(self):
        # Return logs as a list, newest first
        return list(self.logs)[::-1]

    def add_log(self, event, level):
        now = datetime.now().strftime("%I:%M:%S %p")
        self.logs.append((now, event, level))

    def simulate_incoming_logs(self):
        # In a real app, this loop would be reading from a ZMQ socket or a log file
        events = [
            ("Outbound Connection Blocked (192.168.1.55)", "Warning"),
            ("Database Definition Sync (v2025.4.1)", "Info"),
            ("Process Whitelisted (code.exe)", "Info"),
            ("Heuristic Analysis: Clean", "Info"),
            ("Unauthorized Access Attempt (Admin)", "Critical"),
            ("Memory Integrity Check Passed", "Info"),
            ("Real-Time File Scan: 'suspicious.tmp'", "Info")
        ]
        while True:
            time.sleep(random.uniform(2.0, 6.0)) # Simulate varied traffic
            event, level = random.choice(events)
            self.add_log(event, level)

# --- MAIN DASHBOARD ---
class SecurityDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.backend = DashboardBackend()
        
        # Window Setup
        self.title("AMTE Security Center")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        self.resizable(True, True)

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Loading Screen State
        self.is_loading = True
        self.show_loading_screen()

        # Simulate "Engine Initialization"
        self.after(2000, self.init_main_interface)

    def show_loading_screen(self):
        self.loading_frame = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=0)
        self.loading_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        self.spinner_label = ctk.CTkLabel(self.loading_frame, text="🛡️", font=("Segoe UI Emoji", 80))
        self.spinner_label.place(relx=0.5, rely=0.4, anchor="center")
        
        self.loading_text = ctk.CTkLabel(self.loading_frame, text="Connecting to AMTE Kernel Engine...", font=("Segoe UI", 16))
        self.loading_text.place(relx=0.5, rely=0.55, anchor="center")
        
        self.progress = ctk.CTkProgressBar(self.loading_frame, width=400, mode="indeterminate")
        self.progress.place(relx=0.5, rely=0.6, anchor="center")
        self.progress.start()

    def init_main_interface(self):
        self.loading_frame.destroy()
        self.is_loading = False

        self.current_frame = None
        self.last_known_log_count = 0 
        
        self.setup_sidebar()
        self.setup_main_area()
        
        # Start Data Loops
        self.update_stats_loop()
        self.update_logs_loop()

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1) 

        ctk.CTkLabel(self.sidebar, text="AMTE SecAI", font=("Segoe UI", 26, "bold")).grid(row=0, column=0, padx=20, pady=(40, 5), sticky="w")
        ctk.CTkLabel(self.sidebar, text="Enterprise Dashboard", font=("Segoe UI", 12), text_color="gray").grid(row=1, column=0, padx=20, pady=(0, 40), sticky="w")

        self.nav_btns = {}
        self.nav_btns["Overview"] = self.create_nav_btn("📊  Overview", 2, lambda: self.switch_view("Overview"))
        self.nav_btns["Protection"] = self.create_nav_btn("🛡️  Protection", 3, lambda: self.switch_view("Protection"))
        self.nav_btns["Logs"] = self.create_nav_btn("📜  Threat Logs", 4, lambda: self.switch_view("Logs"))
        
        self.nav_btns["Overview"].configure(fg_color=("gray75", "#3a3a3a"))

        footer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer.grid(row=6, column=0, padx=20, pady=20, sticky="ew")
        
        ctk.CTkLabel(footer, text="Engine Status:", font=("Segoe UI", 12, "bold"), text_color="gray").pack(anchor="w")
        self.engine_lbl = ctk.CTkLabel(footer, text="● ONLINE", font=("Segoe UI", 12, "bold"), text_color="#2ecc71")
        self.engine_lbl.pack(anchor="w")
        self.pulse_engine_status()

    def setup_main_area(self):
        self.main_container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)

        self.views = {}
        self.views["Overview"] = self.create_overview_view()
        self.views["Protection"] = self.create_protection_view()
        self.views["Logs"] = self.create_logs_view()

        self.current_frame = self.views["Overview"]
        self.current_frame.place(relx=0, rely=0, relwidth=1, relheight=1)

    # --- VIEWS ---
    def create_overview_view(self):
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        
        # Status Card
        status_card = ctk.CTkFrame(frame, corner_radius=15, fg_color="#2ecc71", height=140)
        status_card.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(status_card, text="🛡️", font=("Segoe UI Emoji", 50)).pack(side="left", padx=(30, 20))
        text_box = ctk.CTkFrame(status_card, fg_color="transparent")
        text_box.pack(side="left", pady=30)
        ctk.CTkLabel(text_box, text="SYSTEM SECURE", font=("Segoe UI", 28, "bold"), text_color="white").pack(anchor="w")
        ctk.CTkLabel(text_box, text="Real-time protection active", font=("Segoe UI", 14), text_color="white").pack(anchor="w")

        # Stats Grid
        stats_frame = ctk.CTkFrame(frame, fg_color="transparent")
        stats_frame.pack(fill="x", pady=10)
        
        self.stat_labels = {} 
        self.create_stat_card(stats_frame, "Files Scanned", "0", 0, "files_scanned")
        self.create_stat_card(stats_frame, "Threats Blocked", "0", 1, "threats_blocked")
        self.create_stat_card(stats_frame, "CPU Load", "0%", 2, "cpu_usage")

        # Toggles
        toggle_frame = ctk.CTkFrame(frame, corner_radius=10, fg_color=("gray85", "#2b2b2b"))
        toggle_frame.pack(fill="x", pady=20)
        
        ctk.CTkLabel(toggle_frame, text="Active Modules", font=("Segoe UI", 14, "bold"), text_color="gray").pack(anchor="w", padx=20, pady=(15, 5))
        toggles_inner = ctk.CTkFrame(toggle_frame, fg_color="transparent")
        toggles_inner.pack(fill="x", padx=10, pady=(0, 15))
        
        self.create_toggle(toggles_inner, "Real-Time AI", True).pack(side="left", padx=10, expand=True)
        self.create_toggle(toggles_inner, "Cloud Lookup", True).pack(side="left", padx=10, expand=True)
        self.create_toggle(toggles_inner, "Heuristic Engine", True).pack(side="left", padx=10, expand=True)

        return frame

    def create_protection_view(self):
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        ctk.CTkLabel(frame, text="Advanced Protection Settings", font=("Segoe UI", 24, "bold")).pack(anchor="w", pady=20)
        self.create_setting_row(frame, "Deep Packet Inspection", "Analyzes network traffic for anomalies.")
        self.create_setting_row(frame, "Kernel-Level Hooks", "Prevents driver tampering.")
        self.create_setting_row(frame, "Auto-Sample Submission", "Uploads suspicious binaries to cloud sandbox.")
        return frame

    def create_logs_view(self):
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        ctk.CTkLabel(frame, text="Security Event Logs", font=("Segoe UI", 24, "bold")).pack(anchor="w", pady=20)
        self.log_scroll = ctk.CTkScrollableFrame(frame, corner_radius=10, fg_color=("gray90", "#212121"))
        self.log_scroll.pack(fill="both", expand=True)
        return frame

    # --- ANIMATION LOGIC: "RISE UP" TRANSITION ---
    def switch_view(self, view_name):
        target_frame = self.views[view_name]
        if self.current_frame == target_frame: 
            return

        for name, btn in self.nav_btns.items():
            btn.configure(fg_color="transparent")
        self.nav_btns[view_name].configure(fg_color=("gray75", "#3a3a3a"))

        target_frame.place(relx=0, rely=0.03, relwidth=1, relheight=1)
        target_frame.lift()
        self.animate_rise(target_frame, 0.03)
        self.current_frame = target_frame

    def animate_rise(self, frame, current_y):
        if current_y > 0.001:
            new_y = current_y - (current_y * 0.10)
            frame.place(relx=0, rely=new_y, relwidth=1, relheight=1)
            self.after(15, lambda: self.animate_rise(frame, new_y))
        else:
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)

    # --- UPDATES & LOOPS ---
    def update_stats_loop(self):
        stats = self.backend.get_live_stats()
        if "Overview" in self.views and self.stat_labels:
            self.stat_labels["files_scanned"].configure(text=stats["files_scanned"])
            self.stat_labels["threats_blocked"].configure(text=stats["threats_blocked"])
            self.stat_labels["cpu_usage"].configure(text=stats["cpu_usage"])
        self.after(2000, self.update_stats_loop)

    def update_logs_loop(self):
        # 1. Get latest logs from backend
        logs = self.backend.get_logs()
        
        # 2. Compare log count to see if we need an update
        # (In a real app, you might check a timestamp or hash instead)
        if len(logs) != self.last_known_log_count:
             # Only redraw if something changed
            self.refresh_log_ui(logs)
            self.last_known_log_count = len(logs)
            
        self.after(1000, self.update_logs_loop)

    def refresh_log_ui(self, logs):
        # Clear current list
        for widget in self.log_scroll.winfo_children(): 
            widget.destroy()
            
        # Re-populate (since this is a scrolling list, we just dump the new sorted list)
        for l in logs:
            self.add_log_entry(l[0], l[1], l[2])

    def add_log_entry(self, time, event, level):
        row = ctk.CTkFrame(self.log_scroll, fg_color="transparent")
        row.pack(fill="x", pady=5, padx=5)
        
        pill_color = "#3498db" # Info Blue
        text_color = "white"   # White text for Info (Fixed per request)
        
        if level == "Warning": 
            pill_color = "#f1c40f" # Yellow
            text_color = "black"   # Black text for Warning to keep contrast
            
        if level == "Critical": 
            pill_color = "#e74c3c" # Red
            text_color = "white"

        ctk.CTkLabel(row, text=time, width=90, anchor="w", font=("Consolas", 12), text_color="gray").pack(side="left")
        ctk.CTkLabel(row, text=event, anchor="w", font=("Segoe UI", 13)).pack(side="left", padx=10)
        ctk.CTkButton(row, text=level, font=("Segoe UI", 10, "bold"), height=22, width=80, 
                      fg_color=pill_color, text_color=text_color,
                      hover=False, corner_radius=11).pack(side="right")

    def pulse_engine_status(self):
        current_color = self.engine_lbl.cget("text_color")
        new_color = "#27ae60" if current_color == "#2ecc71" else "#2ecc71"
        self.engine_lbl.configure(text_color=new_color)
        self.after(800, self.pulse_engine_status)

    # --- HELPERS ---
    def create_nav_btn(self, text, row, command):
        btn = ctk.CTkButton(self.sidebar, text=text, fg_color="transparent", corner_radius=8, 
                            font=("Segoe UI", 14), height=45, anchor="w", 
                            hover_color=("gray70", "#404040"), command=command)
        btn.grid(row=row, column=0, padx=15, pady=5, sticky="ew")
        return btn

    def create_stat_card(self, parent, title, value, col, key):
        card = ctk.CTkFrame(parent, corner_radius=15, fg_color=("gray85", "#2b2b2b"))
        card.pack(side="left", expand=True, fill="both", padx=5 if col==1 else 0)
        ctk.CTkLabel(card, text=title, font=("Segoe UI", 12, "bold"), text_color="gray").pack(anchor="w", padx=20, pady=(20, 0))
        value_lbl = ctk.CTkLabel(card, text=value, font=("Segoe UI", 28, "bold"))
        value_lbl.pack(anchor="w", padx=20, pady=(0, 20))
        self.stat_labels[key] = value_lbl

    def create_toggle(self, parent, text, default_val):
        switch = ctk.CTkSwitch(parent, text=text, font=("Segoe UI", 13, "bold"), 
                               progress_color="#2ecc71", button_hover_color="#27ae60",
                               button_color="white", switch_height=20, switch_width=40)
        if default_val: switch.select()
        return switch

    def create_setting_row(self, parent, title, desc):
        row = ctk.CTkFrame(parent, fg_color=("gray85", "#2b2b2b"), corner_radius=10)
        row.pack(fill="x", pady=5)
        ctk.CTkLabel(row, text=title, font=("Segoe UI", 14, "bold")).pack(side="left", padx=20, pady=15)
        ctk.CTkLabel(row, text=desc, text_color="gray").pack(side="left", padx=10)
        self.create_toggle(row, "", True).pack(side="right", padx=20)

if __name__ == "__main__":
    app = SecurityDashboard()
    app.mainloop()