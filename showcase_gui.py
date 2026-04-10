"""
showcase_gui.py  -  AMTE SecAI SOC Dashboard (Modern Graphing Edition)
"""
import sys, os, time, socket, ctypes, numpy as np
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

_CORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src', 'core')
sys.path.append(_CORE)
import kernel_panel as kp

# --- ADMIN CHECK ---
try: is_admin = os.getuid() == 0
except AttributeError: is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
if not is_admin:
    print("[!] CRITICAL ERROR: You are NOT running as Administrator.")
    sys.exit(1)

# ── Palette & Helpers ────────────────────────────────────────────────────────
C = {
    "bg": "#0b0f19", "panel": "#131a28", "card": "#1c2331", "border": "#2c364c",
    "accent": "#3b82f6", "green": "#10b981", "red": "#ef4444", "yellow": "#f59e0b",
    "inbound": "#10b981", "inbound_fill": "#064e3b", # Green for Inbound
    "outbound": "#8b5cf6", "outbound_fill": "#312e81", # Purple for Outbound
    "grid": "#2c364c", "text": "#f8fafc", "subtext": "#94a3b8",
}

MONO = ("Consolas", 10); MONO9 = ("Consolas", 9); UI = ("Segoe UI", 10)
UI_B = ("Segoe UI", 10, "bold"); UI_S = ("Segoe UI", 9); H1 = ("Segoe UI", 14, "bold")

def proto_name(n): return {1:"ICMP", 6:"TCP", 17:"UDP", 58:"ICMPv6"}.get(int(n), str(int(n)))
def dir_name(d): return "Inbound" if int(d) == 1 else "Outbound"
def fmt_ip(raw, ver):
    try: return socket.inet_ntop(socket.AF_INET6 if int(ver)==6 else socket.AF_INET, bytes(raw[:16] if int(ver)==6 else raw[:4]))
    except Exception: return "?.?.?.?"
def fmt_flags(f):
    b = int(f)
    out = [n for mask, n in [(0x02,"SYN"),(0x10,"ACK"),(0x01,"FIN"),(0x04,"RST"),(0x08,"PSH")] if b & mask]
    return "|".join(out) if out else "None"
def parse_ip(text, ver):
    text = text.strip()
    if not text or text in ("0.0.0.0", "::", "any", ""): return b'\x00' * 16
    return (socket.inet_pton(socket.AF_INET if ver==4 else socket.AF_INET6, text) + b'\x00' * 12)[:16]

# ── Main Application ──────────────────────────────────────────────────────────
class SecAIDashboard(tk.Tk):
    MAX_ROWS = 300
    GRAPH_POINTS = 60

    def __init__(self):
        super().__init__()
        self.title("AMTE SecAI  ·  Security Operations Center")
        self.geometry("1440x900")
        self.configure(bg=C["bg"])

        self._capturing = False
        self._connected = False
        self._total_pkts = 0
        self._start_time = 0.0
        self._last_poll_time = time.time()
        
        self.in_history = [0] * self.GRAPH_POINTS
        self.out_history = [0] * self.GRAPH_POINTS
        self.last_rule_poll = 0

        self._apply_styles()
        self._build_ui()
        self._try_connect()

    def _apply_styles(self):
        s = ttk.Style(self)
        s.theme_use("default")
        s.configure("Treeview", background=C["card"], foreground=C["text"], fieldbackground=C["card"], rowheight=26, font=MONO9, borderwidth=0, relief="flat")
        s.configure("Treeview.Heading", background=C["panel"], foreground=C["subtext"], font=("Segoe UI", 9, "bold"), borderwidth=0, relief="flat")
        s.map("Treeview", background=[("selected", C["accent"])], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        # HEADER
        hdr = tk.Frame(self, bg=C["panel"], height=55)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=" ⬡ AMTE SecAI SOC", font=H1, fg=C["accent"], bg=C["panel"]).pack(side="left", padx=15, pady=10)
        self._status_var = tk.StringVar(value="Disconnected")
        tk.Label(hdr, textvariable=self._status_var, font=UI_B, fg=C["subtext"], bg=C["panel"]).pack(side="right", padx=15)
        self._btn_conn = tk.Button(hdr, text="Connect Kernel", font=UI_B, fg="#ffffff", bg=C["green"], relief="flat", activebackground=C["green"], command=self.connect)
        self._btn_conn.pack(side="right", padx=5, pady=10)

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=15, pady=15)

        # ─── LEFT COLUMN: Telemetry & Task Manager Graph ───
        col_left = tk.Frame(body, bg=C["bg"], width=320); col_left.pack(side="left", fill="y", padx=(0, 15))
        
        m_frame = tk.Frame(col_left, bg=C["card"], padx=15, pady=15); m_frame.pack(fill="x", pady=(0,15))
        tk.Label(m_frame, text="Kernel Ring Buffer", font=UI_B, fg=C["text"], bg=C["card"]).pack(anchor="w", pady=(0,5))
        self._m_head = tk.StringVar(value="Head: 0"); self._m_tail = tk.StringVar(value="Tail: 0")
        self._t_rate = tk.StringVar(value="0 pkts/s")
        for var in [self._m_head, self._m_tail, self._t_rate]:
            tk.Label(m_frame, textvariable=var, font=MONO, fg=C["subtext"], bg=C["card"]).pack(anchor="w", pady=1)

        # High-Res Graph Frame
        g_frame = tk.Frame(col_left, bg=C["card"], padx=15, pady=15); g_frame.pack(fill="both", expand=True)
        
        # Legend
        leg_f = tk.Frame(g_frame, bg=C["card"])
        leg_f.pack(fill="x", pady=(0,8))
        tk.Label(leg_f, text="Network Throughput", font=UI_B, fg=C["text"], bg=C["card"]).pack(side="left")
        tk.Label(leg_f, text="● In", font=UI_S, fg=C["inbound"], bg=C["card"]).pack(side="right", padx=(5,0))
        tk.Label(leg_f, text="● Out", font=UI_S, fg=C["outbound"], bg=C["card"]).pack(side="right")

        self.canvas = tk.Canvas(g_frame, bg=C["panel"], highlightthickness=1, highlightbackground=C["border"])
        self.canvas.pack(fill="both", expand=True)

        # ─── CENTER COLUMN: Stream & Inspector ───
        col_center = tk.Frame(body, bg=C["bg"]); col_center.pack(side="left", fill="both", expand=True, padx=(0, 15))
        
        s_bar = tk.Frame(col_center, bg=C["card"], padx=15, pady=10); s_bar.pack(fill="x", pady=(0,15))
        tk.Label(s_bar, text="Live Packet Stream", font=UI_B, fg=C["text"], bg=C["card"]).pack(side="left")
        self._btn_stream = tk.Button(s_bar, text="▶ Start Streaming", font=UI_B, fg="#ffffff", bg=C["accent"], relief="flat", activebackground=C["accent"], command=self.toggle_capture)
        self._btn_stream.pack(side="right")

        cols = ("Time","IPv","Proto","Src IP","S.Port","Dst IP","D.Port","Dir","Flags")
        self._tree = ttk.Treeview(col_center, columns=cols, show="headings", height=15)
        widths = [70, 40, 50, 120, 55, 120, 55, 65, 80]
        for c, w in zip(cols, widths): self._tree.heading(c, text=c); self._tree.column(c, width=w, anchor="center")
        self._tree.pack(fill="both", expand=True, pady=(0, 15))
        self._tree.bind("<<TreeviewSelect>>", self.inspect_packet)

        i_frame = tk.Frame(col_center, bg=C["card"], padx=15, pady=15); i_frame.pack(fill="x")
        tk.Label(i_frame, text="Packet Inspector", font=UI_B, fg=C["text"], bg=C["card"]).pack(anchor="w", pady=(0,5))
        self._inspector = tk.Text(i_frame, height=6, font=MONO9, bg=C["panel"], fg=C["text"], relief="flat", insertbackground=C["text"])
        self._inspector.pack(fill="x")

        # ─── RIGHT COLUMN: Firewall Manager ───
        col_right = tk.Frame(body, bg=C["bg"], width=350); col_right.pack(side="right", fill="y")
        
        b_frame = tk.Frame(col_right, bg=C["card"], padx=15, pady=15); b_frame.pack(fill="x", pady=(0, 15))
        tk.Label(b_frame, text="⛔ Active Defense (Ring 0)", font=UI_B, fg=C["red"], bg=C["card"]).pack(anchor="w", pady=(0,10))
        
        def lbl_entry(text, default):
            f = tk.Frame(b_frame, bg=C["card"]); f.pack(fill="x", pady=4)
            tk.Label(f, text=text, font=UI_S, fg=C["subtext"], bg=C["card"], width=10, anchor="w").pack(side="left")
            e = tk.Entry(f, font=MONO, bg=C["panel"], fg=C["text"], insertbackground=C["text"], relief="flat"); e.insert(0, default); e.pack(side="left", fill="x", expand=True, ipady=3)
            return e
            
        self._dst_port = lbl_entry("Target Port:", "443")
        self._ttl = lbl_entry("TTL (ms):", "15000")
        tk.Button(b_frame, text="Fire IOCTL Rule", font=UI_B, fg="#ffffff", bg=C["red"], relief="flat", activebackground=C["red"], command=self.fire_block_rule).pack(fill="x", pady=(15,0), ipady=3)

        r_frame = tk.Frame(col_right, bg=C["card"], padx=15, pady=15); r_frame.pack(fill="both", expand=True)
        tk.Label(r_frame, text="Active Blocked Ports", font=UI_B, fg=C["text"], bg=C["card"]).pack(anchor="w", pady=(0,10))
        
        self._rules_tree = ttk.Treeview(r_frame, columns=("Proto", "Port", "TTL"), show="headings", height=8)
        self._rules_tree.heading("Proto", text="Proto"); self._rules_tree.column("Proto", width=60, anchor="center")
        self._rules_tree.heading("Port", text="Port"); self._rules_tree.column("Port", width=80, anchor="center")
        self._rules_tree.heading("TTL", text="TTL ms"); self._rules_tree.column("TTL", width=100, anchor="center")
        self._rules_tree.pack(fill="both", expand=True, pady=(0, 15))

        tk.Button(r_frame, text="🔓 Unblock Selected", font=UI_B, fg="#ffffff", bg=C["yellow"], relief="flat", activebackground=C["yellow"], command=self.unblock_selected).pack(fill="x", ipady=3)

    # ── Logic ────────────────────────────────────────────────────────────────
    def _try_connect(self):
        try: kp.kp_init_driver(); self._connected = True; self._status_var.set("Kernel Connected"); self._status_var.set("Connected")
        except: pass

    def connect(self):
        try: kp.kp_init_driver(); self._connected = True; self._status_var.set("Kernel Connected")
        except Exception as e: messagebox.showerror("Connection Error", str(e))

    def toggle_capture(self):
        if not self._connected: return messagebox.showwarning("Error", "Connect driver first!")
        self._capturing = not self._capturing
        if self._capturing:
            self._btn_stream.config(text="⏸ Stop Streaming", bg=C["yellow"])
            self._start_time = time.time(); self._last_poll_time = time.time()
            self._poll()
        else:
            self._btn_stream.config(text="▶ Start Streaming", bg=C["accent"])

    def inspect_packet(self, event):
        selected = self._tree.selection()
        if not selected: return
        item = self._tree.item(selected[0])['values']
        
        detail = (
            f"--- KERNEL TRANSPORT LAYER ---\n\n"
            f"Timestamp:   {item[0]}\n"
            f"Protocol:    IP{item[1]} / {item[2]}\n"
            f"Direction:   {item[7]}\n"
            f"Source:      {item[3]}:{item[4]}\n"
            f"Destination: {item[5]}:{item[6]}\n"
            f"TCP Flags:   {item[8]}\n"
        )
        self._inspector.config(state="normal")
        self._inspector.delete("1.0", "end")
        self._inspector.insert("end", detail)
        self._inspector.config(state="disabled")

    def _update_graph(self, in_pps, out_pps):
        self.in_history.pop(0)
        self.in_history.append(in_pps)
        self.out_history.pop(0)
        self.out_history.append(out_pps)
        self.canvas.delete("all")
        
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w <= 1: return
        
        # Dynamic Scaling (with a minimum height of 100 to prevent jitter on low traffic)
        max_val = max(max(self.in_history), max(self.out_history), 100)
        max_val = max_val * 1.2 # Add 20% headroom
        dx = w / (self.GRAPH_POINTS - 1)
        
        # 1. Draw Task Manager Grid
        for i in range(1, 4):
            y = h * (i / 4)
            self.canvas.create_line(0, y, w, y, fill=C["grid"], dash=(2, 4))
        
        # Calculate Points
        in_pts, out_pts = [], []
        for i in range(self.GRAPH_POINTS):
            x = i * dx
            yin = h - (self.in_history[i] / max_val * h)
            yout = h - (self.out_history[i] / max_val * h)
            in_pts.extend([x, yin])
            out_pts.extend([x, yout])
            
        # 2. Draw Outbound (Back Layer - Purple)
        if len(out_pts) >= 4:
            poly_out = [0, h] + out_pts + [w, h]
            self.canvas.create_polygon(poly_out, fill=C["outbound_fill"], outline="")
            self.canvas.create_line(out_pts, fill=C["outbound"], width=2, smooth=True)

        # 3. Draw Inbound (Front Layer - Green)
        if len(in_pts) >= 4:
            poly_in = [0, h] + in_pts + [w, h]
            self.canvas.create_polygon(poly_in, fill=C["inbound_fill"], outline="")
            self.canvas.create_line(in_pts, fill=C["inbound"], width=2, smooth=True)

    def _poll(self):
        if not self._capturing: return

        try:
            h, t, c, d = kp.kp_get_metrics()
            self._m_head.set(f"Head: {h}"); self._m_tail.set(f"Tail: {t}")

            batch = kp.kp_read_batch(kp._shared_memory_view)
            
            in_pps = 0
            out_pps = 0
            
            if batch is not None and len(batch) > 0:
                # Fast numpy calculation for the graph (Instantaneous PPS)
                now = time.time()
                dt = max(now - self._last_poll_time, 0.001)
                self._last_poll_time = now
                
                in_count = np.sum(batch['direction'] == 1)
                out_count = len(batch) - in_count
                
                in_pps = int(in_count / dt)
                out_pps = int(out_count / dt)
                
                self._total_pkts += len(batch)
                self._t_rate.set(f"{(in_pps + out_pps):,} pkts/s")

                ui_sample = batch[-15:] if len(batch) > 15 else batch
                for pkt in ui_sample:
                    self._tree.insert("", "end", values=(
                        datetime.now().strftime("%H:%M:%S"), f"v{pkt['ip_version']}", proto_name(pkt['proto']),
                        fmt_ip(pkt['src_ip'], pkt['ip_version']), pkt['src_port'],
                        fmt_ip(pkt['dst_ip'], pkt['ip_version']), pkt['dst_port'],
                        dir_name(pkt['direction']), fmt_flags(pkt['tcp_flags'])
                    ))

                children = self._tree.get_children()
                if len(children) > self.MAX_ROWS:
                    for iid in children[:len(children) - self.MAX_ROWS]: self._tree.delete(iid)
                self._tree.yview_moveto(1.0)
            else:
                self._last_poll_time = time.time()
            
            # Update the dual-line graph
            self._update_graph(in_pps, out_pps)

            # Poll Active Rules
            now = time.time()
            if now - self.last_rule_poll > 1.0:
                self.last_rule_poll = now
                self.refresh_rules()

        except Exception as e:
            print(f"Poll Error: {e}")
            self._capturing = False
            self._btn_stream.config(text="▶ Start Streaming", bg=C["accent"])
            return

        self.after(50, self._poll)

    def fire_block_rule(self):
        if not self._connected: return
        try:
            rule = kp.BlockRuleV1(
                ip_version=4, proto=6,
                src_ip=b'\x00'*16, dst_ip=b'\x00'*16,
                src_port=0, dst_port=int(self._dst_port.get()), ttl_ms=int(self._ttl.get())
            )
            if kp.kp_add_block_rule(rule):
                self.refresh_rules()
            else: messagebox.showerror("Error", "Kernel rejected IOCTL")
        except Exception as e: messagebox.showerror("Error", str(e))

    def refresh_rules(self):
        try:
            rules = kp.kp_get_active_rules()
            for iid in self._rules_tree.get_children(): self._rules_tree.delete(iid)
            for r in rules:
                self._rules_tree.insert("", "end", values=(proto_name(r['proto']), r['dst_port'], r['ttl_ms']))
        except: pass

    def unblock_selected(self):
        selected = self._rules_tree.selection()
        if not selected: return messagebox.showwarning("Warning", "Select a rule to unblock first.")
        
        item = self._rules_tree.item(selected[0])['values']
        target_port = int(item[1])
        
        try:
            if kp.kp_remove_block_rule(target_port):
                self.refresh_rules()
            else:
                messagebox.showerror("Error", f"Kernel failed to remove rule for port {target_port}.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = SecAIDashboard()
    app.mainloop()