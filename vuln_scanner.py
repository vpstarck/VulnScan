import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import subprocess
import platform
import datetime
import json
import re
import sys
import os

# ── Color palette ──────────────────────────────────────────────
BG       = "#0d1117"
PANEL    = "#161b22"
BORDER   = "#30363d"
ACCENT   = "#00d4aa"      # teal-green
WARN     = "#f0a500"
DANGER   = "#ff4444"
LOW      = "#4fc3f7"
TEXT     = "#e6edf3"
SUBTEXT  = "#8b949e"
SUCCESS  = "#3fb950"

FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI", 13, "bold")

# ── Common ports to scan ────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP",  22: "SSH",  23: "Telnet",  25: "SMTP",
    53: "DNS",  80: "HTTP", 110: "POP3",   143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

RISKY_PORTS = {21, 23, 445, 3389, 6379, 27017}   # flagged as high-risk

WEAK_SERVICES = {
    21: "FTP transmits credentials in plaintext.",
    23: "Telnet is unencrypted — replace with SSH.",
    445: "SMB exposed — risk of ransomware / lateral movement.",
    3389: "RDP exposed to internet — brute-force target.",
    6379: "Redis has no auth by default.",
    27017: "MongoDB has no auth by default.",
}

# ── Outdated version patterns ───────────────────────────────────
OUTDATED_PATTERNS = [
    (r"OpenSSH[_ ]([0-6]\.\d)",  "OpenSSH < 7.x — outdated"),
    (r"Apache[/ ]([01]\.\d)",    "Apache < 2.x — very outdated"),
    (r"nginx[/ ](0\.\d)",        "nginx < 1.x — outdated"),
    (r"vsftpd (1\.|2\.[01])",    "vsftpd < 2.2 — outdated"),
]

# ═══════════════════════════════════════════════════════════════
class VulnScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("960x680")
        self.minsize(800, 580)
        self.configure(bg=BG)
        self.resizable(True, True)

        self._scan_thread = None
        self._stop_flag   = False
        self.findings     = []

        self._build_ui()

    # ── UI ──────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header bar
        hdr = tk.Frame(self, bg=PANEL, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="⚡ VulnScan", font=("Segoe UI", 16, "bold"),
                 fg=ACCENT, bg=PANEL).pack(side="left", padx=20, pady=10)
        tk.Label(hdr, text="Vulnerability Scanner — Mini Project",
                 font=("Segoe UI", 9), fg=SUBTEXT, bg=PANEL).pack(side="left", pady=10)

        self.status_dot = tk.Label(hdr, text="●", font=("Segoe UI", 14),
                                   fg=SUBTEXT, bg=PANEL)
        self.status_dot.pack(side="right", padx=18)
        self.status_lbl = tk.Label(hdr, text="Idle", font=FONT_UI,
                                   fg=SUBTEXT, bg=PANEL)
        self.status_lbl.pack(side="right")

        # ── Content area (left config | right log)
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=14, pady=10)

        left  = tk.Frame(body, bg=BG, width=300)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_config(left)
        self._build_log(right)

        # ── Bottom bar
        btm = tk.Frame(self, bg=PANEL, height=46)
        btm.pack(fill="x", side="bottom")
        btm.pack_propagate(False)

        self.btn_scan = tk.Button(
            btm, text="▶  Start Scan", font=("Segoe UI", 10, "bold"),
            bg=ACCENT, fg="#0d1117", activebackground="#00b896",
            relief="flat", padx=18, cursor="hand2",
            command=self._start_scan)
        self.btn_scan.pack(side="left", padx=14, pady=8)

        self.btn_stop = tk.Button(
            btm, text="■  Stop", font=FONT_UI,
            bg=BORDER, fg=TEXT, activebackground=DANGER,
            relief="flat", padx=14, cursor="hand2", state="disabled",
            command=self._stop_scan)
        self.btn_stop.pack(side="left", padx=4, pady=8)

        self.btn_report = tk.Button(
            btm, text="📄  Save Report", font=FONT_UI,
            bg=BORDER, fg=TEXT, activebackground="#30363d",
            relief="flat", padx=14, cursor="hand2",
            command=self._save_report)
        self.btn_report.pack(side="left", padx=4, pady=8)

        self.btn_clear = tk.Button(
            btm, text="🗑  Clear", font=FONT_UI,
            bg=BORDER, fg=SUBTEXT, activebackground="#30363d",
            relief="flat", padx=14, cursor="hand2",
            command=self._clear_log)
        self.btn_clear.pack(side="right", padx=14, pady=8)

        self.progress = ttk.Progressbar(btm, mode="indeterminate", length=160)
        self.progress.pack(side="right", padx=10, pady=14)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TProgressbar", troughcolor=BORDER,
                        background=ACCENT, thickness=6)

    def _build_config(self, parent):
        def section(title):
            f = tk.Frame(parent, bg=PANEL, bd=0)
            f.pack(fill="x", pady=(0, 10))
            tk.Label(f, text=title, font=("Segoe UI", 9, "bold"),
                     fg=ACCENT, bg=PANEL).pack(anchor="w", padx=12, pady=(10, 4))
            return f

        # Target
        s1 = section("TARGET")
        tk.Label(s1, text="Host / IP", font=FONT_UI, fg=SUBTEXT, bg=PANEL).pack(
            anchor="w", padx=12)
        self.entry_host = tk.Entry(s1, font=FONT_UI, bg="#21262d", fg=TEXT,
                                   insertbackground=ACCENT, relief="flat",
                                   bd=0, highlightthickness=1,
                                   highlightbackground=BORDER,
                                   highlightcolor=ACCENT)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.pack(fill="x", padx=12, pady=(2, 10), ipady=6)

        # Port range
        s2 = section("PORT RANGE")
        row = tk.Frame(s2, bg=PANEL)
        row.pack(fill="x", padx=12, pady=(0, 10))
        for lbl, val, attr in [("From", "1", "e_pstart"), ("To", "1024", "e_pend")]:
            c = tk.Frame(row, bg=PANEL)
            c.pack(side="left", fill="x", expand=True, padx=(0, 8))
            tk.Label(c, text=lbl, font=FONT_UI, fg=SUBTEXT, bg=PANEL).pack(anchor="w")
            e = tk.Entry(c, font=FONT_UI, bg="#21262d", fg=TEXT, width=8,
                         insertbackground=ACCENT, relief="flat", bd=0,
                         highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=ACCENT)
            e.insert(0, val)
            e.pack(fill="x", ipady=6)
            setattr(self, attr, e)

        # Scan options
        s3 = section("SCAN MODULES")
        self.opt_ports   = self._checkbox(s3, "Port scanner",           True)
        self.opt_banner  = self._checkbox(s3, "Banner grabbing",         True)
        self.opt_ping    = self._checkbox(s3, "Host ping / reachability", True)
        self.opt_version = self._checkbox(s3, "Outdated version detect",  True)

        # Timeout
        s4 = section("CONNECTION TIMEOUT (s)")
        self.timeout_var = tk.DoubleVar(value=0.5)
        scale_row = tk.Frame(s4, bg=PANEL)
        scale_row.pack(fill="x", padx=12, pady=(0, 10))
        tk.Scale(scale_row, from_=0.1, to=3.0, resolution=0.1,
                 orient="horizontal", variable=self.timeout_var,
                 bg=PANEL, fg=TEXT, activebackground=ACCENT,
                 highlightthickness=0, troughcolor=BORDER,
                 sliderrelief="flat").pack(fill="x")
        self.lbl_timeout = tk.Label(scale_row, textvariable=self.timeout_var,
                                    font=FONT_UI, fg=ACCENT, bg=PANEL)
        self.lbl_timeout.pack()

        # Stats
        s5 = section("LAST SCAN STATS")
        self.stat_open   = self._stat_row(s5, "Open ports",   "—")
        self.stat_vuln   = self._stat_row(s5, "Vulns found",  "—")
        self.stat_time   = self._stat_row(s5, "Duration",     "—")

    def _checkbox(self, parent, label, default):
        var = tk.BooleanVar(value=default)
        cb  = tk.Checkbutton(parent, text=label, variable=var,
                              font=FONT_UI, fg=TEXT, bg=PANEL,
                              selectcolor=PANEL, activebackground=PANEL,
                              activeforeground=ACCENT,
                              highlightthickness=0)
        cb.pack(anchor="w", padx=12, pady=1)
        return var

    def _stat_row(self, parent, label, value):
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill="x", padx=12, pady=1)
        tk.Label(row, text=label, font=FONT_UI, fg=SUBTEXT, bg=PANEL).pack(side="left")
        var = tk.StringVar(value=value)
        tk.Label(row, textvariable=var, font=("Segoe UI", 10, "bold"),
                 fg=ACCENT, bg=PANEL).pack(side="right")
        return var

    def _build_log(self, parent):
        tk.Label(parent, text="SCAN OUTPUT", font=("Segoe UI", 9, "bold"),
                 fg=SUBTEXT, bg=BG).pack(anchor="w", pady=(0, 4))

        self.log = scrolledtext.ScrolledText(
            parent, font=FONT_MONO, bg=PANEL, fg=TEXT,
            insertbackground=ACCENT, relief="flat", bd=0,
            state="disabled", wrap="word",
            highlightthickness=1, highlightbackground=BORDER)
        self.log.pack(fill="both", expand=True)

        # Tags
        self.log.tag_config("head",    foreground=ACCENT,  font=("Courier New", 10, "bold"))
        self.log.tag_config("info",    foreground=TEXT)
        self.log.tag_config("success", foreground=SUCCESS)
        self.log.tag_config("warn",    foreground=WARN)
        self.log.tag_config("danger",  foreground=DANGER)
        self.log.tag_config("low",     foreground=LOW)
        self.log.tag_config("muted",   foreground=SUBTEXT)

    # ── Logging helpers ─────────────────────────────────────────
    def _log(self, text, tag="info"):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.configure(state="disabled")
        self.log.see("end")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.findings.clear()

    # ── Scan control ────────────────────────────────────────────
    def _start_scan(self):
        host = self.entry_host.get().strip()
        if not host:
            messagebox.showwarning("Input", "Enter a target host.")
            return
        try:
            p1 = int(self.e_pstart.get())
            p2 = int(self.e_pend.get())
            assert 1 <= p1 <= p2 <= 65535
        except Exception:
            messagebox.showwarning("Input", "Invalid port range (1–65535).")
            return

        self._stop_flag = False
        self.btn_scan.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.progress.start(10)
        self._set_status("Scanning…", WARN)
        self.findings.clear()

        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(host, p1, p2), daemon=True)
        self._scan_thread.start()

    def _stop_scan(self):
        self._stop_flag = True
        self._set_status("Stopped", DANGER)

    def _set_status(self, text, color=SUBTEXT):
        self.status_lbl.config(text=text, fg=color)
        self.status_dot.config(fg=color)

    # ── Core scan logic ─────────────────────────────────────────
    def _run_scan(self, host, p1, p2):
        start = datetime.datetime.now()
        self._log(f"\n{'═'*58}", "muted")
        self._log(f"  VulnScan Report  —  {start.strftime('%Y-%m-%d %H:%M:%S')}", "head")
        self._log(f"{'═'*58}", "muted")
        self._log(f"  Target : {host}   Ports : {p1}–{p2}", "info")
        self._log(f"{'─'*58}\n", "muted")

        # 1. Ping
        if self.opt_ping.get():
            self._log("[ PING CHECK ]", "head")
            alive = self._ping(host)
            if alive:
                self._log(f"  ✔ Host {host} is reachable.\n", "success")
            else:
                self._log(f"  ✘ Host {host} did not respond to ping.\n", "warn")
            self.findings.append({"type": "ping", "alive": alive})

        # 2. Port scan
        open_ports = []
        if self.opt_ports.get():
            self._log("[ PORT SCAN ]", "head")
            timeout = self.timeout_var.get()
            total   = p2 - p1 + 1

            for i, port in enumerate(range(p1, p2 + 1)):
                if self._stop_flag:
                    break
                banner = ""
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        # Banner grab
                        if self.opt_banner.get():
                            try:
                                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                                banner = s.recv(256).decode(errors="ignore").strip()
                            except Exception:
                                pass
                        s.close()

                        svc  = COMMON_PORTS.get(port, "unknown")
                        risk = "HIGH" if port in RISKY_PORTS else "LOW"
                        tag  = "danger" if risk == "HIGH" else "low"
                        self._log(
                            f"  {'[HIGH]' if risk=='HIGH' else '[ LOW]'} "
                            f"Port {port:5d} ({svc}) — OPEN", tag)

                        if banner:
                            short = banner.split("\n")[0][:80]
                            self._log(f"         Banner: {short}", "muted")

                        # Version check
                        vuln_note = ""
                        if self.opt_version.get() and banner:
                            for pat, msg in OUTDATED_PATTERNS:
                                if re.search(pat, banner, re.I):
                                    vuln_note = msg
                                    self._log(f"         ⚠ {msg}", "warn")
                                    break

                        if port in WEAK_SERVICES:
                            self._log(f"         ⚠ {WEAK_SERVICES[port]}", "warn")

                        open_ports.append(port)
                        self.findings.append({
                            "type": "port", "port": port, "service": svc,
                            "risk": risk, "banner": banner, "vuln_note": vuln_note
                        })
                    else:
                        s.close()
                except Exception:
                    pass

                # Update progress every 50 ports
                if i % 50 == 0:
                    pct = int(i / total * 100)
                    self.after(0, lambda p=pct: self.title(f"VulnScan [{p}%]"))

            if not open_ports:
                self._log("  No open ports found in range.\n", "muted")
            else:
                self._log(f"\n  {len(open_ports)} open port(s) found.\n", "success")

        # ── Summary ─────────────────────────────────────────────
        elapsed = (datetime.datetime.now() - start).total_seconds()
        high    = sum(1 for f in self.findings if f.get("risk") == "HIGH")
        low_cnt = sum(1 for f in self.findings if f.get("risk") == "LOW")

        self._log(f"\n{'─'*58}", "muted")
        self._log("[ SCAN SUMMARY ]", "head")
        self._log(f"  Open ports   : {len(open_ports)}", "info")
        self._log(f"  High-risk    : {high}", "danger" if high else "info")
        self._log(f"  Low-risk     : {low_cnt}", "low")
        self._log(f"  Duration     : {elapsed:.1f}s", "info")
        self._log(f"{'═'*58}\n", "muted")

        # Update stat labels
        self.stat_open.set(str(len(open_ports)))
        self.stat_vuln.set(str(high))
        self.stat_time.set(f"{elapsed:.1f}s")

        self.after(0, self._scan_done)
        self.after(0, lambda: self.title("Vulnerability Scanner"))

    def _scan_done(self):
        self.btn_scan.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.progress.stop()
        if self._stop_flag:
            self._set_status("Stopped", DANGER)
        else:
            self._set_status("Scan complete", SUCCESS)

    # ── Helpers ─────────────────────────────────────────────────
    def _ping(self, host):
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            result = subprocess.run(
                ["ping", param, "1", "-W", "1", host],
                capture_output=True, timeout=3)
            return result.returncode == 0
        except Exception:
            return False

    # ── Report ──────────────────────────────────────────────────
    def _save_report(self):
        if not self.findings:
            messagebox.showinfo("Report", "Run a scan first.")
            return
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        host = self.entry_host.get().strip().replace(".", "_")
        path = f"vuln_report_{host}_{ts}.txt"

        lines = []
        lines.append("=" * 60)
        lines.append("VULNERABILITY SCAN REPORT")
        lines.append(f"Target  : {self.entry_host.get().strip()}")
        lines.append(f"Date    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)

        for f in self.findings:
            if f["type"] == "ping":
                lines.append(f"\n[PING] Host alive: {f['alive']}")
            elif f["type"] == "port":
                lines.append(
                    f"\n[PORT {f['port']}] {f['service']} | Risk: {f['risk']}")
                if f.get("banner"):
                    lines.append(f"  Banner  : {f['banner'][:120]}")
                if f.get("vuln_note"):
                    lines.append(f"  WARNING : {f['vuln_note']}")
                if f["port"] in WEAK_SERVICES:
                    lines.append(f"  WARNING : {WEAK_SERVICES[f['port']]}")

        lines.append("\n" + "=" * 60)
        lines.append(f"Total findings: {len(self.findings)}")
        lines.append("=" * 60)

        with open(path, "w") as fh:
            fh.write("\n".join(lines))

        messagebox.showinfo("Report Saved", f"Report saved to:\n{os.path.abspath(path)}")

# ── Entry point ─────────────────────────────────────────────────
if __name__ == "__main__":
    app = VulnScanner()
    app.mainloop()
