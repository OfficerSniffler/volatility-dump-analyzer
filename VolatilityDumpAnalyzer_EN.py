import re
import ipaddress
import threading
import csv
import io
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import defaultdict
from typing import Optional

# Optional GeoIP (pip install geoip2)
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    GEOIP_AVAILABLE = False


# -----------------------------
# Helper / Forensik-Klassifikation
# -----------------------------
def normalize_ip(raw: str) -> str:
    if raw is None:
        return ""
    s = str(raw).strip()
    s = s.replace("[", "").replace("]", "").strip()
    return s


def ip_class(ip_str: str) -> str:
    if not ip_str:
        return "unknown"

    if ip_str in ("*", "0.0.0.0", "::"):
        return "any"

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"

    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_link_local:
        return "link-local"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_unspecified:
        return "unspecified"
    if ip_obj.is_private:
        return "private"
    if getattr(ip_obj, "is_reserved", False):
        return "reserved"
    return "public"


def norm_port(p: str) -> str:
    if p is None:
        return ""
    p = str(p).strip()
    if p in ("*", "-", ""):
        return ""
    if re.fullmatch(r"0+", p):
        return ""
    return p


def safe_int(s: str, default=0) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def guess_header_map(header_row):
    """
    Header-Mapper für windows.netstat CSV. Volatility kann leicht variieren.
    """
    tokens = [str(x).strip().lower() for x in header_row]
    idx = {name: None for name in ("local_ip", "local_port", "remote_ip", "remote_port", "pid", "process", "proto", "state")}

    def find_any(candidates):
        for c in candidates:
            if c in tokens:
                return tokens.index(c)
        return None

    idx["local_ip"] = find_any(["localaddr", "localaddress", "local_addr", "local_address", "local ip", "localip"])
    idx["local_port"] = find_any(["localport", "local_port", "lport", "local port"])
    idx["remote_ip"] = find_any(["remoteaddr", "remoteaddress", "remote_addr", "remote_address",
                                 "foreignaddr", "foreignaddress", "foreign_addr", "foreign_address",
                                 "remote ip", "remoteip", "foreign"])
    idx["remote_port"] = find_any(["remoteport", "remote_port", "rport", "foreignport", "foreign_port", "remote port"])
    idx["pid"] = find_any(["pid", "processid", "process id"])
    idx["process"] = find_any(["process", "owner", "image", "name"])
    idx["proto"] = find_any(["proto", "protocol"])
    idx["state"] = find_any(["state", "connectionstate", "connection state", "status"])

    essential = ("local_ip", "local_port", "remote_ip", "remote_port", "pid", "process")
    if any(idx[k] is None for k in essential):
        return None
    return idx


# -----------------------------
# Main App
# -----------------------------
class SentinelV3:
    # (1) Common suspicious ports (tunable)
    SUSPICIOUS_PORTS = {"4444", "1337", "8080", "8443", "9001", "9002", "31337", "5555"}

    # Common well-known service ports (extend as needed)
    # Used to describe "remote IP connects to local service: <port> (<name>)"
    SERVICE_PORTS = {
        "3389": "RDP",
        "445": "SMB",
        "5985": "WinRM",
        "5986": "WinRM",
        "22": "SSH",
        "21": "FTP",
        "80": "HTTP",
        "443": "HTTPS",
        "135": "RPC",
        "139": "NetBIOS",
        "53": "DNS",
    }

    # Tiered process sets (all lowercase!)
    HIGH_RISK_PROCESSES = {"lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe", "services.exe"}

    LOLBINS = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe",
        "certutil.exe", "bitsadmin.exe", "msiexec.exe", "installutil.exe"
    }

    OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}

    COMMON_NETWORK_PROCS = {
        "svchost.exe", "chrome.exe", "msedge.exe", "firefox.exe",
        "teams.exe", "onedrive.exe", "outlook.exe"
    }

    SUSPICIOUS_PATH_KEYWORDS = {
        "\\appdata\\",
        "\\temp\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\programdata\\",
        "\\public\\",
        "\\recycle",
    }

    def __init__(self, root):
        self.root = root
        self.root.title("Volatility Dump Analyzer")
        self.root.geometry("1650x930")

        # Thread control
        self._cancel_flag = threading.Event()

        # Raw lines for context view
        self.raw_lines = []

        # GeoIP
        self.geoip_path_var = tk.StringVar(value="")
        self._geoip_reader = None  # geoip2.database.Reader or None

        # Correlation inputs
        self.pslist_path_var = tk.StringVar(value="")
        self.cmdline_path_var = tk.StringVar(value="")
        self.pstree_path_var = tk.StringVar(value="")

        self.pslist_by_pid = {}
        self.cmdline_by_pid = {}
        self.pstree_by_pid = {}
        self.proc_by_pid = {}  # unified PID index with chain/path/cmdline

        # Stats per IP
        self.ip_stats = defaultdict(lambda: {
            "local_cnt": 0,
            "remote_cnt": 0,
            "class": "unknown",
            "country": "",
            "chain_preview": "",
            "service_preview": "",
            "services": set(),
            "local_ports": set(),
            "remote_ports": set(),
            "pids": set(),
            "procs": set(),
            "states": set(),
            "protos": set(),
            "lines": []
        })

        self._current_view_ips = []

        self._setup_ui()

    # ---------------- UI ----------------
    def _setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", font=("Consolas", 10), rowheight=26)
        style.map("Treeview", background=[("selected", "#11416d")])

        # Top controls
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Volatility CSV (windows.netstat):").pack(side=tk.LEFT)
        self.path_ent = ttk.Entry(top, width=70)
        self.path_ent.pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Browse", command=self.browse).pack(side=tk.LEFT)

        self.btn_run = ttk.Button(top, text="START ANALYSIS", command=self.start_task)
        self.btn_run.pack(side=tk.LEFT, padx=10)

        self.btn_cancel = ttk.Button(top, text="CANCEL", command=self.cancel_task)
        self.btn_cancel.configure(state="disabled")
        self.btn_cancel.pack(side=tk.LEFT)

        # GeoIP controls
        ttk.Separator(self.root).pack(fill=tk.X, padx=10, pady=4)

        geo = ttk.Frame(self.root, padding=(10, 4))
        geo.pack(fill=tk.X)
        ttk.Label(geo, text="GeoIP DB (GeoLite2 .mmdb):").pack(side=tk.LEFT)
        self.geoip_ent = ttk.Entry(geo, width=60, textvariable=self.geoip_path_var)
        self.geoip_ent.pack(side=tk.LEFT, padx=6)
        ttk.Button(geo, text="Select MMDB", command=self.browse_geoip).pack(side=tk.LEFT)
        ttk.Button(geo, text="Load GeoIP", command=self.load_geoip).pack(side=tk.LEFT, padx=6)

        ttk.Separator(self.root).pack(fill=tk.X, padx=10, pady=4)

        # Correlation inputs
        corr = ttk.Frame(self.root, padding=(10, 4))
        corr.pack(fill=tk.X)

        ttk.Label(corr, text="pslist CSV:").grid(row=0, column=0, sticky="w")
        ttk.Entry(corr, width=65, textvariable=self.pslist_path_var).grid(row=0, column=1, padx=6, sticky="we")
        ttk.Button(corr, text="Browse", command=self.browse_pslist).grid(row=0, column=2, padx=4)

        ttk.Label(corr, text="cmdline CSV:").grid(row=1, column=0, sticky="w")
        ttk.Entry(corr, width=65, textvariable=self.cmdline_path_var).grid(row=1, column=1, padx=6, sticky="we")
        ttk.Button(corr, text="Browse", command=self.browse_cmdline).grid(row=1, column=2, padx=4)

        ttk.Label(corr, text="pstree CSV:").grid(row=2, column=0, sticky="w")
        ttk.Entry(corr, width=65, textvariable=self.pstree_path_var).grid(row=2, column=1, padx=6, sticky="we")
        ttk.Button(corr, text="Browse", command=self.browse_pstree).grid(row=2, column=2, padx=4)

        ttk.Button(corr, text="Load Correlation Data", command=self.load_correlation_inputs).grid(
            row=0, column=3, rowspan=3, padx=12, sticky="ns"
        )
        corr.grid_columnconfigure(1, weight=1)

        # Filter bar
        filt = ttk.Frame(self.root, padding=(10, 6))
        filt.pack(fill=tk.X)

        ttk.Label(filt, text="Search (IP / Process / PID):").pack(side=tk.LEFT)
        self.search_var = tk.StringVar(value="")
        self.search_ent = ttk.Entry(filt, width=30, textvariable=self.search_var)
        self.search_ent.pack(side=tk.LEFT, padx=6)
        self.search_ent.bind("<KeyRelease>", lambda e: self.apply_filters())

        self.only_public_remote = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            filt, text="Only PUBLIC remote", variable=self.only_public_remote, command=self.apply_filters
        ).pack(side=tk.LEFT, padx=10)

        self.only_established = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            filt, text="Only ESTABLISHED", variable=self.only_established, command=self.apply_filters
        ).pack(side=tk.LEFT, padx=10)

        ttk.Label(filt, text="Min Remote Count:").pack(side=tk.LEFT, padx=(14, 0))
        self.min_remote_var = tk.StringVar(value="1")
        self.min_remote_ent = ttk.Entry(filt, width=6, textvariable=self.min_remote_var)
        self.min_remote_ent.pack(side=tk.LEFT, padx=6)
        self.min_remote_ent.bind("<KeyRelease>", lambda e: self.apply_filters())

        ttk.Button(filt, text="Export View (CSV)", command=self.export_view).pack(side=tk.RIGHT)

        # Split panes
        self.paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        preview_frame = ttk.LabelFrame(self.paned, text="Preview (First Lines)")
        self.paned.add(preview_frame, weight=1)
        self.preview_text = tk.Text(preview_frame, height=6, bg="#2d2d2d", fg="#00ff00", font=("Consolas", 9))
        self.preview_text.pack(fill=tk.BOTH, expand=True)

        table_frame = ttk.Frame(self.paned)
        self.paned.add(table_frame, weight=4)

        # Table columns incl. chain preview
        cols = ("top", "ip", "class", "country", "l_count", "r_count", "chain", "svc", "lports", "rports", "state", "proto", "process", "pid")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")

        headers = {
            "top": "!",
            "ip": "IP",
            "class": "CLASS",
            "country": "COUNTRY",
            "l_count": "LOCAL#",
            "r_count": "REMOTE#",
            "chain": "CHAIN (preview)",
            "svc": "SERVICE(S)",
            "lports": "LPORT(S)",
            "rports": "RPORT(S)",
            "state": "STATE(S)",
            "proto": "PROTO(S)",
            "process": "PROZESS(E)",
            "pid": "PID(s)"
        }

        col_widths = {
            "top": 40,
            "ip": 170, "class": 110, "country": 110,
            "l_count": 80, "r_count": 90,
            "chain": 380,
            "svc": 180,
            "lports": 140, "rports": 140,
            "state": 160, "proto": 120,
            "process": 320, "pid": 220
        }

        for col in cols:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self.sort_tree(c))
            anchor = tk.CENTER if col in ("top", "class", "country", "l_count", "r_count", "lports", "rports", "state", "proto", "pid") else tk.W
            self.tree.column(col, width=col_widths[col], anchor=anchor, stretch=(col in ("process", "chain")))


        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(table_frame, command=self.tree.yview)
        self.tree.configure(yscroll=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self.show_context)

        # Row tags
        self.tree.tag_configure("red", foreground="#b00020")
        self.tree.tag_configure("orange", foreground="#d97a00")
        self.tree.tag_configure("top", font=("Consolas", 10, "bold"))

        context_frame = ttk.LabelFrame(self.paned, text="Forensic Details & Row Context")
        self.paned.add(context_frame, weight=3)
        self.context_view = tk.Text(context_frame, bg="white", font=("Consolas", 10), wrap=tk.NONE)
        self.context_view.pack(fill=tk.BOTH, expand=True)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self.root, textvariable=self.status, relief=tk.SUNKEN).pack(side=tk.BOTTOM, fill=tk.X)

    # ---------------- GeoIP ----------------
    def browse_geoip(self):
        f = filedialog.askopenfilename(filetypes=[("MaxMind MMDB", "*.mmdb"), ("All Files", "*.*")])
        if f:
            self.geoip_path_var.set(f)

    def load_geoip(self):
        if not GEOIP_AVAILABLE:
            messagebox.showwarning("GeoIP", "Python-Modul 'geoip2' ist nicht installiert.\n\npip install geoip2")
            return

        path = self.geoip_path_var.get().strip()
        if not path:
            messagebox.showwarning("GeoIP", "Please select a .mmdb file (e.g., GeoLite2-Country.mmdb).")
            return

        try:
            if self._geoip_reader:
                try:
                    self._geoip_reader.close()
                except Exception:
                    pass
            self._geoip_reader = geoip2.database.Reader(path)
            messagebox.showinfo("GeoIP", "GeoIP database loaded.")
            self._enrich_all_countries()
            self.apply_filters()
        except Exception as e:
            messagebox.showerror("GeoIP", f"Konnte MMDB nicht laden:\n{e}")

    def _geoip_country(self, ip_str: str) -> str:
        if not self._geoip_reader:
            return ""
        try:
            if ip_class(ip_str) != "public":
                return ""
            resp = self._geoip_reader.country(ip_str)
            return resp.country.iso_code or ""
        except Exception:
            return ""

    def _enrich_all_countries(self):
        if not self._geoip_reader:
            return
        for ip_str, s in self.ip_stats.items():
            if not s.get("country"):
                s["country"] = self._geoip_country(ip_str)

    # ---------------- Correlation IO ----------------
    def browse_pslist(self):
        f = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if f:
            self.pslist_path_var.set(f)

    def browse_cmdline(self):
        f = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if f:
            self.cmdline_path_var.set(f)

    def browse_pstree(self):
        f = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if f:
            self.pstree_path_var.set(f)

    def load_correlation_inputs(self):
        """
        Lädt pslist/cmdline/pstree und baut proc_by_pid inkl. parent chain.
        """
        try:
            self.pslist_by_pid = self._load_pslist(self.pslist_path_var.get().strip()) if self.pslist_path_var.get().strip() else {}
            self.cmdline_by_pid = self._load_cmdline(self.cmdline_path_var.get().strip()) if self.cmdline_path_var.get().strip() else {}
            self.pstree_by_pid = self._load_pstree(self.pstree_path_var.get().strip()) if self.pstree_path_var.get().strip() else {}

            self.proc_by_pid = self._build_proc_index(self.pslist_by_pid, self.cmdline_by_pid, self.pstree_by_pid)

            messagebox.showinfo(
                "Correlation",
                f"Geladen: pslist={len(self.pslist_by_pid)} PIDs, cmdline={len(self.cmdline_by_pid)} PIDs, pstree={len(self.pstree_by_pid)} PIDs\n"
                f"Proc-Index: {len(self.proc_by_pid)} PIDs"
            )

            # re-render table to fill chain preview
            self.apply_filters()

        except Exception as e:
            messagebox.showerror("Correlation", str(e))

    # ---------------- Core helper: suspicious path / chain ----------------
    def _is_suspicious_path(self, path: str) -> bool:
        if not path:
            return False
        p = path.lower()
        return any(k in p for k in self.SUSPICIOUS_PATH_KEYWORDS)

    def _detect_suspicious_chain(self, chain: str) -> Optional[str]:
        if not chain:
            return None
        c = chain.lower()

        # Office -> PowerShell
        if "winword.exe" in c and "powershell.exe" in c:
            return "Office → PowerShell execution"
        if "excel.exe" in c and "powershell.exe" in c:
            return "Excel → PowerShell execution"
        if "powerpnt.exe" in c and "powershell.exe" in c:
            return "PowerPoint → PowerShell execution"
        if "outlook.exe" in c and "powershell.exe" in c:
            return "Outlook → PowerShell execution"

        # Office -> CMD
        if ("winword.exe" in c or "excel.exe" in c or "powerpnt.exe" in c) and "cmd.exe" in c:
            return "Office → CMD execution"

        # CMD -> PowerShell
        if "cmd.exe" in c and "powershell.exe" in c:
            return "CMD → PowerShell chain"

        # Script hosts
        if "wscript.exe" in c or "cscript.exe" in c:
            return "Script host execution"

        # MSHTA
        if "mshta.exe" in c:
            return "MSHTA execution (LOLBIN)"

        return None

    def _make_chain_preview_for_ip(self, pid_set, max_chains=2, max_len=110) -> str:
        if not self.proc_by_pid or not pid_set:
            return ""

        pid_ints = []
        for p in pid_set:
            pi = safe_int(p, -1)
            if pi >= 0:
                pid_ints.append(pi)

        chains = []
        seen = set()

        for pid in sorted(set(pid_ints)):
            pr = self.proc_by_pid.get(pid)
            if not pr:
                continue
            img = pr.get("image", "") or "?"
            chain = pr.get("chain", "")
            full = f"{chain} -> {img}({pid})" if chain else f"{img}({pid})"
            if full not in seen:
                seen.add(full)
                chains.append(full)

        if not chains:
            return ""

        chains.sort(key=lambda s: (-len(s), s))
        out = []
        for c in chains[:max_chains]:
            c2 = c if len(c) <= max_len else c[: max_len - 1] + "…"
            out.append(c2)

        return " | ".join(out)

    # ---------------- CSV loading ----------------
    def read_with_encoding(self, path, limit=None):
        # binary read for BOM / null-byte detection
        with open(path, "rb") as bf:
            raw = bf.read()

        if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            enc = "utf-16"
        elif raw.startswith(b"\xef\xbb\xbf"):
            enc = "utf-8-sig"
        else:
            enc = "utf-16" if raw.count(b"\x00") > 0 else "utf-8"

        try:
            text = raw.decode(enc, errors="replace")
        except Exception:
            text = raw.decode("latin-1", errors="replace")
            enc = "latin-1"

        if limit is not None:
            lines = text.splitlines(True)
            return "".join(lines[:limit]), enc

        return text.splitlines(True), enc

    def _read_csv_rows(self, path: str):
        lines, _ = self.read_with_encoding(path)
        text = "".join(lines)
        sample = text[:20000]

        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=";,|\t,")
        except Exception:
            dialect = csv.excel

        f_buffer = io.StringIO(text)
        reader = csv.reader(f_buffer, dialect)

        rows = []
        header = None
        for row in reader:
            if not row or all(not str(x).strip() for x in row):
                continue
            if header is None:
                header = [str(x).strip() for x in row]
                continue
            rows.append(row)

        header_tokens = [h.strip() for h in (header or [])]
        return rows, header_tokens

    def _col_index(self, header_tokens, name: str):
        name_l = name.lower()
        for i, h in enumerate(header_tokens):
            if h.lower() == name_l:
                return i
        return None

    def _load_pslist(self, path: str):
        rows, hdr = self._read_csv_rows(path)
        i_pid = self._col_index(hdr, "PID")
        i_ppid = self._col_index(hdr, "PPID")
        i_img = self._col_index(hdr, "ImageFileName")
        i_ct = self._col_index(hdr, "CreateTime")

        if None in (i_pid, i_ppid, i_img):
            raise ValueError("pslist: benötigte Spalten fehlen (PID, PPID, ImageFileName).")

        out = {}
        for r in rows:
            pid = safe_int(r[i_pid], -1)
            if pid < 0:
                continue
            out[pid] = {
                "pid": pid,
                "ppid": safe_int(r[i_ppid], 0),
                "image": str(r[i_img]).strip(),
                "createtime": str(r[i_ct]).strip() if i_ct is not None and i_ct < len(r) else ""
            }
        return out

    def _load_cmdline(self, path: str):
        rows, hdr = self._read_csv_rows(path)
        i_pid = self._col_index(hdr, "PID")
        i_proc = self._col_index(hdr, "Process")
        i_args = self._col_index(hdr, "Args")

        if None in (i_pid, i_proc, i_args):
            raise ValueError("cmdline: benötigte Spalten fehlen (PID, Process, Args).")

        out = {}
        for r in rows:
            pid = safe_int(r[i_pid], -1)
            if pid < 0:
                continue
            args = str(r[i_args]).strip()
            proc = str(r[i_proc]).strip()
            prev = out.get(pid, {})
            if (not prev) or (len(args) > len(prev.get("args", ""))):
                out[pid] = {"pid": pid, "process": proc, "args": args}
        return out

    def _load_pstree(self, path: str):
        rows, hdr = self._read_csv_rows(path)
        i_pid = self._col_index(hdr, "PID")
        i_ppid = self._col_index(hdr, "PPID")
        i_img = self._col_index(hdr, "ImageFileName")
        i_cmd = self._col_index(hdr, "Cmd")
        i_path = self._col_index(hdr, "Path")

        if None in (i_pid, i_ppid, i_img):
            raise ValueError("pstree: benötigte Spalten fehlen (PID, PPID, ImageFileName).")

        out = {}
        for r in rows:
            pid = safe_int(r[i_pid], -1)
            if pid < 0:
                continue
            out[pid] = {
                "pid": pid,
                "ppid": safe_int(r[i_ppid], 0),
                "image": str(r[i_img]).strip(),
                "cmd": str(r[i_cmd]).strip() if i_cmd is not None and i_cmd < len(r) else "",
                "path": str(r[i_path]).strip() if i_path is not None and i_path < len(r) else "",
            }
        return out

    def _build_proc_index(self, pslist_by_pid, cmdline_by_pid, pstree_by_pid):
        all_pids = set(pslist_by_pid.keys()) | set(cmdline_by_pid.keys()) | set(pstree_by_pid.keys())
        proc = {}

        for pid in all_pids:
            ps = pslist_by_pid.get(pid, {})
            pt = pstree_by_pid.get(pid, {})
            cl = cmdline_by_pid.get(pid, {})

            image = (ps.get("image") or pt.get("image") or cl.get("process") or "").strip()
            ppid = ps.get("ppid")
            if ppid is None:
                ppid = pt.get("ppid", 0)

            cmdline = (cl.get("args") or pt.get("cmd") or "").strip()
            path = (pt.get("path") or "").strip()
            createtime = (ps.get("createtime") or "").strip()

            mismatch_ppid = False
            if ps and pt and (ps.get("ppid") is not None) and (pt.get("ppid") is not None):
                mismatch_ppid = (safe_int(ps.get("ppid"), 0) != safe_int(pt.get("ppid"), 0))

            proc[pid] = {
                "pid": pid,
                "ppid": safe_int(ppid, 0),
                "image": image,
                "cmdline": cmdline,
                "path": path,
                "createtime": createtime,
                "ppid_mismatch": mismatch_ppid,
                "chain": "",
                "root": ""
            }

        def name_of(x):
            return proc.get(x, {}).get("image", "") or "?"

        for pid in list(proc.keys()):
            chain = []
            visited = set()
            cur = pid
            depth = 0
            while True:
                if cur in visited:
                    chain.append("LOOP(?)")
                    break
                visited.add(cur)

                ppid = proc.get(cur, {}).get("ppid", 0)
                if ppid in (0, None):
                    break

                chain.append(f"{name_of(ppid)}({ppid})")
                cur = ppid
                depth += 1
                if depth > 30:
                    chain.append("DEPTH_LIMIT")
                    break

            proc[pid]["chain"] = " -> ".join(reversed(chain)) if chain else ""
            proc[pid]["root"] = chain[-1] if chain else f"{name_of(pid)}({pid})"

        return proc

    # ---------------- Netstat IO ----------------
    def browse(self):
        f = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if f:
            self.path_ent.delete(0, tk.END)
            self.path_ent.insert(0, f)
            self.check_preview(f)

    def check_preview(self, path):
        self.preview_text.delete("1.0", tk.END)
        content, _ = self.read_with_encoding(path, limit=10)
        if isinstance(content, list):
            content = "".join(content)
        self.preview_text.insert(tk.END, content)

    # ---------------- Thread control ----------------
    def start_task(self):
        try:
            path = self.path_ent.get().strip()
            if not path:
                messagebox.showwarning("Notice", "Please select a CSV file.")
                return

            # optional: autoload correlation if paths are set (non-blocking for user)
            if any(v.get().strip() for v in (self.pslist_path_var, self.cmdline_path_var, self.pstree_path_var)):
                self.load_correlation_inputs()

            self._cancel_flag.clear()
            self.btn_run.configure(state="disabled")
            self.btn_cancel.configure(state="normal")
            self.status.set("Analysis running...")

            t = threading.Thread(target=self.analyze, args=(path,), daemon=True)
            t.start()

        except Exception as e:
            messagebox.showerror("Error in start_task()", str(e))
            self.btn_run.configure(state="normal")
            self.btn_cancel.configure(state="disabled")
            self.status.set("Ready.")

    def cancel_task(self):
        self._cancel_flag.set()
        self.status.set("Cancellation requested...")

    # ---------------- Core analysis (netstat) ----------------
    def analyze(self, path):
        processed_rows = 0
        cancelled = False

        try:
            lines, enc = self.read_with_encoding(path)
            self.raw_lines = lines
            self.ip_stats.clear()

            text = "".join(lines)

            sample = text[:20000]
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=";,|\t,")
            except Exception:
                dialect = csv.excel

            f_buffer = io.StringIO(text)
            reader = csv.reader(f_buffer, dialect)

            header_map = None
            first_row = None
            MAX_CONTEXT_LINES_PER_IP = 60

            for idx, row in enumerate(reader):
                if self._cancel_flag.is_set():
                    cancelled = True
                    break

                if not row or all(not str(x).strip() for x in row):
                    continue

                if first_row is None:
                    first_row = row
                    header_map = guess_header_map(first_row)
                    if header_map is not None:
                        continue  # skip header

                if idx % 5000 == 0:
                    self.root.after(
                        0,
                        lambda i=idx, e=enc: self.status.set(f"Analysis running... Line {i:,} (Encoding: {e})")
                    )

                parsed = self._parse_row(row, header_map)
                if not parsed:
                    continue

                (l_ip, l_port, r_ip, r_port, pid, process, proto, state) = parsed

                self._add_ip_entry(l_ip, l_port, pid, process, proto, state, idx, True, svc_port=r_port, max_context=MAX_CONTEXT_LINES_PER_IP)
                self._add_ip_entry(r_ip, r_port, pid, process, proto, state, idx, False, svc_port=l_port, max_context=MAX_CONTEXT_LINES_PER_IP)

                processed_rows += 1

            if self._geoip_reader:
                self._enrich_all_countries()

        except Exception as e:
            self.root.after(0, lambda err=e: messagebox.showerror("Analysis failed", str(err)))

        finally:
            self.root.after(0, lambda: self.finish_ui(processed_rows, cancelled=cancelled))

    def _parse_row(self, row, header_map):
        try:
            if header_map:
                l_ip = row[header_map["local_ip"]].strip()
                l_port = row[header_map["local_port"]].strip()
                r_ip = row[header_map["remote_ip"]].strip()
                r_port = row[header_map["remote_port"]].strip()
                pid = row[header_map["pid"]].strip()
                process = row[header_map["process"]].strip()
                proto = row[header_map["proto"]].strip() if header_map.get("proto") is not None else ""
                state = row[header_map["state"]].strip() if header_map.get("state") is not None else ""
                return (l_ip, l_port, r_ip, r_port, pid, process, proto, state)

            # fallback indices (Volatility 3 typical)
            if len(row) < 10:
                return None
            l_ip, l_port = row[3].strip(), row[4].strip()
            r_ip, r_port = row[5].strip(), row[6].strip()
            pid, process = row[8].strip(), row[9].strip()
            proto = row[1].strip() if len(row) > 1 else ""
            state = row[7].strip() if len(row) > 7 else ""
            return (l_ip, l_port, r_ip, r_port, pid, process, proto, state)
        except Exception:
            return None

    def _add_ip_entry(self, ip_raw, port, pid, process, proto, state, line_idx, is_local, svc_port=None, max_context=60):
        ip_s = normalize_ip(ip_raw)
        if not ip_s:
            return

        cls = ip_class(ip_s)

        # validate real IPs, but allow wildcards/unknown
        if cls not in ("any", "unknown"):
            try:
                ipaddress.ip_address(ip_s)
            except ValueError:
                return

        p = norm_port(port)
        pid_s = str(pid).strip()
        proc_s = str(process).strip()
        proto_s = str(proto).strip()
        state_s = str(state).strip()

        rec = self.ip_stats[ip_s]
        rec["class"] = cls

        # Service correlation: map well-known service ports to a friendly name
        svc_p = norm_port(svc_port) if svc_port is not None else ""
        if svc_p and svc_p in self.SERVICE_PORTS:
            rec["services"].add(f"{self.SERVICE_PORTS[svc_p]}:{svc_p}")

        if is_local:
            rec["local_cnt"] += 1
            if p:
                rec["local_ports"].add(p)
        else:
            rec["remote_cnt"] += 1
            if p:
                rec["remote_ports"].add(p)

        if pid_s:
            rec["pids"].add(pid_s)
        if proc_s:
            rec["procs"].add(proc_s)
        if proto_s:
            rec["protos"].add(proto_s)
        if state_s:
            rec["states"].add(state_s)

        if len(rec["lines"]) < max_context:
            rec["lines"].append(line_idx)

    # ---------------- UI update + filtering ----------------
    def finish_ui(self, processed_rows, cancelled=False):
        self.btn_run.configure(state="normal")
        self.btn_cancel.configure(state="disabled")

        if cancelled:
            self.status.set(f"Cancelled. {len(self.ip_stats)} IPs partially processed (Rows: {processed_rows:,}).")
        else:
            self.status.set(f"Analysis finished. {len(self.ip_stats)} IPs processed (Rows: {processed_rows:,}).")

        self.apply_filters()

    def apply_filters(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        q = self.search_var.get().strip().lower()
        only_pub_remote = self.only_public_remote.get()
        only_est = self.only_established.get()
        min_remote = safe_int(self.min_remote_var.get(), default=1)

        items = sorted(
            self.ip_stats.items(),
            key=lambda x: (x[1]["remote_cnt"], x[1]["local_cnt"]),
            reverse=True
        )

        # top talker threshold in filtered baseline
        base_for_top = []
        for ip_str, s in items:
            if s["remote_cnt"] < min_remote:
                continue
            if only_pub_remote and (s["class"] != "public" or s["remote_cnt"] <= 0):
                continue
            base_for_top.append((ip_str, s))

        TOP_N = 10
        remote_counts_sorted = sorted((s["remote_cnt"] for _, s in base_for_top), reverse=True) or [999999999]
        thresh = remote_counts_sorted[min(TOP_N - 1, len(remote_counts_sorted) - 1)]

        self._current_view_ips = []

        for ip_str, s in items:
            # Filters
            if s["remote_cnt"] < min_remote:
                continue
            if only_pub_remote and (s["class"] != "public" or s["remote_cnt"] <= 0):
                continue
            if only_est and (not any("established" in st.lower() for st in s["states"])):
                continue

            if q:
                hay = " ".join([
                    ip_str.lower(),
                    " ".join(p.lower() for p in s["procs"]),
                    " ".join(str(p).lower() for p in s["pids"]),
                    " ".join(st.lower() for st in s["states"]),
                    " ".join(pr.lower() for pr in s["protos"]),
                    str(s.get("country", "")).lower(),
                ])
                if q not in hay:
                    continue

            # String fields
            lports = ", ".join(sorted(s["local_ports"], key=lambda x: int(x) if x.isdigit() else 999999))
            rports = ", ".join(sorted(s["remote_ports"], key=lambda x: int(x) if x.isdigit() else 999999))
            pids = ", ".join(sorted(s["pids"], key=lambda x: int(x) if x.isdigit() else 999999))
            procs = ", ".join(sorted(s["procs"]))
            states = ", ".join(sorted(s["states"]))
            protos = ", ".join(sorted(s["protos"]))
            country = s.get("country", "")

            # chain preview (cached)
            chain_preview = self._make_chain_preview_for_ip(s["pids"], max_chains=2, max_len=110)
            s["chain_preview"] = chain_preview

            # service preview (e.g., RDP:3389) derived from per-connection correlation
            service_preview = ", ".join(sorted(s.get("services", set())))
            s["service_preview"] = service_preview

            # suspicious ports
            has_susp_port = any(p in self.SUSPICIOUS_PORTS for p in (s["remote_ports"] | s["local_ports"]))

            # tiered process risk when talking to public IPs
            procs_lower = {p.lower() for p in s["procs"]}
            talks_to_public = (s["class"] == "public" and s["remote_cnt"] > 0)

            has_high_risk_proc = talks_to_public and any(p in self.HIGH_RISK_PROCESSES for p in procs_lower)
            has_lolbin_proc = talks_to_public and any(p in self.LOLBINS for p in procs_lower)
            has_office_proc = talks_to_public and any(p in self.OFFICE_PROCESSES for p in procs_lower)
            has_unknown_proc = talks_to_public and any(
                p not in (self.HIGH_RISK_PROCESSES | self.LOLBINS | self.OFFICE_PROCESSES | self.COMMON_NETWORK_PROCS)
                for p in procs_lower
            )

            # suspicious path via PID correlation
            has_susp_path = False
            if talks_to_public and self.proc_by_pid and s["pids"]:
                for pid_s in s["pids"]:
                    pid_i = safe_int(pid_s, -1)
                    pr = self.proc_by_pid.get(pid_i)
                    if pr and self._is_suspicious_path(pr.get("path", "")):
                        has_susp_path = True
                        break

            # top talker
            top_flag = "!" if (s["remote_cnt"] >= thresh and s["remote_cnt"] > 0) else ""

            tags = []
            # red has precedence
            if has_high_risk_proc or has_susp_path:
                tags.append("red")
            elif has_lolbin_proc or has_office_proc or has_unknown_proc or has_susp_port:
                tags.append("orange")
            if top_flag == "!":
                tags.append("top")

            self.tree.insert("", tk.END, values=(
                top_flag,
                ip_str,
                s["class"],
                country,
                s["local_cnt"],
                s["remote_cnt"],
                chain_preview,
                service_preview,
                lports,
                rports,
                states,
                protos,
                procs,
                pids
            ), tags=tuple(tags))

            self._current_view_ips.append(ip_str)

    def show_context(self, event):
        sel = self.tree.selection()
        if not sel:
            return

        vals = self.tree.item(sel[0])["values"]
        ip = vals[1]  # because first col is "top"

        s = self.ip_stats.get(ip)
        if not s:
            return

        talks_to_public = (s["class"] == "public" and s["remote_cnt"] > 0)

        # flags overview
        has_susp_port = any(p in self.SUSPICIOUS_PORTS for p in (s["remote_ports"] | s["local_ports"]))
        sp = sorted((s["remote_ports"] | s["local_ports"]) & self.SUSPICIOUS_PORTS)

        high_hits = sorted(p for p in s["procs"] if p.lower() in self.HIGH_RISK_PROCESSES)
        lol_hits = sorted(p for p in s["procs"] if p.lower() in self.LOLBINS)
        off_hits = sorted(p for p in s["procs"] if p.lower() in self.OFFICE_PROCESSES)
        unknown_hits = sorted(
            p for p in s["procs"]
            if p.lower() not in (self.HIGH_RISK_PROCESSES | self.LOLBINS | self.OFFICE_PROCESSES | self.COMMON_NETWORK_PROCS)
        )

        self.context_view.delete("1.0", tk.END)
        self.context_view.insert(tk.END, f"=== Forensic log for IP: {ip} ({s['class']}) ===\n\n")
        if s.get("country"):
            self.context_view.insert(tk.END, f"GeoIP Country: {s['country']}\n")

        self.context_view.insert(
            tk.END,
            f"Summary: LOCAL={s['local_cnt']} | REMOTE={s['remote_cnt']} | "
            f"LPorts={len(s['local_ports'])} | RPorts={len(s['remote_ports'])} | "
            f"PIDs={len(s['pids'])} | Prozesse={len(s['procs'])}\n"
        )

        # risk flags after summary
        if talks_to_public:
            if high_hits:
                self.context_view.insert(tk.END, f"[FLAG][HIGH] High-risk process to PUBLIC IP: {', '.join(high_hits)}\n")
            if lol_hits:
                self.context_view.insert(tk.END, f"[FLAG][MED] LOLBin to PUBLIC IP: {', '.join(lol_hits)}\n")
            if off_hits:
                self.context_view.insert(tk.END, f"[FLAG][MED] Office process to PUBLIC IP: {', '.join(off_hits)}\n")
            if unknown_hits:
                self.context_view.insert(tk.END, f"[FLAG][MED] Unknown process name(s) to PUBLIC IP: {', '.join(unknown_hits)}\n")

        if has_susp_port:
            self.context_view.insert(tk.END, f"[FLAG][MED] Suspicious Port(s): {', '.join(sp)}\n")

        # Service correlation output for selected IP
        if s.get("services"):
            # format: ["RDP:3389", ...] -> "3389 (RDP)"
            svc_fmt = []
            for item in sorted(s["services"]):
                if ":" in item:
                    name, port = item.split(":", 1)
                    svc_fmt.append(f"{port} ({name})")
                else:
                    svc_fmt.append(item)
            self.context_view.insert(tk.END, f"Connects to local service(s): {', '.join(svc_fmt)}\n")

        # PID correlation block
        if self.proc_by_pid and s["pids"]:
            self.context_view.insert(tk.END, "\n=== PID Correlation (pslist/cmdline/pstree) ===\n")

            pid_ints = []
            for p in s["pids"]:
                pi = safe_int(p, -1)
                if pi >= 0:
                    pid_ints.append(pi)

            for pid in sorted(set(pid_ints)):
                pr = self.proc_by_pid.get(pid)
                if not pr:
                    self.context_view.insert(tk.END, f"- PID {pid}: (keine Correlation gefunden)\n")
                    continue

                chain = pr.get("chain", "")
                chain_flag = self._detect_suspicious_chain(chain)
                if chain_flag and talks_to_public:
                    self.context_view.insert(tk.END, f"[FLAG][HIGH] Suspicious process chain detected: {chain_flag}\n")

                proc_name = (pr.get("image", "") or "").lower()
                path = pr.get("path", "") or ""
                is_unknown_proc = proc_name and (proc_name not in (self.HIGH_RISK_PROCESSES | self.LOLBINS | self.OFFICE_PROCESSES | self.COMMON_NETWORK_PROCS))
                is_susp_path = self._is_suspicious_path(path)

                if talks_to_public and is_unknown_proc and is_susp_path:
                    self.context_view.insert(tk.END, "[FLAG][CRITICAL] Unknown process from suspicious path communicating with PUBLIC IP\n")
                elif talks_to_public and is_susp_path:
                    self.context_view.insert(tk.END, f"[FLAG][HIGH] Process running from suspicious path: {path}\n")

                parent = pr.get("ppid", 0)
                parent_name = self.proc_by_pid.get(parent, {}).get("image", "?") if parent else "N/A"
                mismatch = " [PPID-MISMATCH]" if pr.get("ppid_mismatch") else ""

                self.context_view.insert(
                    tk.END,
                    f"- PID {pid}{mismatch}\n"
                    f"  Image: {pr.get('image','')}\n"
                    f"  PPID: {parent} ({parent_name})\n"
                )
                if pr.get("createtime"):
                    self.context_view.insert(tk.END, f"  CreateTime: {pr.get('createtime')}\n")
                if pr.get("path"):
                    self.context_view.insert(tk.END, f"  Path: {pr.get('path')}\n")
                if pr.get("cmdline"):
                    self.context_view.insert(tk.END, f"  Cmdline: {pr.get('cmdline')}\n")
                if pr.get("chain"):
                    self.context_view.insert(tk.END, f"  ParentChain: {pr.get('chain')}\n")
                self.context_view.insert(tk.END, "\n")

        if s["states"]:
            self.context_view.insert(tk.END, f"States: {', '.join(sorted(s['states']))}\n")
        if s["protos"]:
            self.context_view.insert(tk.END, f"Protos: {', '.join(sorted(s['protos']))}\n")

        self.context_view.insert(tk.END, "-" * 95 + "\n")

        for line_idx in s["lines"]:
            if 0 <= line_idx < len(self.raw_lines):
                raw = self.raw_lines[line_idx].rstrip("\n")
                self.context_view.insert(tk.END, f"[Line {line_idx + 1}]\nRAW: {raw}\n" + "." * 95 + "\n")

    # ---------------- Sorting ----------------
    def sort_tree(self, col):
        rows = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        numeric_cols = {"l_count", "r_count"}

        if col in numeric_cols:
            rows.sort(key=lambda x: safe_int(x[0], 0), reverse=True)
        else:
            rows.sort(key=lambda x: str(x[0]).lower(), reverse=False)

        for i, (_, k) in enumerate(rows):
            self.tree.move(k, "", i)

    # ---------------- Export ----------------
    def export_view(self):
        if not self._current_view_ips:
            messagebox.showinfo("Export", "No data in the current view.")
            return

        out = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Export view"
        )
        if not out:
            return

        try:
            with open(out, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow([
                    "top", "ip", "class", "country", "local_cnt", "remote_cnt",
                    "chain_preview",
                    "service_preview",
                    "local_ports", "remote_ports", "states", "protos", "processes", "pids"
                ])
                for ip in self._current_view_ips:
                    s = self.ip_stats[ip]
                    top = ""  # keep empty on export
                    w.writerow([
                        top,
                        ip,
                        s["class"],
                        s.get("country", ""),
                        s["local_cnt"],
                        s["remote_cnt"],
                        s.get("chain_preview", ""),
                        s.get("service_preview", ""),
                        ";".join(sorted(s["local_ports"])),
                        ";".join(sorted(s["remote_ports"])),
                        ";".join(sorted(s["states"])),
                        ";".join(sorted(s["protos"])),
                        ";".join(sorted(s["procs"])),
                        ";".join(sorted(s["pids"])),
                    ])
            messagebox.showinfo("Export", "Export successful.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SentinelV3(root)
    root.mainloop()
