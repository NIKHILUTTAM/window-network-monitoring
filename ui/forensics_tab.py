import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import time
import datetime
import json
import csv
import os
from collections import deque, defaultdict
import logging
from logging.handlers import RotatingFileHandler
import math
import statistics

from utils.logger import log
from utils.ip_utils import classify_internal_external
from analysis.heuristics import mark_suspicious_by_ip_or_host


class ForensicsTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.data = deque(maxlen=10000)
        self.connection_history = deque(maxlen=20000)
        self.ip_data = defaultdict(lambda: {
            'count': 0,
            'internal_count': 0,
            'external_count': 0,
            'first_seen': float('inf'),
            'last_seen': 0,
            'sessions': defaultdict(list),
            'geo_data': None,
            'suspicious': None,
            'threat_score': 0
        })
        self.logger = logging.getLogger('forensics')
        self.logger.setLevel(logging.INFO)
        self.handler = RotatingFileHandler('logs/forensics.log', maxBytes=5 * 1024 * 1024, backupCount=3,
                                           encoding='utf-8')
        self.handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.logger.addHandler(self.handler)

        self.time_ranges = {
            "15 minutes": 15,
            "30 minutes": 30,
            "1 hour": 60,
            "3 hours": 180,
            "6 hours": 360,
            "12 hours": 720,
            "24 hours": 1440,
            "7 days": 10080
        }

        self.create_widgets()
        self.last_update_time = time.time()
        self.refresh_interval = 10
        self.active = False
        self.schedule_refresh()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.summary_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.summary_tab, text="Summary")
        self.create_summary_widgets(self.summary_tab)

        self.ip_stats_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.ip_stats_tab, text="IP Statistics")
        self.create_ip_stats_widgets(self.ip_stats_tab)

        self.geo_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.geo_tab, text="Geo/ASN")
        self.create_geo_widgets(self.geo_tab)

        self.suspicious_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.suspicious_tab, text="Suspicious IPs")
        self.create_suspicious_widgets(self.suspicious_tab)

        self.time_search_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.time_search_tab, text="Time Search")
        self.create_time_search_widgets(self.time_search_tab)

        self.create_vtscore_tab()

    def create_vtscore_tab(self):
        self.vt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.vt_tab, text="VT Score")
        self.vt_tab.columnconfigure(0, weight=1)
        self.vt_tab.rowconfigure(1, weight=1)

        control_frame = ttk.Frame(self.vt_tab)
        control_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        control_frame.columnconfigure(2, weight=1)

        self.vt_refresh_button = ttk.Button(control_frame, text="Refresh Scores", command=self.update_vt_ip_scores)
        self.vt_refresh_button.pack(side=tk.LEFT)

        self.vt_status_var = tk.StringVar(value="IP reputations from VirusTotal.")
        ttk.Label(control_frame, textvariable=self.vt_status_var).pack(side=tk.LEFT, padx=10)

        self.export_vt_button = ttk.Button(control_frame, text="Export Data", command=self.export_vt_scores)
        self.export_vt_button.pack(side=tk.RIGHT)

        results_frame = ttk.LabelFrame(self.vt_tab, text="VirusTotal IP Reputation")
        results_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        columns = ("ip", "score", "country", "domain", "risk")
        self.vt_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        self.vt_tree.grid(row=0, column=0, sticky="nsew")

        self.vt_tree.heading("ip", text="IP Address")
        self.vt_tree.heading("score", text="Detection Ratio (Malicious/Total)")
        self.vt_tree.heading("country", text="Country")
        self.vt_tree.heading("domain", text="Domain Name (Reverse DNS)")
        self.vt_tree.heading("risk", text="Risk Level")

        self.vt_tree.column("ip", width=120, anchor="w")
        self.vt_tree.column("score", width=180, anchor="center")
        self.vt_tree.column("country", width=80, anchor="center")
        self.vt_tree.column("domain", width=250, anchor="w")
        self.vt_tree.column("risk", width=100, anchor="center")

        vt_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.vt_tree.yview)
        vt_scroll.grid(row=0, column=1, sticky="ns")
        self.vt_tree.configure(yscrollcommand=vt_scroll.set)

        self.vt_tree.tag_configure('high', background='', foreground='red')
        self.vt_tree.tag_configure('medium', background='', foreground='#cfb413')
        self.vt_tree.tag_configure('low', background='', foreground='blue')
        self.vt_tree.tag_configure('unknown', foreground='grey')

    def export_vt_scores(self):
        self._export_treeview_data(
            self.vt_tree,
            "VirusTotal Score Report",
            "vt_score_report"
        )

    def update_vt_ip_scores(self):
        self.vt_status_var.set("Refreshing IP scores...")

        selected_range = self.time_ranges[self.time_range_var.get()]
        cutoff_time = time.time() - (selected_range * 60)

        active_external_ips = {
            ip for ip, data in self.ip_data.items()
            if data['last_seen'] >= cutoff_time and classify_internal_external(ip) == "external"
        }

        for ip in active_external_ips:
            if ip and not self.app.ip_details.get(ip):
                self.app.queue_ip_for_geo(ip)

        self.vt_tree.delete(*self.vt_tree.get_children())

        sorted_ips = sorted(list(active_external_ips))

        for ip in sorted_ips:
            details = self.app.ip_details.get(ip)
            if not details or "vt_stats" not in details or not details["vt_stats"]:
                self.vt_tree.insert("", "end", values=(ip, "Loading...", "...", "...", "..."), tags=('unknown',))
                continue

            stats = details["vt_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            score_str = f"{malicious}/{total}" if total > 0 else "N/A"
            country = details.get("country", "N/A")
            domain = details.get("reverse", "N/A")

            risk = "Low"
            tag = 'low'
            if total > 0:
                percentage = (malicious / total) * 100
                if percentage > 50:
                    risk = "High"
                    tag = 'high'
                elif 50>=percentage >=20:
                    risk = "Medium"
                    tag = 'medium'

            self.vt_tree.insert("", "end", values=(ip, score_str, country, domain, risk), tags=(tag,))

        self.vt_status_var.set("Scores updated.")

    def create_summary_widgets(self, parent):
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(control_frame, text="Time Range:").pack(side=tk.LEFT, padx=(0, 5))
        self.time_range_var = tk.StringVar(value="15 minutes")
        time_range_combo = ttk.Combobox(
            control_frame,
            textvariable=self.time_range_var,
            values=list(self.time_ranges.keys()),
            state="readonly",
            width=12
        )
        time_range_combo.pack(side=tk.LEFT, padx=5)
        time_range_combo.bind("<<ComboboxSelected>>", lambda e: self.update_display())

        self.refresh_btn = ttk.Button(
            control_frame,
            text="Refresh",
            command=self.manual_refresh
        )
        self.refresh_btn.pack(side=tk.LEFT, padx=5)

        export_btn = ttk.Button(
            control_frame,
            text="Export Data",
            command=self.export_data
        )
        export_btn.pack(side=tk.RIGHT, padx=5)

        self.auto_refresh_var = tk.StringVar(value="🔄 Auto-refresh: ON")
        auto_refresh_label = ttk.Label(control_frame, textvariable=self.auto_refresh_var)
        auto_refresh_label.pack(side=tk.RIGHT, padx=(0, 10))

        stats_frame = ttk.LabelFrame(parent, text="Summary Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        stats = [
            ("Total Connections", "total_stats"),
            ("Internal Connections", "internal_stats"),
            ("External Connections", "external_stats")
        ]

        for i, (label, var_name) in enumerate(stats):
            frame = ttk.Frame(stats_frame)
            frame.grid(row=0, column=i, padx=10, pady=5, sticky="nsew")
            stats_frame.columnconfigure(i, weight=1)

            ttk.Label(frame, text=label, font=("Arial", 9, "bold")).pack(anchor="w")
            setattr(self, f"{var_name}_avg", tk.StringVar(value="Avg: -"))
            setattr(self, f"{var_name}_max", tk.StringVar(value="Max: -"))
            setattr(self, f"{var_name}_min", tk.StringVar(value="Min: -"))

            ttk.Label(frame, textvariable=getattr(self, f"{var_name}_avg")).pack(anchor="w")
            ttk.Label(frame, textvariable=getattr(self, f"{var_name}_max")).pack(anchor="w")
            ttk.Label(frame, textvariable=getattr(self, f"{var_name}_min")).pack(anchor="w")

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        columns = ("timestamp", "total", "internal", "external")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.heading("timestamp", text="Timestamp", command=lambda: self.sort_column("timestamp", False))
        self.tree.heading("total", text="Total", command=lambda: self.sort_column("total", False))
        self.tree.heading("internal", text="Internal", command=lambda: self.sort_column("internal", False))
        self.tree.heading("external", text="External", command=lambda: self.sort_column("external", False))

        self.tree.column("timestamp", width=180, anchor="center")
        self.tree.column("total", width=80, anchor="center")
        self.tree.column("internal", width=80, anchor="center")
        self.tree.column("external", width=80, anchor="center")

        v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        h_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.status_var = tk.StringVar(value="Last refresh: Never")
        status_bar = ttk.Label(parent, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=5, pady=(0, 5))

    def create_ip_stats_widgets(self, parent):
        paned_window = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        top_frame = ttk.LabelFrame(paned_window, text="Top Talkers")

        control_frame = ttk.Frame(top_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=(5, 0))

        ttk.Label(control_frame, text="Show Top:").pack(side=tk.LEFT, padx=(5, 5))
        self.top_n_var = tk.IntVar(value=10)
        top_n_combo = ttk.Combobox(control_frame, textvariable=self.top_n_var,
                                   values=[5, 10, 25, 50], width=5, state="readonly")
        top_n_combo.pack(side=tk.LEFT, padx=5)
        top_n_combo.bind("<<ComboboxSelected>>", lambda e: self.update_ip_stats())

        ttk.Label(control_frame, text="IP Type:").pack(side=tk.LEFT, padx=(20, 5))
        self.ip_type_var = tk.StringVar(value="All")
        ip_type_combo = ttk.Combobox(control_frame, textvariable=self.ip_type_var,
                                     values=["All", "External", "Internal"], width=8, state="readonly")
        ip_type_combo.pack(side=tk.LEFT, padx=5)
        ip_type_combo.bind("<<ComboboxSelected>>", lambda e: self.update_ip_stats())

        tree_frame = ttk.Frame(top_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        columns = ("ip", "count", "first_seen", "last_seen", "session_duration", "threat_score")
        self.top_talkers_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        for col, text in [("ip", "IP Address"),
                          ("count", "Connections"),
                          ("first_seen", "First Seen"),
                          ("last_seen", "Last Seen"),
                          ("session_duration", "Avg Session"),
                          ("threat_score", "Threat Score")]:
            self.top_talkers_tree.heading(col, text=text, command=lambda c=col: self.sort_top_talkers_column(c, False))

        self.top_talkers_tree.column("ip", width=120)
        self.top_talkers_tree.column("count", width=80, anchor="center")
        self.top_talkers_tree.column("first_seen", width=120)
        self.top_talkers_tree.column("last_seen", width=120)
        self.top_talkers_tree.column("session_duration", width=100, anchor="center")
        self.top_talkers_tree.column("threat_score", width=80, anchor="center")

        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.top_talkers_tree.yview)
        self.top_talkers_tree.configure(yscrollcommand=scroll.set)

        self.top_talkers_tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        paned_window.add(top_frame, weight=3)
        details_frame = ttk.LabelFrame(paned_window, text="IP Details")

        ttk.Label(details_frame, text="Select IP:").pack(anchor="w", padx=5, pady=(5, 0))
        self.ip_select_var = tk.StringVar()
        self.ip_select_combo = ttk.Combobox(details_frame, textvariable=self.ip_select_var, state="readonly")
        self.ip_select_combo.pack(fill=tk.X, padx=5, pady=(0, 10))
        self.ip_select_combo.bind("<<ComboboxSelected>>", self.update_ip_details)

        details_tree_frame = ttk.Frame(details_frame)
        details_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        details_tree_frame.rowconfigure(0, weight=1)
        details_tree_frame.columnconfigure(0, weight=1)

        columns_details = ("property", "value")
        self.ip_details_tree = ttk.Treeview(details_tree_frame, columns=columns_details, show="headings")
        self.ip_details_tree.heading("property", text="Property")
        self.ip_details_tree.heading("value", text="Value")
        self.ip_details_tree.column("property", width=150, anchor="w")
        self.ip_details_tree.column("value", width=250, anchor="w")

        details_scroll = ttk.Scrollbar(details_tree_frame, orient="vertical", command=self.ip_details_tree.yview)
        self.ip_details_tree.configure(yscrollcommand=details_scroll.set)

        self.ip_details_tree.grid(row=0, column=0, sticky="nsew")
        details_scroll.grid(row=0, column=1, sticky="ns")

        export_btn = ttk.Button(details_frame, text="Export IP Report", command=self.export_ip_report)
        export_btn.pack(pady=5)

        paned_window.add(details_frame, weight=2)

    def create_geo_widgets(self, parent):
        geo_frame = ttk.LabelFrame(parent, text="Geo Aggregation")
        geo_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        control_frame = ttk.Frame(geo_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(control_frame, text="Group By:").pack(side=tk.LEFT, padx=(10, 5))
        self.geo_group_var = tk.StringVar(value="Country")
        geo_group_combo = ttk.Combobox(control_frame, textvariable=self.geo_group_var,
                                       values=["Country", "ASN", "Organization"], width=12, state="readonly")
        geo_group_combo.pack(side=tk.LEFT, padx=5)
        geo_group_combo.bind("<<ComboboxSelected>>", lambda e: self.update_geo_aggregation())

        columns = ("group", "count", "avg_rate", "peak_rate", "ips")
        self.geo_tree = ttk.Treeview(geo_frame, columns=columns, show="headings")

        self.geo_tree.heading("group", text="Group")
        self.geo_tree.heading("count", text="Connections")
        self.geo_tree.heading("avg_rate", text="Avg/Min")
        self.geo_tree.heading("peak_rate", text="Peak/Min")
        self.geo_tree.heading("ips", text="Top IPs")

        self.geo_tree.column("group", width=150)
        self.geo_tree.column("count", width=80, anchor="center")
        self.geo_tree.column("avg_rate", width=80, anchor="center")
        self.geo_tree.column("peak_rate", width=80, anchor="center")
        self.geo_tree.column("ips", width=200)

        v_scroll = ttk.Scrollbar(geo_frame, orient="vertical", command=self.geo_tree.yview)
        h_scroll = ttk.Scrollbar(geo_frame, orient="horizontal", command=self.geo_tree.xview)
        self.geo_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.geo_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5), pady=5)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))

    def create_suspicious_widgets(self, parent):
        suspicious_frame = ttk.LabelFrame(parent, text="Suspicious IPs")
        suspicious_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        filter_frame = ttk.Frame(suspicious_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(10, 5))
        self.suspicious_filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.suspicious_filter_var,
                                    values=["All", "Malicious", "Social Media", "Ecommerce"], width=12,
                                    state="readonly")
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self.update_suspicious_ips())

        columns = ("ip", "count", "first_seen", "last_seen", "type", "threat_score")
        self.suspicious_tree = ttk.Treeview(suspicious_frame, columns=columns, show="headings")

        self.suspicious_tree.heading("ip", text="IP Address")
        self.suspicious_tree.heading("count", text="Connections")
        self.suspicious_tree.heading("first_seen", text="First Seen")
        self.suspicious_tree.heading("last_seen", text="Last Seen")
        self.suspicious_tree.heading("type", text="Type")
        self.suspicious_tree.heading("threat_score", text="Threat Score")

        self.suspicious_tree.column("ip", width=120)
        self.suspicious_tree.column("count", width=80, anchor="center")
        self.suspicious_tree.column("first_seen", width=120)
        self.suspicious_tree.column("last_seen", width=120)
        self.suspicious_tree.column("type", width=100)
        self.suspicious_tree.column("threat_score", width=80, anchor="center")

        v_scroll = ttk.Scrollbar(suspicious_frame, orient="vertical", command=self.suspicious_tree.yview)
        h_scroll = ttk.Scrollbar(suspicious_frame, orient="horizontal", command=self.suspicious_tree.xview)
        self.suspicious_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.suspicious_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5), pady=5)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))

    def create_time_search_widgets(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        controls_frame = ttk.LabelFrame(parent, text="Search by Time Range")
        controls_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        ttk.Label(controls_frame, text="Start (YYYY-MM-DD HH:MM):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.start_time_var = tk.StringVar()
        ttk.Entry(controls_frame, textvariable=self.start_time_var, width=20).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(controls_frame, text="End (YYYY-MM-DD HH:MM):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.end_time_var = tk.StringVar()
        ttk.Entry(controls_frame, textvariable=self.end_time_var, width=20).grid(row=1, column=1, padx=5, pady=5)

        button_frame = ttk.Frame(controls_frame)
        button_frame.grid(row=0, column=2, rowspan=2, padx=10, pady=5, sticky="w")

        style = ttk.Style()
        style.configure("Small.TButton", padding=3)

        btn_5m = ttk.Button(button_frame, text="Last 5 Mins", command=lambda: self._set_time_range(minutes_ago=5),
                            style="Small.TButton")
        btn_5m.grid(row=0, column=0, padx=2)

        btn_15m = ttk.Button(button_frame, text="Last 15 Mins", command=lambda: self._set_time_range(minutes_ago=15),
                             style="Small.TButton")
        btn_15m.grid(row=0, column=1, padx=2)

        btn_1h = ttk.Button(button_frame, text="Last 1 Hour", command=lambda: self._set_time_range(hours_ago=1),
                            style="Small.TButton")
        btn_1h.grid(row=0, column=2, padx=2)

        btn_24h = ttk.Button(button_frame, text="Last 24 Hours", command=lambda: self._set_time_range(hours_ago=24),
                             style="Small.TButton")
        btn_24h.grid(row=1, column=0, padx=2, pady=3)

        btn_today = ttk.Button(button_frame, text="Today", command=lambda: self._set_time_range(today=True),
                               style="Small.TButton")
        btn_today.grid(row=1, column=1, padx=2, pady=3)

        search_button = ttk.Button(controls_frame, text="Search", command=self.perform_time_search)
        search_button.grid(row=0, column=3, rowspan=2, padx=10, pady=5, sticky="ns")

        now = datetime.datetime.now()
        yesterday = now - datetime.timedelta(days=1)
        self.end_time_var.set(now.strftime("%Y-%m-%d %H:%M"))
        self.start_time_var.set(yesterday.strftime("%Y-%m-%d %H:%M"))

        main_pane = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        main_pane.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)

        left_pane = ttk.PanedWindow(main_pane, orient=tk.VERTICAL)
        main_pane.add(left_pane, weight=3)
        suspicious_frame = ttk.LabelFrame(left_pane, text="🚨 Suspicious Connections Detected")
        left_pane.add(suspicious_frame, weight=1)
        self.time_search_suspicious_tree = self.create_results_treeview(suspicious_frame)

        new_conn_frame = ttk.LabelFrame(left_pane, text="🆕 New External Connections")
        left_pane.add(new_conn_frame, weight=1)
        new_conn_frame.rowconfigure(0, weight=1)
        new_conn_frame.columnconfigure(0, weight=1)
        self.time_search_new_tree = self.create_results_treeview(new_conn_frame)
        export_new_btn = ttk.Button(new_conn_frame, text="Export Data", command=self.export_time_search_new_connections)
        export_new_btn.grid(row=1, column=0, columnspan=2, pady=(5, 2), sticky="e", padx=5)

        summary_frame = ttk.LabelFrame(main_pane, text="📊 Connection Summary by Process")
        main_pane.add(summary_frame, weight=1)
        summary_frame.rowconfigure(0, weight=1)
        summary_frame.columnconfigure(0, weight=1)

        cols = ("process", "count")
        self.time_search_summary_tree = ttk.Treeview(summary_frame, columns=cols, show="headings")
        self.time_search_summary_tree.heading("process", text="Process Name")
        self.time_search_summary_tree.heading("count", text="Connection Count")
        self.time_search_summary_tree.column("process", anchor="w", width=200)
        self.time_search_summary_tree.column("count", anchor="center", width=120)

        summary_scroll = ttk.Scrollbar(summary_frame, orient="vertical", command=self.time_search_summary_tree.yview)
        self.time_search_summary_tree.configure(yscrollcommand=summary_scroll.set)

        self.time_search_summary_tree.grid(row=0, column=0, sticky="nsew")
        summary_scroll.grid(row=0, column=1, sticky="ns")
        export_summary_btn = ttk.Button(summary_frame, text="Export Data", command=self.export_time_search_summary)
        export_summary_btn.grid(row=1, column=0, columnspan=2, pady=(5, 2), sticky="e", padx=5)

    def create_results_treeview(self, parent):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        columns = ("timestamp", "proto", "local", "remote", "process", "type", "threat_score")
        tree = ttk.Treeview(parent, columns=columns, show="headings")

        tree.heading("timestamp", text="Timestamp")
        tree.heading("proto", text="Protocol")
        tree.heading("local", text="Local Address")
        tree.heading("remote", text="Remote Address")
        tree.heading("process", text="Process")
        tree.heading("type", text="Details")
        tree.heading("threat_score", text="Threat Score")

        tree.column("timestamp", width=140, anchor="w")
        tree.column("proto", width=60, anchor="center")
        tree.column("local", width=180, anchor="w")
        tree.column("remote", width=180, anchor="w")
        tree.column("process", width=120, anchor="w")
        tree.column("type", width=120, anchor="w")
        tree.column("threat_score", width=80, anchor="center")

        v_scroll = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=v_scroll.set)

        tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        return tree

    def _set_time_range(self, minutes_ago=None, hours_ago=None, today=False):
        now = datetime.datetime.now()
        end_dt = now

        if minutes_ago is not None:
            start_dt = now - datetime.timedelta(minutes=minutes_ago)
        elif hours_ago is not None:
            start_dt = now - datetime.timedelta(hours=hours_ago)
        elif today:
            start_dt = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            return

        self.start_time_var.set(start_dt.strftime("%Y-%m-%d %H:%M"))
        self.end_time_var.set(end_dt.strftime("%Y-%m-%d %H:%M"))

        self.perform_time_search()

    def perform_time_search(self):
        try:
            start_dt = datetime.datetime.strptime(self.start_time_var.get(), "%Y-%m-%d %H:%M")
            end_dt = datetime.datetime.strptime(self.end_time_var.get(), "%Y-%m-%d %H:%M")
            start_ts = start_dt.timestamp()
            end_ts = end_dt.timestamp()
        except ValueError:
            messagebox.showerror("Invalid Format", "Please use 'YYYY-MM-DD HH:MM' format.")
            return

        for tree in [self.time_search_suspicious_tree, self.time_search_new_tree, self.time_search_summary_tree]:
            for item in tree.get_children():
                tree.delete(item)

        relevant_records = [r for r in self.connection_history if start_ts <= r['timestamp'] <= end_ts]

        suspicious_found = 0
        new_conn_found = 0
        process_summary = defaultdict(int)

        for record in relevant_records:
            remote_ip = record.get("remote_ip")
            if not remote_ip or remote_ip == "*":
                continue

            process_summary[record.get("process", "Unknown")] += 1
            threat_score = self.ip_data.get(remote_ip, {}).get('threat_score', 0)

            suspicious_tag = self.ip_data[remote_ip].get('suspicious')
            if suspicious_tag:
                suspicious_found += 1
                self.add_record_to_tree(self.time_search_suspicious_tree, record,
                                        suspicious_tag.replace("_", " ").title(), threat_score)

            if classify_internal_external(remote_ip) == 'external':
                first_seen_ts = self.ip_data[remote_ip].get('first_seen')
                if first_seen_ts and start_ts <= first_seen_ts <= end_ts:
                    new_conn_found += 1
                    self.add_record_to_tree(self.time_search_new_tree, record, "First time seen", threat_score)

        for process, count in sorted(process_summary.items(), key=lambda item: item[1], reverse=True):
            self.time_search_summary_tree.insert("", "end", values=(process, count))

        messagebox.showinfo("Search Complete",
                            f"Found {len(relevant_records)} total records.\n\n"
                            f"-> {suspicious_found} suspicious connection(s).\n"
                            f"-> {new_conn_found} new external connection(s).")

    def add_record_to_tree(self, tree, record, details_text, threat_score):
        local_addr = f"{record.get('local_ip', '')}:{record.get('local_port', '')}"
        remote_addr = f"{record.get('remote_ip', '')}:{record.get('remote_port', '')}"
        timestamp_str = datetime.datetime.fromtimestamp(record['timestamp']).strftime("%Y-%m-%d %H:%M:%S")

        tree.insert("", "end", values=(
            timestamp_str,
            record.get("proto", ""),
            local_addr,
            remote_addr,
            record.get("process", "Unknown"),
            details_text,
            f"{threat_score:.1f}"
        ))

    def _export_treeview_data(self, treeview, title, default_filename):
        if not treeview.get_children():
            messagebox.showinfo(title, f"There is no data to export from '{title}'.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=f"{default_filename}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json")],
            title=f"Export {title}"
        )

        if not file_path:
            return

        try:
            headers = [treeview.heading(col)['text'] for col in treeview['columns']]
            data = [treeview.item(item)['values'] for item in treeview.get_children()]

            if file_path.lower().endswith('.csv'):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(data)
            else:
                json_data = [dict(zip(headers, row)) for row in data]
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2)

            messagebox.showinfo("Export Complete", f"Data successfully exported to:\n{file_path}")

        except Exception as e:
            log("ERROR", f"Failed to export data for '{title}': {e}")
            messagebox.showerror("Export Error", f"An error occurred while exporting the data:\n{e}")

    def export_time_search_new_connections(self):
        self._export_treeview_data(
            self.time_search_new_tree,
            "New External Connections",
            "new_connections_export"
        )

    def export_time_search_summary(self):
        self._export_treeview_data(
            self.time_search_summary_tree,
            "Connection Summary by Process",
            "process_summary_export"
        )

    def collect_data(self):
        with self.app.last_seen_lock:
            connections = self.app.last_seen[:]

        total = len(connections)
        internal = 0
        external = 0

        now = time.time()
        rounded_time = round(now / 60) * 60

        interval_ips = set()

        for conn in connections:
            conn_with_ts = conn.copy()
            conn_with_ts['timestamp'] = now
            self.connection_history.append(conn_with_ts)

            ip = conn.get("remote_ip", "")
            if not ip or ip in ["::", "*"]:
                continue

            classification = classify_internal_external(ip)
            if classification == "internal":
                internal += 1
            elif classification == "external":
                external += 1

            if ip not in self.ip_data:
                self.ip_data[ip] = {
                    'count': 0,
                    'internal_count': 0,
                    'external_count': 0,
                    'first_seen': rounded_time,
                    'last_seen': rounded_time,
                    'sessions': defaultdict(list),
                    'geo_data': None,
                    'suspicious': None,
                    'threat_score': 0
                }
                self.app.queue_ip_for_geo(ip)
            else:
                self.ip_data[ip]['last_seen'] = rounded_time

            self.ip_data[ip]['count'] += 1
            if classification == "internal":
                self.ip_data[ip]['internal_count'] += 1
            else:
                self.ip_data[ip]['external_count'] += 1

            session_key = f"{ip}:{conn.get('remote_port', '')}"
            session_data = self.ip_data[ip]['sessions'][session_key]
            if not session_data or now - session_data[-1] > 300:
                session_data.append(now)
            else:
                session_data[-1] = now

            interval_ips.add(ip)

        for ip in interval_ips:
            ip_info = self.ip_data[ip]

            resolved_domain = self.app.domain_mapping.get(ip)
            tag_from_ip = mark_suspicious_by_ip_or_host(ip)
            tag_from_domain = mark_suspicious_by_ip_or_host(resolved_domain)
            ip_info['suspicious'] = tag_from_domain or tag_from_ip

            score = 0
            geo_data = self.app.ip_details.get(ip, {})

            vt_positives = 0
            if geo_data:
                vt_positives = geo_data.get('vt_positives', 0)
                abuse_score = geo_data.get('abuse_score', 0)
                if vt_positives > 0:
                    score += 40 + min(50, vt_positives * 5)

                if abuse_score > 75:
                    score += (abuse_score - 70) * 0.6

            if ip_info['suspicious'] == "malicious":
                score += 50
            elif ip_info['suspicious']:
                score += 10

            if score == 0:
                score += min(15, math.log1p(ip_info['count']))

            ip_info['threat_score'] = min(100, round(score, 1))

        self.data.append((rounded_time, total, internal, external))

        timestamp_str = datetime.datetime.fromtimestamp(rounded_time).strftime("%Y-%m-%d %H:%M")
        self.logger.info(f"Timestamp: {timestamp_str}, Total: {total}, Internal: {internal}, External: {external}")

        return rounded_time, total, internal, external

    def update_display(self):
        selected_range = self.time_ranges[self.time_range_var.get()]
        cutoff_time = time.time() - (selected_range * 60)

        filtered_data = [item for item in self.data if item[0] >= cutoff_time]

        for item in self.tree.get_children():
            self.tree.delete(item)

        for ts, total, internal, external in filtered_data:
            timestamp_str = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
            self.tree.insert("", "end", values=(timestamp_str, total, internal, external))

        self.update_statistics(filtered_data)

        self.update_ip_stats()

        self.status_var.set(
            f"Last refresh: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Showing {len(filtered_data)} records")

        self.update_geo_aggregation()
        self.update_suspicious_ips()
        self.update_vt_ip_scores()

    def update_statistics(self, data):
        if not data:
            for prefix in ["total", "internal", "external"]:
                getattr(self, f"{prefix}_stats_avg").set("Avg: -")
                getattr(self, f"{prefix}_stats_max").set("Max: -")
                getattr(self, f"{prefix}_stats_min").set("Min: -")
            return

        totals = [item[1] for item in data]
        internals = [item[2] for item in data]
        externals = [item[3] for item in data]

        stats = {
            "total": totals,
            "internal": internals,
            "external": externals
        }

        for prefix, values in stats.items():
            if values:
                avg = statistics.mean(values)
                max_val = max(values)
                min_val = min(values)

                getattr(self, f"{prefix}_stats_avg").set(f"Avg: {avg:.1f}")
                getattr(self, f"{prefix}_stats_max").set(f"Max: {max_val}")
                getattr(self, f"{prefix}_stats_min").set(f"Min: {min_val}")
            else:
                getattr(self, f"{prefix}_stats_avg").set("Avg: -")
                getattr(self, f"{prefix}_stats_max").set("Max: -")
                getattr(self, f"{prefix}_stats_min").set("Min: -")

    def update_ip_stats(self):
        for item in self.top_talkers_tree.get_children():
            self.top_talkers_tree.delete(item)

        selected_range = self.time_ranges[self.time_range_var.get()]
        cutoff_time = time.time() - (selected_range * 60)

        active_ips = []
        for ip, data in self.ip_data.items():
            if data['last_seen'] >= cutoff_time:
                avg_session = 0
                session_count = 0
                for session_key, timestamps in data['sessions'].items():
                    if len(timestamps) > 1:
                        durations = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
                        if durations:
                            avg_session += sum(durations) / len(durations)
                            session_count += 1

                if session_count > 0:
                    avg_session = avg_session / session_count

                active_ips.append((ip, data['count'], data['first_seen'], data['last_seen'],
                                   avg_session, data['threat_score']))

        ip_type = self.ip_type_var.get()
        if ip_type == "Internal":
            active_ips = [ip for ip in active_ips if
                          self.ip_data[ip[0]]['internal_count'] > self.ip_data[ip[0]]['external_count']]
        elif ip_type == "External":
            active_ips = [ip for ip in active_ips if
                          self.ip_data[ip[0]]['external_count'] > self.ip_data[ip[0]]['internal_count']]

        active_ips.sort(key=lambda x: x[1], reverse=True)

        top_n = self.top_n_var.get()
        top_ips = active_ips[:top_n]

        for ip_data in top_ips:
            ip, count, first_seen, last_seen, avg_session, threat_score = ip_data
            first_str = datetime.datetime.fromtimestamp(first_seen).strftime("%Y-%m-%d %H:%M")
            last_str = datetime.datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d %H:%M")
            session_str = f"{avg_session:.1f}s" if avg_session > 0 else "N/A"
            self.top_talkers_tree.insert("", "end", values=(
                ip, count, first_str, last_str, session_str, f"{threat_score:.1f}"
            ))

        ips = [ip[0] for ip in top_ips]
        self.ip_select_combo['values'] = ips
        if ips and not self.ip_select_var.get():
            self.ip_select_var.set(ips[0])
            self.update_ip_details()

        self.sort_top_talkers_column('threat_score', True)

    def update_ip_details(self, event=None):
        for item in self.ip_details_tree.get_children():
            self.ip_details_tree.delete(item)

        ip = self.ip_select_var.get()
        if not ip or ip not in self.ip_data:
            return

        data = self.ip_data[ip]
        geo_data = self.app.ip_details.get(ip, {})

        self.ip_details_tree.insert("", "end", values=("IP Address", ip))
        self.ip_details_tree.insert("", "end", values=("First Seen",
                                                       datetime.datetime.fromtimestamp(data['first_seen']).strftime(
                                                           "%Y-%m-%d %H:%M")))
        self.ip_details_tree.insert("", "end", values=("Last Seen",
                                                       datetime.datetime.fromtimestamp(data['last_seen']).strftime(
                                                           "%Y-%m-%d %H:%M")))
        self.ip_details_tree.insert("", "end", values=("Total Connections", data['count']))
        self.ip_details_tree.insert("", "end", values=("Internal Connections", data['internal_count']))
        self.ip_details_tree.insert("", "end", values=("External Connections", data['external_count']))
        self.ip_details_tree.insert("", "end", values=("Threat Score", f"{data['threat_score']:.1f}/100"))

        if data['suspicious']:
            self.ip_details_tree.insert("", "end", values=("Suspicious Type", data['suspicious'].title()))

        if geo_data:
            self.ip_details_tree.insert("", "end", values=("Country", geo_data.get('country', 'Unknown')))
            self.ip_details_tree.insert("", "end", values=("Region", geo_data.get('region', 'Unknown')))
            self.ip_details_tree.insert("", "end", values=("City", geo_data.get('city', 'Unknown')))
            self.ip_details_tree.insert("", "end", values=("Organization", geo_data.get('org', 'Unknown')))
            self.ip_details_tree.insert("", "end", values=("ASN", geo_data.get('asn', 'Unknown')))
            self.ip_details_tree.insert("", "end", values=("Service", geo_data.get('service', 'Unknown')))

            self.ip_details_tree.insert("", "end", values=("", ""))
            self.ip_details_tree.insert("", "end", values=("Threat Status", geo_data.get('threat', 'Unknown')))
            self.ip_details_tree.insert("", "end",
                                        values=("AbuseIPDB Score", f"{geo_data.get('abuse_score', 'N/A')}/100"))
            self.ip_details_tree.insert("", "end",
                                        values=("VirusTotal Detections", geo_data.get('vt_positives', 'N/A')))
            self.ip_details_tree.insert("", "end", values=("Threat Details", geo_data.get('threat_details', 'N/A')))

    def update_geo_aggregation(self):
        for item in self.geo_tree.get_children():
            self.geo_tree.delete(item)

        selected_range = self.time_ranges[self.time_range_var.get()]
        cutoff_time = time.time() - (selected_range * 60)

        group_field = self.geo_group_var.get().lower()
        if group_field == "organization":
            group_field = "org"

        groups = defaultdict(lambda: {'count': 0, 'ips': defaultdict(int), 'timestamps': []})

        for ip, data in self.ip_data.items():
            if data['last_seen'] < cutoff_time:
                continue

            geo_data = self.app.ip_details.get(ip, {})
            group = geo_data.get(group_field, "Unknown")
            if not group or group == "Unknown":
                group = "Unknown"

            groups[group]['count'] += data['count']
            groups[group]['ips'][ip] += data['count']
            groups[group]['timestamps'].append(data['last_seen'])

        group_data = []
        for group, stats in groups.items():
            top_ips = sorted(stats['ips'].items(), key=lambda x: x[1], reverse=True)[:3]
            top_ips_str = ", ".join([f"{ip[0]} ({ip[1]})" for ip in top_ips])

            if stats['timestamps']:
                min_time = min(stats['timestamps'])
                max_time = max(stats['timestamps'])
                time_span = max(1, (max_time - min_time) / 60)
                avg_rate = stats['count'] / time_span
                peak_rate = max(stats['ips'].values())
            else:
                avg_rate = peak_rate = 0

            group_data.append((group, stats['count'], f"{avg_rate:.1f}", f"{peak_rate:.1f}", top_ips_str))

        group_data.sort(key=lambda x: x[1], reverse=True)

        for item in group_data:
            self.geo_tree.insert("", "end", values=item)

    def update_suspicious_ips(self):
        for item in self.suspicious_tree.get_children():
            self.suspicious_tree.delete(item)

        selected_range = self.time_ranges[self.time_range_var.get()]
        cutoff_time = time.time() - (selected_range * 60)

        filter_type = self.suspicious_filter_var.get()

        suspicious_ips = []
        for ip, data in self.ip_data.items():
            if data['last_seen'] < cutoff_time or not data['suspicious']:
                continue

            if filter_type != "All" and data['suspicious'] != filter_type.lower().replace(" ", "_"):
                continue

            first_str = datetime.datetime.fromtimestamp(data['first_seen']).strftime("%Y-%m-%d %H:%M")
            last_str = datetime.datetime.fromtimestamp(data['last_seen']).strftime("%Y-%m-%d %H:%M")
            suspicious_ips.append((
                ip, data['count'], first_str, last_str,
                data['suspicious'].replace("_", " ").title(),
                f"{data['threat_score']:.1f}"
            ))

        suspicious_ips.sort(key=lambda x: float(x[5]), reverse=True)

        for ip_data in suspicious_ips:
            self.suspicious_tree.insert("", "end", values=ip_data)

    def update_heatmap(self):
        pass

    def get_ips_active_at(self, timestamp):
        active_ips = []
        for ip, data in self.ip_data.items():
            if abs(data['last_seen'] - timestamp) <= 300:
                active_ips.append(ip)
        return active_ips

    def export_ip_report(self):
        ip = self.ip_select_var.get()
        if not ip or ip not in self.ip_data:
            messagebox.showwarning("Export", "No IP selected")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv"), ("All Files", "*.*")],
            title=f"Export Forensic Report for {ip}"
        )

        if not file_path:
            return

        ip_data = self.ip_data[ip]
        geo_data = self.app.ip_details.get(ip, {})

        report = {
            "ip": ip,
            "first_seen": datetime.datetime.fromtimestamp(ip_data['first_seen']).isoformat(),
            "last_seen": datetime.datetime.fromtimestamp(ip_data['last_seen']).isoformat(),
            "total_connections": ip_data['count'],
            "internal_connections": ip_data['internal_count'],
            "external_connections": ip_data['external_count'],
            "suspicious": ip_data['suspicious'],
            "threat_score": ip_data['threat_score'],
            "geo_data": geo_data,
            "activity": []
        }

        for i in range(min(100, ip_data['count'])):
            timestamp = ip_data['first_seen'] + i * (ip_data['last_seen'] - ip_data['first_seen']) / max(1, ip_data[
                'count'])
            report["activity"].append({
                "timestamp": datetime.datetime.fromtimestamp(timestamp).isoformat(),
                "event": "Connection established"
            })

        if file_path.lower().endswith('.csv'):
            self.save_ip_report_csv(file_path, report)
        else:
            self.save_ip_report_json(file_path, report)

        messagebox.showinfo("Export Complete", f"IP forensic report exported to:\n{file_path}")

    def save_ip_report_json(self, file_path, report):
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

    def save_ip_report_csv(self, file_path, report):
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Property", "Value"])

            writer.writerow(["IP Address", report["ip"]])
            writer.writerow(["First Seen", report["first_seen"]])
            writer.writerow(["Last Seen", report["last_seen"]])
            writer.writerow(["Total Connections", report["total_connections"]])
            writer.writerow(["Internal Connections", report["internal_connections"]])
            writer.writerow(["External Connections", report["external_connections"]])
            writer.writerow(["Suspicious", report["suspicious"] or "None"])
            writer.writerow(["Threat Score", report["threat_score"]])

            writer.writerow([])
            writer.writerow(["Geo Data", ""])
            for key, value in report["geo_data"].items():
                writer.writerow([key, value])

            writer.writerow([])
            writer.writerow(["Activity Timeline", ""])
            writer.writerow(["Timestamp", "Event"])
            for event in report["activity"]:
                writer.writerow([event["timestamp"], event["event"]])

    def sort_column(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            l.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)

        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))

    def sort_top_talkers_column(self, col, reverse):
        l = [(self.top_talkers_tree.set(k, col), k) for k in self.top_talkers_tree.get_children('')]

        try:
            l.sort(key=lambda t: float(t[0].replace('s', '').replace('N/A', '-1')), reverse=reverse)
        except ValueError:
            l.sort(key=lambda t: t[0], reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.top_talkers_tree.move(k, '', index)

        self.top_talkers_tree.heading(col, command=lambda: self.sort_top_talkers_column(col, not reverse))

    def schedule_refresh(self):
        if not self.active:
            return

        try:
            self.collect_data()
            self.update_display()
        except Exception as e:
            log("ERROR", f"Forensics refresh error: {e}")

        self.parent.after(self.refresh_interval * 1000, self.schedule_refresh)

    def manual_refresh(self):
        try:
            self.collect_data()
            self.update_display()
            self.status_var.set(f"Manual refresh at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            log("ERROR", f"Manual refresh failed: {e}")

    def export_data(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Export Forensic Data"
        )

        if not file_path:
            return

        selected_range = self.time_ranges[self.time_range_var.get()]
        cutoff_time = time.time() - (selected_range * 60)
        filtered_data = [item for item in self.data if item[0] >= cutoff_time]

        if file_path.lower().endswith('.csv'):
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Total Connections", "Internal", "External"])
                for ts, total, internal, external in filtered_data:
                    timestamp_str = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
                    writer.writerow([timestamp_str, total, internal, external])
        else:
            data = [{
                "timestamp": datetime.datetime.fromtimestamp(ts).isoformat(),
                "total": total,
                "internal": internal,
                "external": external
            } for ts, total, internal, external in filtered_data]
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

        messagebox.showinfo("Export Complete", f"Forensic data exported to:\n{file_path}")

    def start(self):
        if not self.active:
            self.active = True
            self.auto_refresh_var.set("🔄 Auto-refresh: ON")
            self.schedule_refresh()

    def stop(self):
        self.active = False
        self.auto_refresh_var.set("⏸️ Auto-refresh: OFF")