import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import datetime
import json
import csv
import os
import ipaddress
import queue
from collections import defaultdict

import tkintermapview
from config import CONFIG, alerts_q, dns_queue, geo_queue, alert_lock, alert_history, dns_lock, dns_cache
from utils.logger import log, rolling_logs
from utils.network import run_netstat_windows, parse_netstat_lines
from utils.ip_utils import classify_internal_external
from analysis.heuristics import feed_record, mark_suspicious_by_ip_or_host
from analysis.alerting import determine_alert_severity
from ui.responsive_ui import ResponsiveUIHelper
from ui.forensics_tab import ForensicsTab

class NetstatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("End Point Monitoring and Security (EPMS)")
        self.root.geometry("1200x900")
        self.root.minsize(800, 600)

        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.ui_helper = ResponsiveUIHelper(root)
        self.is_monitoring = False
        self.colors = {
            "bg": "#f0f0f0",
            "header": "#2c3e50",
            "primary": "#3498db",
            "success": "#2ecc71",
            "danger": "#e74c3c",
            "warning": "#f39c12",
            "info": "#1abc9c",
            "light": "#ecf0f1",
            "dark": "#34495e",
            "text": "#2c3e50",
            "external": "#ffe6e6",
            "internal": "#e6ffe6",
            "ecommerce": "#e67e22",
            "social_media": "#3498db",
            "malicious": "#e74c3c",
        }

        self.last_seen = []
        self.last_seen_lock = threading.Lock()
        self.ip_details = {}
        self.security_alerts_history = []
        self.general_alerts_history = []
        self.domain_mapping = {}
        self.domain_counts = defaultdict(int)
        self.domain_lock = threading.Lock()

        self._stop_event = threading.Event()
        self.monitor_thread = None
        self.ui_update_interval = 1000

        self.create_responsive_widgets()
        self.root.bind('<Configure>', self.on_window_resize)
        self.root.after(self.ui_update_interval, self.ui_update_loop)
        self.root.after(100, self.update_responsive_layout)

    def create_responsive_widgets(self):
        header_frame = tk.Frame(self.root, bg=self.colors["header"], height=50)
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_propagate(False)
        header_font = self.ui_helper.get_scaled_font("Arial", 16, "bold")
        header_label = tk.Label(header_frame, text="🛡️ End Point Monitoring and Security (EPMS)",
                                font=header_font, fg="white", bg=self.colors["header"])
        header_label.grid(row=0, column=0, pady=10)

        main_frame = tk.Frame(self.root, bg=self.colors["bg"])
        main_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        self.create_filter_controls(main_frame)

        self.create_responsive_tabs(main_frame)

        self.create_responsive_status_bar()

    def create_filter_controls(self, parent):
        filter_frame = ttk.LabelFrame(parent, text="🔍 Filter Settings", padding="10")
        filter_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        filter_frame.grid_columnconfigure(0, weight=1)
        checkbox_frame = tk.Frame(filter_frame, bg=self.colors["bg"])
        checkbox_frame.grid(row=0, column=0, sticky="ew")
        self.exclude_zero_var = tk.BooleanVar(value=CONFIG["filters"]["exclude_zero_remote"])
        self.show_internal_var = tk.BooleanVar(value=CONFIG["filters"]["show_only_internal"])
        self.show_listening_var = tk.BooleanVar(value=CONFIG["filters"]["show_listening_only"])
        checkbox_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"])
        cb1 = ttk.Checkbutton(checkbox_frame, text="Exclude 0.0.0.0 remote connections",
                              variable=self.exclude_zero_var, command=self.update_filters)
        cb2 = ttk.Checkbutton(checkbox_frame, text="Show only internal connections",
                              variable=self.show_internal_var, command=self.update_filters)
        cb3 = ttk.Checkbutton(checkbox_frame, text="Show only LISTENING connections",
                              variable=self.show_listening_var, command=self.update_filters)
        cb1.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        cb2.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        cb3.grid(row=0, column=2, sticky="w", padx=5, pady=2)
        checkbox_frame.grid_columnconfigure(0, weight=1)
        checkbox_frame.grid_columnconfigure(1, weight=1)
        checkbox_frame.grid_columnconfigure(2, weight=1)
    def on_connection_double_click(self, event):
        """Handles the double-click event on the connections Treeview."""
        selected = self.conn_tree.selection()
        if not selected:
            return

        # Reuse the single-click logic to populate the details
        self.on_tree_select(event)

        # Programmatically switch the view to the IP Details tab
        self.tab_control.select(self.tab_geo)

    def on_domain_double_click(self, event):
        """Handles a double-click on the Domains tab to find the IP and show details."""
        selected = self.domain_tree.selection()
        if not selected:
            return

        # Get the IP address from the selected row in the Domains tab
        item = self.domain_tree.item(selected[0])
        ip_address = item["values"][0]

        # Search for this IP in the Connections tab's tree
        found_item = None
        for child_item in self.conn_tree.get_children():
            # The remote IP is in the 3rd column (index 2)
            remote_addr = self.conn_tree.item(child_item)["values"][2].split(":")[0]
            if remote_addr == ip_address:
                found_item = child_item
                break

        # If the IP was found in the connections list
        if found_item:
            self.conn_tree.selection_set(found_item)
            self.conn_tree.focus(found_item)
            self.on_tree_select(None)  # Trigger detail update
            self.tab_control.select(self.tab_geo)  # Switch to the IP Details tab
        else:
            # Inform the user if the connection is no longer active
            messagebox.showinfo("Not Found", f"The connection for IP {ip_address} is no longer active.")
    def create_responsive_tabs(self, parent):
        self.tab_control = ttk.Notebook(parent)
        self.tab_control.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.create_live_tab()
        self.create_security_alerts_tab()
        self.create_general_alerts_tab()
        self.create_connections_tab()
        self.create_metadata_tab()
        self.create_geo_details_tab()
        self.create_domains_tab()
        self.create_forensics_tab()

    def create_live_tab(self):
        self.tab_live = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_live, text="📊 Live Netstat")
        self.tab_live.grid_rowconfigure(1, weight=1)
        self.tab_live.grid_columnconfigure(0, weight=1)
        header_font = self.ui_helper.get_scaled_font("Arial", 12, "bold")
        live_header = ttk.Label(self.tab_live, text="ACTIVE NETWORK CONNECTIONS",
                                font=header_font, foreground=self.colors["primary"])
        live_header.grid(row=0, column=0, pady=5, sticky="w")
        text_font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
        self.live_text = scrolledtext.ScrolledText(self.tab_live, wrap=tk.NONE,
                                                   font=text_font, bg="white")
        self.live_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.configure_live_text_tags()

    def create_security_alerts_tab(self):
        self.tab_security = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_security, text="🚨 Security Alerts")
        self.tab_security.grid_rowconfigure(1, weight=1)
        self.tab_security.grid_columnconfigure(0, weight=1)
        header_font = self.ui_helper.get_scaled_font("Arial", 12, "bold")
        security_label = ttk.Label(self.tab_security, text="⚠️ HIGH-PRIORITY SECURITY THREATS",
                                   font=header_font, foreground=self.colors["danger"])
        security_label.grid(row=0, column=0, pady=5, sticky="w")
        text_font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
        self.sec_text = scrolledtext.ScrolledText(self.tab_security, wrap=tk.WORD,
                                                  font=text_font,
                                                  foreground="darkred", background="#fff8f8")
        self.sec_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.configure_security_text_tags()

    def create_general_alerts_tab(self):
        self.tab_general = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_general, text="ℹ️ General Alerts")
        self.tab_general.grid_rowconfigure(1, weight=1)
        self.tab_general.grid_columnconfigure(0, weight=1)
        header_font = self.ui_helper.get_scaled_font("Arial", 12, "bold")
        general_label = ttk.Label(self.tab_general, text="📊 INFORMATIONAL ALERTS",
                                  font=header_font, foreground=self.colors["info"])
        general_label.grid(row=0, column=0, pady=5, sticky="w")
        text_font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
        self.gen_text = scrolledtext.ScrolledText(self.tab_general, wrap=tk.WORD,
                                                  font=text_font,
                                                  foreground="darkblue", background="#f2f2f7")
        self.gen_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.configure_general_text_tags()

    def create_connections_tab(self):
        self.tab_conn = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_conn, text="🔗 Connections")
        self.tab_conn.grid_rowconfigure(1, weight=1)
        self.tab_conn.grid_columnconfigure(0, weight=1)
        header_font = self.ui_helper.get_scaled_font("Arial", 12, "bold")
        conn_label = ttk.Label(self.tab_conn, text="CONNECTION DETAILS WITH GEO INFO",
                               font=header_font, foreground=self.colors["primary"])
        conn_label.grid(row=0, column=0, pady=5, sticky="w")
        tree_container = tk.Frame(self.tab_conn, bg=self.colors["bg"])
        tree_container.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        cols = ("proto", "local", "remote", "state", "pid", "process", "class", "country", "org", "service")
        self.conn_tree = ttk.Treeview(tree_container, columns=cols, show="headings")
        self.column_configs = {
            "proto": {"ratio": 0.8, "min_width": 50},
            "local": {"ratio": 2.5, "min_width": 120},
            "remote": {"ratio": 2.5, "min_width": 120},
            "state": {"ratio": 1.2, "min_width": 80},
            "pid": {"ratio": 0.8, "min_width": 50},
            "process": {"ratio": 2.0, "min_width": 100},
            "class": {"ratio": 1.0, "min_width": 70},
            "country": {"ratio": 1.2, "min_width": 80},
            "org": {"ratio": 3.0, "min_width": 150},
            "service": {"ratio": 1.5, "min_width": 90}
        }

        for col in cols:
            self.conn_tree.heading(col, text=col.capitalize())
        v_scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.conn_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_container, orient="horizontal", command=self.conn_tree.xview)
        self.conn_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        self.conn_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        self.conn_tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        self.conn_tree.bind('<Double-1>', self.on_connection_double_click)

    def create_metadata_tab(self):
        self.tab_meta = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_meta, text="📋 Metadata")
        self.tab_meta.grid_rowconfigure(1, weight=1)
        self.tab_meta.grid_columnconfigure(0, weight=1)
        header_font = self.ui_helper.get_scaled_font("Arial", 12, "bold")
        meta_label = ttk.Label(self.tab_meta, text="ALERT EVIDENCE & PACKET METADATA",
                               font=header_font, foreground=self.colors["primary"])
        meta_label.grid(row=0, column=0, pady=5, sticky="w")
        text_font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
        self.meta_text = scrolledtext.ScrolledText(self.tab_meta, wrap=tk.WORD,
                                                   font=text_font, bg="white")
        self.meta_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.configure_metadata_text_tags()

    def create_geo_details_tab(self):
        self.tab_geo = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_geo, text="🌍 IP Details")

        # <-- CHANGE: Configure grid rows/columns for proper expansion
        self.tab_geo.grid_rowconfigure(1, weight=1)
        self.tab_geo.grid_columnconfigure(0, weight=1)

        header_font = self.ui_helper.get_scaled_font("Arial", 12, "bold")
        geo_label = ttk.Label(self.tab_geo, text="GEOGRAPHIC & ORGANIZATIONAL DETAILS",
                              font=header_font, foreground=self.colors["primary"])
        # <-- CHANGE: Use grid for the header
        geo_label.grid(row=0, column=0, pady=5, sticky="w", padx=5)

        # <-- CHANGE: Use a PanedWindow for a resizable layout
        paned_window = ttk.PanedWindow(self.tab_geo, orient=tk.HORIZONTAL)
        paned_window.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # --- Left Pane (Details Tree) ---
        tree_frame = tk.Frame(paned_window, bg=self.colors["bg"])
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        geo_cols = ("property", "value")
        self.geo_tree = ttk.Treeview(tree_frame, columns=geo_cols, show="headings")
        self.geo_tree.heading("property", text="Property")
        self.geo_tree.heading("value", text="Value")
        geo_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.geo_tree.yview)
        self.geo_tree.configure(yscrollcommand=geo_scroll.set)
        self.geo_tree.grid(row=0, column=0, sticky="nsew")
        geo_scroll.grid(row=0, column=1, sticky="ns")

        # --- Right Pane (Map) ---
        map_frame = ttk.LabelFrame(paned_window, text="📍 Location Visualization")
        map_frame.grid_rowconfigure(0, weight=1)
        map_frame.grid_columnconfigure(0, weight=1)

        self.map_widget = tkintermapview.TkinterMapView(map_frame, corner_radius=0)
        self.map_widget.grid(row=0, column=0, sticky="nsew")
        self.map_widget.set_position(28.6139, 77.2090)  # Default to Delhi, India
        self.map_widget.set_zoom(5)

        # <-- CHANGE: Add the frames to the PanedWindow with equal weight
        paned_window.add(tree_frame, weight=1)
        paned_window.add(map_frame, weight=1)

        # <-- CHANGE: Put the placeholder inside the left `tree_frame` to center it correctly
        self.ip_details_placeholder = ttk.Label(
            tree_frame,  # Parent is now the left pane
            text="double click a ip from the 'Connections/Domain/VTscore' tab to see details here.",
            font=("Arial", 11, "italic"),
            foreground="grey",
            wraplength=800  # Wraps text if the pane is too narrow
        )
        self.ip_details_placeholder.place(relx=0.5, rely=0.5, anchor='center')
    def create_domains_tab(self):
        self.tab_domains = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_domains, text="🌐 Domains")
        self.tab_domains.grid_rowconfigure(1, weight=1)
        self.tab_domains.grid_columnconfigure(0, weight=1)
        header_font = self.ui_helper.get_scaled_font("Arial", 12, "bold")
        domain_label = ttk.Label(self.tab_domains, text="DOMAIN NAME RESOLUTIONS & STATISTICS",
                                 font=header_font, foreground=self.colors["primary"])
        domain_label.grid(row=0, column=0, pady=5, sticky="w", padx=5)

        tree_container = tk.Frame(self.tab_domains, bg=self.colors["bg"])
        tree_container.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        domain_cols = ("ip", "domain", "count", "classification")
        self.domain_tree = ttk.Treeview(tree_container, columns=domain_cols, show="headings")
        self.domain_tree.heading("ip", text="IP Address")
        self.domain_tree.heading("domain", text="Domain Name")
        self.domain_tree.heading("count", text="Connections")
        self.domain_tree.heading("classification", text="Type")
        self.domain_column_configs = {
            "ip": {"ratio": 2, "min_width": 120},
            "domain": {"ratio": 4, "min_width": 200},
            "count": {"ratio": 1, "min_width": 80},
            "classification": {"ratio": 1.5, "min_width": 100}
        }
        domain_scroll_y = ttk.Scrollbar(tree_container, orient="vertical", command=self.domain_tree.yview)
        domain_scroll_x = ttk.Scrollbar(tree_container, orient="horizontal", command=self.domain_tree.xview)
        self.domain_tree.configure(yscrollcommand=domain_scroll_y.set, xscrollcommand=domain_scroll_x.set)
        self.domain_tree.grid(row=0, column=0, sticky="nsew")
        domain_scroll_y.grid(row=0, column=1, sticky="ns")
        domain_scroll_x.grid(row=1, column=0, sticky="ew")
        self.domain_tree.bind('<Double-1>', self.on_domain_double_click)
        button_frame = tk.Frame(self.tab_domains, bg=self.colors["bg"])
        button_frame.grid(row=2, column=0, sticky="ew", pady=5, padx=5)
        button_frame.grid_columnconfigure(1, weight=1)

        # lookup_btn = tk.Button(button_frame, text="🔎 Lookup IP Details",
        #                        command=self.lookup_ip_from_domain_tab,
        #                        bg=self.colors["info"], fg="white",
        #                        font=self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"]))
        # lookup_btn.grid(row=0, column=0, sticky="w")

        export_domain_btn = tk.Button(button_frame, text="📤 Export Domain Data",
                                      command=self.export_domain_data,
                                      bg=self.colors["primary"], fg="white",
                                      font=self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"]))
        export_domain_btn.grid(row=0, column=1, sticky="e")
        self.domain_placeholder = ttk.Label(
            tree_container, # Use tree_container so it's in the same space as the tree
            text="click start monitoring to see the domain details",
            font=("Arial", 11, "italic"),
            foreground="red",
            wraplength=1000
        )
        self.domain_placeholder.place(relx=0.5, rely=0.5, anchor="center")

    def create_forensics_tab(self):
        self.tab_forensics = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_forensics, text="🔍 Forensics")
        self.forensics_tab = ForensicsTab(self.tab_forensics, self)
        self.forensics_tab.start()

    def create_responsive_status_bar(self):
        status_container = tk.Frame(self.root, bg=self.colors["bg"])
        status_container.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        status_container.grid_columnconfigure(0, weight=1)

        status_info_frame = tk.Frame(status_container, bg=self.colors["bg"])
        status_info_frame.grid(row=0, column=0, sticky="ew", pady=2)

        status_info_frame.grid_columnconfigure(0, weight=1)
        status_info_frame.grid_columnconfigure(1, weight=0)

        status_frame = tk.Frame(status_info_frame, bg=self.colors["bg"])
        status_frame.grid(row=0, column=0, sticky="w")

        status_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"])
        self.status_var = tk.StringVar(value="🔴 Monitoring Stopped")
        self.conn_count_var = tk.StringVar(value="Connections: 0")
        self.api_source_var = tk.StringVar(value="API: None")
        self.threat_api_source_var = tk.StringVar(value="Threat API: None")
        self.security_stats_var = tk.StringVar(value="🚨 Security Alerts: 0")
        self.general_stats_var = tk.StringVar(value="ℹ️ General Alerts: 0")

        self.status_label = tk.Label(status_frame, textvariable=self.status_var,
                                     bg=self.colors["bg"], fg=self.colors["dark"], font=status_font)
        self.status_label.grid(row=0, column=0, sticky="w")

        self.conn_count_label = tk.Label(status_frame, textvariable=self.conn_count_var,
                                         bg=self.colors["bg"], fg=self.colors["dark"], font=status_font)
        self.conn_count_label.grid(row=0, column=1, sticky="w", padx=(20, 0))

        self.api_source_label = tk.Label(status_frame, textvariable=self.api_source_var,
                                         bg=self.colors["bg"], fg=self.colors["dark"], font=status_font)
        self.api_source_label.grid(row=0, column=2, sticky="w", padx=(20, 0))

        self.threat_api_source_label = tk.Label(status_frame, textvariable=self.threat_api_source_var,
                                          bg=self.colors["bg"], fg=self.colors["dark"], font=status_font)
        self.threat_api_source_label.grid(row=0, column=3, sticky="w", padx=(20, 0))

        self.security_stats_label = tk.Label(status_frame, textvariable=self.security_stats_var,
                                             bg=self.colors["bg"], fg=self.colors["danger"],
                                             font=status_font)
        self.security_stats_label.grid(row=0, column=4, sticky="w", padx=(20, 0))

        self.general_stats_label = tk.Label(status_frame, textvariable=self.general_stats_var,
                                            bg=self.colors["bg"], fg=self.colors["info"],
                                            font=status_font)
        self.general_stats_label.grid(row=0, column=5, sticky="w", padx=(20, 0))

        export_frame = tk.Frame(status_info_frame, bg=self.colors["bg"])
        export_frame.grid(row=0, column=1, sticky="e")

        export_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"] - 1)
        self.export_conn_btn = tk.Button(export_frame, text="📊 Export Connections",
                                         command=self.export_connections,
                                         bg=self.colors["primary"], fg="white",
                                         font=export_font, padx=5)
        self.export_conn_btn.grid(row=0, column=0, padx=2, pady=2)

        self.export_security_btn = tk.Button(export_frame, text="🚨 Export Security",
                                             command=self.export_security_alerts,
                                             bg=self.colors["danger"], fg="white",
                                             font=export_font, padx=5)
        self.export_security_btn.grid(row=0, column=1, padx=2, pady=2)

        self.export_general_btn = tk.Button(export_frame, text="ℹ️ Export General",
                                            command=self.export_general_alerts,
                                            bg=self.colors["info"], fg="white",
                                            font=export_font, padx=5)
        self.export_general_btn.grid(row=1, column=0, padx=2, pady=2)

        self.clear_alerts_btn = tk.Button(export_frame, text="🗑️ Clear Alerts",
                                          command=self.clear_alert_history,
                                          bg=self.colors["warning"], fg="white",
                                          font=export_font, padx=5)
        self.clear_alerts_btn.grid(row=1, column=1, padx=2, pady=2)

        ctrl_frame = tk.Frame(status_container, bg=self.colors["bg"])
        ctrl_frame.grid(row=1, column=0, sticky="w", pady=2)

        button_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"], "bold")
        self.start_btn = tk.Button(ctrl_frame, text="▶️ Start Monitoring",
                                   command=self.start_monitoring,
                                   bg=self.colors["success"], fg="white",
                                   font=button_font, padx=10)
        self.start_btn.grid(row=0, column=0, padx=5, pady=2)

        self.stop_btn = tk.Button(ctrl_frame, text="⏹️ Stop Monitoring",
                                  command=self.stop_monitoring, state=tk.DISABLED,
                                  bg=self.colors["danger"], fg="white",
                                  font=button_font, padx=10)
        self.stop_btn.grid(row=0, column=1, padx=5, pady=2)

    def lookup_ip_from_domain_tab(self):
        selected = self.domain_tree.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Please select an item from the domain list first.")
            return

        item = self.domain_tree.item(selected[0])
        ip_address = item["values"][0]

        for child_item in self.conn_tree.get_children():
            values = self.conn_tree.item(child_item)["values"]
            remote_addr = values[2].split(":")[0]
            if remote_addr == ip_address:
                self.conn_tree.selection_set(child_item)
                self.conn_tree.focus(child_item)
                self.on_tree_select(None)
                self.tab_control.select(self.tab_geo)
                break
        else:
            messagebox.showwarning("Not Found", f"Could not find an active connection for IP {ip_address} to look up.")

    def configure_live_text_tags(self):
        header_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"] + 1, "bold")
        timestamp_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"] - 1)
        self.live_text.tag_configure("listening", foreground="green")
        self.live_text.tag_configure("established", foreground="blue")
        self.live_text.tag_configure("time_wait", foreground="purple")
        self.live_text.tag_configure("close_wait", foreground="orange")
        self.live_text.tag_configure("header", font=header_font, foreground=self.colors["primary"])
        self.live_text.tag_configure("timestamp", font=timestamp_font, foreground="#7f8c8d")

    def configure_security_text_tags(self):
        critical_font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"], "bold")
        high_font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
        timestamp_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"] - 1)
        self.sec_text.tag_configure("critical", foreground="red", font=critical_font)
        self.sec_text.tag_configure("high", foreground="darkred", font=high_font)
        self.sec_text.tag_configure("timestamp", font=timestamp_font, foreground="#7f8c8d")

    def configure_general_text_tags(self):
        suspicious_font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
        info_font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
        timestamp_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"] - 1)
        self.gen_text.tag_configure("suspicious", foreground="#8e44ad", font=suspicious_font)
        self.gen_text.tag_configure("ecommerce", foreground=self.colors["ecommerce"], font=suspicious_font)
        self.gen_text.tag_configure("social_media", foreground=self.colors["social_media"], font=suspicious_font)
        self.gen_text.tag_configure("malicious", foreground=self.colors["malicious"], font=(suspicious_font[0], suspicious_font[1], "bold"))
        self.gen_text.tag_configure("info", foreground="darkblue", font=info_font)
        self.gen_text.tag_configure("timestamp", font=timestamp_font, foreground="#7f8c8d")

    def configure_metadata_text_tags(self):
        header_font = self.ui_helper.get_scaled_font("Arial", CONFIG["ui"]["base_font_size"] + 1, "bold")
        self.meta_text.tag_configure("header", font=header_font, foreground=self.colors["primary"])
        self.meta_text.tag_configure("security", background="#fff8f8")
        self.meta_text.tag_configure("general", background="#f8f8ff")
        self.meta_text.tag_configure("ecommerce", background="#fff0e6", foreground=self.colors["ecommerce"])
        self.meta_text.tag_configure("social_media", background="#ebf5fb", foreground=self.colors["social_media"])
        self.meta_text.tag_configure("malicious", background="#fdeded", foreground=self.colors["malicious"], font=("Consolas", CONFIG["ui"]["base_font_size"], "bold"))

    def on_window_resize(self, event):
        if event.widget == self.root:
            width = event.width
            height = event.height
            old_scale = self.ui_helper.scale_factor
            self.ui_helper.update_scale_factor(width, height)
            if abs(old_scale - self.ui_helper.scale_factor) > 0.1:
                self.root.after(100, self.update_responsive_layout)

    def update_responsive_layout(self):
        try:
            if hasattr(self, 'conn_tree') and hasattr(self, 'column_configs'):
                self.ui_helper.configure_responsive_column_widths(self.conn_tree, self.column_configs)
            if hasattr(self, 'domain_tree') and hasattr(self, 'domain_column_configs'):
                self.ui_helper.configure_responsive_column_widths(self.domain_tree, self.domain_column_configs)
            if hasattr(self, 'geo_tree'):
                geo_width = max(200, int(self.ui_helper.current_width * 0.15))
                value_width = max(300, int(self.ui_helper.current_width * 0.25))
                try:
                    self.geo_tree.column("property", width=geo_width)
                    self.geo_tree.column("value", width=value_width)
                except tk.TclError:
                    pass
            self.update_text_widget_fonts()
            if hasattr(self, 'live_text'):
                self.configure_live_text_tags()
            if hasattr(self, 'sec_text'):
                self.configure_security_text_tags()
            if hasattr(self, 'gen_text'):
                self.configure_general_text_tags()
            if hasattr(self, 'meta_text'):
                self.configure_metadata_text_tags()
        except Exception as e:
            log("ERROR", f"Error updating responsive layout: {e}")

    def update_text_widget_fonts(self):
        try:
            if hasattr(self, 'live_text'):
                font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
                self.live_text.configure(font=font)
            if hasattr(self, 'sec_text'):
                font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
                self.sec_text.configure(font=font)
            if hasattr(self, 'gen_text'):
                font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
                self.gen_text.configure(font=font)
            if hasattr(self, 'meta_text'):
                font = self.ui_helper.get_scaled_font("Consolas", CONFIG["ui"]["base_font_size"])
                self.meta_text.configure(font=font)
        except Exception as e:
            log("ERROR", f"Error updating text widget fonts: {e}")

    def update_filters(self):
        CONFIG["filters"]["exclude_zero_remote"] = self.exclude_zero_var.get()
        CONFIG["filters"]["show_only_internal"] = self.show_internal_var.get()
        CONFIG["filters"]["show_listening_only"] = self.show_listening_var.get()
        log("INFO", f"Filters updated: exclude_zero={CONFIG['filters']['exclude_zero_remote']}, "
                  f"internal_only={CONFIG['filters']['show_only_internal']}, "
                  f"listening_only={CONFIG['filters']['show_listening_only']}")

    def start_monitoring(self):
        if self.is_monitoring:
            return
        self._stop_event.clear()
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.is_monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("🟢 Monitoring Active")
        log("INFO", "Endpoint monitoring started")

    def stop_monitoring(self):
        if not self.is_monitoring:
            return
        self._stop_event.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.is_monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("🔴 Monitoring Stopped")
        log("INFO", "Network monitoring stopped")

    def monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                lines = run_netstat_windows()
                recs = list(parse_netstat_lines(lines))

                with self.last_seen_lock:
                    self.last_seen = recs

                for r in recs:
                    try:
                        feed_record(r)
                    except Exception as e:
                        log("ERROR", f"Error feeding record: {e}")

                    if classify_internal_external(r.get("remote_ip")) == "external":
                        self.queue_ip_for_geo(r.get("remote_ip"))

                    self.track_domains(r)

                with self.domain_lock:
                    domain_state = {
                        'mapping': self.domain_mapping.copy(),
                        'counts': dict(self.domain_counts)
                    }
                rolling_logs['domains'].info(f"Domain State: {json.dumps(domain_state, indent=2)}")

            except Exception as e:
                log("ERROR", f"Monitor loop error: {e}")
            time.sleep(CONFIG["poll_interval_seconds"])

    def track_domains(self, record):
        remote_ip = record.get("remote_ip")
        if not remote_ip or remote_ip in ["0.0.0.0", "::", "*", ""]:
            return

        domain = ""
        if remote_ip in self.ip_details:
            details = self.ip_details[remote_ip]
            if "reverse" in details and details["reverse"] != "Unknown":
                domain = details["reverse"]

        if not domain:
            with dns_lock:
                if remote_ip in dns_cache and dns_cache[remote_ip]:
                    domain = dns_cache[remote_ip]

        with self.domain_lock:
            self.domain_mapping[remote_ip] = domain
            self.domain_counts[remote_ip] += 1

    def queue_ip_for_geo(self, ip):
        if not ip or ip in ["0.0.0.0", "::", "*", ""]:
            return

        if isinstance(ip, tuple) and len(ip) == 2:
            ip = ip[0]

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return

        if ip in self.ip_details and self.ip_details[ip].get("status") != "queued":
            return

        self.ip_details[ip] = {"status": "queued"}

        def geo_callback(ip_addr, details):
            self.ip_details[ip_addr] = details
            self.api_source_var.set(f"API: {details.get('api_source', 'Unknown')}")
            self.threat_api_source_var.set(f"Threat API: {details.get('threat_api_source', 'None')}")

        try:
            geo_queue.put_nowait((ip, geo_callback))
        except queue.Full:
            log("WARNING", f"Geo queue full, skipping IP: {ip}")

    def ui_update_loop(self):
        try:
            self.update_live_text()
            self.update_connections_tree()
            self.update_domains_tree()
            self.process_alerts_queue()
            self.update_statistics()
        except Exception as e:
            log("ERROR", f"UI update loop error: {e}")
        self.root.after(self.ui_update_interval, self.ui_update_loop)

    def update_live_text(self):
        try:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.live_text.config(state="normal")
            self.live_text.delete(1.0, tk.END)
            self.live_text.insert(tk.END, f"📊 Last Updated: ", "header")
            self.live_text.insert(tk.END, f"{ts}\n", "timestamp")
            filter_text = []
            if CONFIG['filters']['exclude_zero_remote']:
                filter_text.append("Exclude 0.0.0.0")
            if CONFIG['filters']['show_only_internal']:
                filter_text.append("Internal Only")
            if CONFIG['filters']['show_listening_only']:
                filter_text.append("Listening Only")
            filter_display = ", ".join(filter_text) if filter_text else "None"
            self.live_text.insert(tk.END, f"🔍 Active Filters: ", "header")
            self.live_text.insert(tk.END, f"{filter_display}\n\n")
            with self.last_seen_lock:
                last_seen_copy = self.last_seen[:]
            if last_seen_copy:
                self.live_text.insert(tk.END, f"📈 Active Connections ({len(last_seen_copy)}):\n", "header")
                for r in last_seen_copy:
                    remote_port = f":{r.get('remote_port')}" if r.get('remote_port') is not None else ""
                    local_port = f":{r.get('local_port')}" if r.get('local_port') is not None else ""
                    line = f"{r.get('proto'):5} {r.get('local_ip')}{local_port:15} → {r.get('remote_ip')}{remote_port:20} [{r.get('state'):12}] PID:{r.get('pid')} ({r.get('process') or 'Unknown'})\n"
                    state = r.get('state', '').lower()
                    classification = classify_internal_external(r.get("remote_ip"))
                    if state in ["listening", "listen"]:
                        tag = "listening"
                    elif state == "established":
                        tag = "established" if classification == "internal" else "time_wait"
                    elif state in ["time_wait", "close_wait"]:
                        tag = state.replace("_", "_")
                    else:
                        tag = None
                    self.live_text.insert(tk.END, line, tag)
            else:
                self.live_text.insert(tk.END, "⏸️ No active connections. Click 'Start Monitoring' to begin.\n")
            self.live_text.config(state="disabled")
        except Exception as e:
            log("ERROR", f"Live text update error: {e}")

    def update_connections_tree(self):
        try:
            for item in self.conn_tree.get_children():
                self.conn_tree.delete(item)
            with self.last_seen_lock:
                last_seen_copy = self.last_seen[:]

            for r in last_seen_copy:
                state = r.get('state', '')
                remote_ip = r.get("remote_ip")
                is_listening = state.upper() in ('LISTENING', 'LISTEN')

                if CONFIG["filters"]["show_listening_only"]:
                    if not is_listening:
                        continue
                else:
                    if is_listening or remote_ip == "*":
                        continue

                if CONFIG["filters"]["exclude_zero_remote"] and remote_ip == "0.0.0.0":
                    continue

                classification = classify_internal_external(remote_ip)
                if CONFIG["filters"]["show_only_internal"] and classification != "internal":
                    continue

                if is_listening:
                    remote_addr = "N/A"
                    classification = "N/A"
                    geo = {}
                else:
                    geo = self.ip_details.get(remote_ip, {})
                    remote_port = r.get("remote_port")
                    remote_addr = f"{remote_ip}" + (f":{remote_port}" if remote_port is not None else "")

                local_port = r.get("local_port")
                local_addr = f"{r.get('local_ip')}" + (f":{local_port}" if local_port is not None else "")
                process_name = r.get('process') or "Unknown"

                item = self.conn_tree.insert("", "end", values=(
                    r.get("proto", ""),
                    local_addr,
                    remote_addr,
                    state,
                    r.get('pid') or "-",
                    process_name,
                    classification.title(),
                    geo.get("country", "N/A"),
                    geo.get("org", "N/A")[:30] + "..." if geo.get("org") and len(geo.get("org", "")) > 30 else geo.get("org", "N/A"),
                    geo.get("service", "N/A")
                ))

                if classification == "external":
                    self.conn_tree.item(item, tags=("external",))
                elif classification == "internal":
                    self.conn_tree.item(item, tags=("internal",))

            if hasattr(self, 'column_configs'):
                self.ui_helper.configure_responsive_column_widths(self.conn_tree, self.column_configs)
        except Exception as e:
            log("ERROR", f"Connection tree update error: {e}")

    def update_domains_tree(self):
        try:
            for item in self.domain_tree.get_children():
                self.domain_tree.delete(item)
            with self.domain_lock:
                domain_mapping_copy = self.domain_mapping.copy()
                domain_counts_copy = dict(self.domain_counts)
            if not domain_mapping_copy:
                # If no data, ensure the placeholder is visible and hide the tree
                if self.domain_placeholder:
                    self.domain_placeholder.lift()  # Bring placeholder to the front
                self.domain_tree.delete(*self.domain_tree.get_children())  # Clear tree just in case
                return  # Stop the function here
            else:
                # If there is data, hide the placeholder
                if self.domain_placeholder:
                    self.domain_placeholder.lower()  # Send placeholder to the back

            for ip, domain in domain_mapping_copy.items():
                count = domain_counts_copy.get(ip, 0)
                classification = classify_internal_external(ip)
                tag = mark_suspicious_by_ip_or_host(ip) or mark_suspicious_by_ip_or_host(domain or "")
                if tag:
                    classification_display = f"{classification.title()} ({tag.replace('_', ' ').title()})"
                else:
                    classification_display = classification.title()
                item = self.domain_tree.insert("", "end", values=(
                    ip,
                    domain or "Resolving...",
                    count,
                    classification_display
                ))
                if tag == "ecommerce":
                    self.domain_tree.item(item, tags=("ecommerce",))
                elif tag == "social_media":
                    self.domain_tree.item(item, tags=("social_media",))
                elif tag == "malicious":
                    self.domain_tree.item(item, tags=("malicious",))
            if hasattr(self, 'domain_column_configs'):
                self.ui_helper.configure_responsive_column_widths(self.domain_tree, self.domain_column_configs)
        except Exception as e:
            log("ERROR", f"Domain tree update error: {e}")

    def process_alerts_queue(self):
        try:
            while True:
                alert = alerts_q.get_nowait()
                self.display_alert(alert)
        except queue.Empty:
            pass

    def update_statistics(self):
        with self.last_seen_lock:
            conn_count = len(self.last_seen)
        security_count = len(self.security_alerts_history)
        general_count = len(self.general_alerts_history)
        self.conn_count_var.set(f"🔗 Connections: {conn_count}")
        self.security_stats_var.set(f"🚨 Security Alerts: {security_count}")
        self.general_stats_var.set(f"ℹ️ General Alerts: {general_count}")

    def display_alert(self, alert):
        try:
            alert_type = alert.get("type", "UNKNOWN")
            level = alert.get("level", "INFO")
            msg = alert.get("message", "")
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            severity = determine_alert_severity(alert_type, level)

            if severity == "security":
                rolling_logs['security_alerts'].info(f"[{level}] {msg}")

                self.sec_text.config(state="normal")
                self.sec_text.insert(tk.END, f"[{ts}] ", "timestamp")
                if level == "CRITICAL":
                    self.sec_text.insert(tk.END, f"🔴 [{level}] ", "critical")
                else:
                    self.sec_text.insert(tk.END, f"🟠 [{level}] ", "high")
                self.sec_text.insert(tk.END, f"{msg}\n")
                self.sec_text.see(tk.END)
                self.sec_text.config(state="disabled")
                self.security_alerts_history.append({
                    "timestamp": ts,
                    "level": level,
                    "type": alert_type,
                    "message": msg,
                    "evidence": alert.get("evidence", {}),
                    "severity": "security"
                })
                if level == "CRITICAL":
                    self.root.after(0, lambda: messagebox.showwarning(
                        f"🚨 CRITICAL SECURITY ALERT: {alert_type}",
                        msg,
                        icon=messagebox.WARNING
                    ))
            else:
                rolling_logs['general_alerts'].info(f"[{level}] {msg}")

                self.gen_text.config(state="normal")
                self.gen_text.insert(tk.END, f"[{ts}] ", "timestamp")
                if alert_type == "SUSPICIOUS":
                    subtype = alert.get("subtype", "suspicious")
                    tag = subtype if subtype in ["ecommerce", "social_media", "malicious"] else "suspicious"
                    self.gen_text.insert(tk.END, f"🔍 [{level}] ", tag)
                    self.gen_text.insert(tk.END, f"{msg}\n", tag)
                else:
                    self.gen_text.insert(tk.END, f"ℹ️ [{level}] {msg}\n", "info")
                self.gen_text.see(tk.END)
                self.gen_text.config(state="disabled")
                self.general_alerts_history.append({
                    "timestamp": ts,
                    "level": level,
                    "type": alert_type,
                    "message": msg,
                    "evidence": alert.get("evidence", {}),
                    "severity": "general",
                    "subtype": alert.get("subtype", None)
                })
            self.update_metadata_display(alert, severity)
        except Exception as e:
            log("ERROR", f"Error displaying alert: {e}")

    def update_metadata_display(self, alert, severity):
        try:
            ev = alert.get("evidence", {})
            if ev:
                geo_details = ""
                rip = ev.get("remote_ip")
                if rip and rip in self.ip_details:
                    details = self.ip_details[rip]
                    geo_details = (
                        f"\n🌍 Geographic Details:"
                        f"\n  Organization: {details.get('org', 'Unknown')}"
                        f"\n  Country: {details.get('country', 'Unknown')}"
                        f"\n  Region: {details.get('region', 'Unknown')}"
                        f"\n  City: {details.get('city', 'Unknown')}"
                        f"\n  Service Type: {details.get('service', 'Unknown')}"
                        f"\n\n🛡️ Threat Intelligence:"
                        f"\n  Threat Status: {details.get('threat', 'Unknown')}"
                        f"\n  AbuseIPDB Score: {details.get('abuse_score', 'N/A')}/100"
                        f"\n  VirusTotal Detections: {details.get('vt_positives', 'N/A')}"
                    )
                severity_emoji = "🚨" if severity == "security" else "ℹ️"
                meta = (
                    f"=== {severity_emoji} {severity.upper()} ALERT EVIDENCE ===\n"
                    f"🔍 Alert Type: {alert.get('type')} | Severity: {severity.upper()}\n"
                    f"📊 Raw Connection: {ev.get('line_raw')}\n"
                    f"🖥️  Process Info: PID:{ev.get('pid')} | Process: {ev.get('process')}{geo_details}\n\n"
                )

                rolling_logs['metadata'].info(meta)

                self.meta_text.config(state="normal")
                tag = "security" if severity == "security" else "general"
                subtype = alert.get("subtype")
                if subtype in ["ecommerce", "social_media", "malicious"]:
                    tag = subtype
                self.meta_text.insert(tk.END, meta, tag)
                self.meta_text.see(tk.END)
                self.meta_text.config(state="disabled")
        except Exception as e:
            log("ERROR", f"Error updating metadata display: {e}")

    def on_tree_select(self, event):
        # === NEW: Part 1 - Remove the placeholder label on first click ===
        if hasattr(self, 'ip_details_placeholder') and self.ip_details_placeholder:
            self.ip_details_placeholder.destroy()
            self.ip_details_placeholder = None  # Set to None to prevent errors

        # Standard logic to get the selected item
        if self.root.focus_get() != self.conn_tree and event is not None:
            return
        selected = self.conn_tree.selection()
        if not selected:
            return
        item = self.conn_tree.item(selected[0])
        values = item["values"]
        if not values: return
        remote_addr = values[2].split(":")[0]

        # Clear previous details
        for i in self.geo_tree.get_children():
            self.geo_tree.delete(i)
        self.map_widget.delete_all_marker()

        # === NEW: Part 2 - Check if IP is internal and display a message ===
        classification = classify_internal_external(remote_addr)
        if classification in ["internal", "unknown"]:
            self.geo_tree.insert("", "end", values=("Status", f"No external lookup for {classification} IPs."))
            self.map_widget.set_position(20.5937, 78.9629)  # Reset map to default view
            self.map_widget.set_zoom(4)
            return  # Stop further processing

        if self.root.focus_get() != self.conn_tree and event is not None:
            return

        selected = self.conn_tree.selection()
        if not selected:
            return
        item = self.conn_tree.item(selected[0])
        values = item["values"]
        if not values: return
        remote_addr = values[2].split(":")[0]

        for i in self.geo_tree.get_children():
            self.geo_tree.delete(i)

        self.map_widget.delete_all_marker()

        if remote_addr in self.ip_details:
            details = self.ip_details[remote_addr]
            display_details = [
                ("IP Address", remote_addr),
                ("Country", details.get("country", "Unknown")),
                ("Region", details.get("region", "Unknown")),
                ("City", details.get("city", "Unknown")),
                ("Organization", details.get("org", "Unknown")),
                ("Service Type", details.get("service", "Unknown")),
                ("ASN", details.get("asn", "Unknown")),
                ("Reverse DNS", details.get("reverse", "Unknown")),
                ("Location", details.get("location", "Unknown")),
                ("Data Source", details.get("api_source", "Unknown")),
                ("", ""),
                ("Threat Status", details.get("threat", "Unknown")),
                ("AbuseIPDB Score", f"{details.get('abuse_score', 'N/A')}/100"),
                ("VirusTotal Detections", details.get('vt_positives', 'N/A')),
                ("Threat Details", details.get('threat_details', 'N/A'))
            ]
            for key, value in display_details:
                display_value = str(value)
                if len(display_value) > 50:
                    display_value = display_value[:47] + "..."
                self.geo_tree.insert("", "end", values=(key, display_value))

            location_str = details.get("location", "Unknown")
            if location_str and location_str != "Unknown":
                try:
                    lat, lon = map(float, location_str.split(','))
                    self.map_widget.set_position(lat, lon, marker=True)
                    self.map_widget.set_zoom(10)
                    if self.map_widget.canvas_marker_list:
                        marker_text = f"{remote_addr}\n{details.get('city', '')}"
                        self.map_widget.canvas_marker_list[0].set_text(marker_text)

                except (ValueError, IndexError):
                    log("WARNING", f"Could not parse location: {location_str}")
                    self.map_widget.set_position(20.5937, 78.9629)
                    self.map_widget.set_zoom(4)
            else:
                self.map_widget.set_position(20.5937, 78.9629)
                self.map_widget.set_zoom(4)
        else:
            self.geo_tree.insert("", "end", values=("Status", "⏳ Loading details..."))
            self.queue_ip_for_geo(remote_addr)

    def export_connections(self):
        with self.last_seen_lock:
            last_seen_copy = self.last_seen[:]
        if not last_seen_copy:
            messagebox.showinfo("📊 Export", "No connection data available to export")
            return
        try:
            self._export_data_with_dialog(
                data=last_seen_copy,
                title="Export Network Connections",
                default_name="network_connections",
                formatter=self._format_connection_export
            )
        except Exception as e:
            log("ERROR", f"Connection export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export connections:\n{str(e)}")

    def export_security_alerts(self):
        if not self.security_alerts_history:
            messagebox.showinfo("🚨 Export", "No security alerts to export")
            return
        try:
            self._export_alerts_with_dialog(
                self.security_alerts_history,
                "Security Alerts",
                "security_alerts"
            )
        except Exception as e:
            log("ERROR", f"Security alerts export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export security alerts:\n{str(e)}")

    def export_general_alerts(self):
        if not self.general_alerts_history:
            messagebox.showinfo("ℹ️ Export", "No general alerts to export")
            return
        try:
            self._export_alerts_with_dialog(
                self.general_alerts_history,
                "General Alerts",
                "general_alerts"
            )
        except Exception as e:
            log("ERROR", f"General alerts export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export general alerts:\n{str(e)}")

    def export_domain_data(self):
        if not self.domain_mapping:
            messagebox.showinfo("🌐 Export", "No domain data available to export")
            return
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                initialfile=f"domain_data_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
                filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json"), ("All Files", "*.*")],
                title="Export Domain Data"
            )
            if not file_path:
                return
            ext = os.path.splitext(file_path)[1].lower()
            if ext == ".csv":
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["IP Address", "Domain Name", "Connection Count", "Classification", "Suspicious"])
                    for ip, domain in self.domain_mapping.items():
                        count = self.domain_counts.get(ip, 0)
                        classification = classify_internal_external(ip)
                        suspicious_tag = mark_suspicious_by_ip_or_host(ip) or mark_suspicious_by_ip_or_host(domain or "")
                        writer.writerow([
                            ip,
                            domain or "Unknown",
                            count,
                            classification,
                            suspicious_tag or "None"
                        ])
            else:
                data = []
                for ip, domain in self.domain_mapping.items():
                    count = self.domain_counts.get(ip, 0)
                    classification = classify_internal_external(ip)
                    suspicious_tag = mark_suspicious_by_ip_or_host(ip) or mark_suspicious_by_ip_or_host(domain or "")
                    data.append({
                        "ip_address": ip,
                        "domain_name": domain or "Unknown",
                        "connection_count": count,
                        "classification": classification,
                        "suspicious": suspicious_tag,
                        "geo_details": self.ip_details.get(ip, {})
                    })
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            messagebox.showinfo("✅ Export Complete", f"Domain data exported successfully:\n{file_path}")
            log("INFO", f"Domain data exported to {file_path}")
        except Exception as e:
            log("ERROR", f"Domain export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export domain data:\n{str(e)}")

    def clear_alert_history(self):
        try:
            result = messagebox.askyesno(
                "Clear Alerts",
                "Are you sure you want to clear all alert history?\n\nThis will also reset alert cooldowns.",
                icon=messagebox.QUESTION
            )
            if result:
                self.sec_text.config(state="normal")
                self.sec_text.delete(1.0, tk.END)
                self.sec_text.config(state="disabled")
                self.gen_text.config(state="normal")
                self.gen_text.delete(1.0, tk.END)
                self.gen_text.config(state="disabled")
                self.meta_text.config(state="normal")
                self.meta_text.delete(1.0, tk.END)
                self.meta_text.config(state="disabled")
                self.security_alerts_history.clear()
                self.general_alerts_history.clear()
                with alert_lock:
                    for alert_type in alert_history:
                        alert_history[alert_type].clear()
                log("INFO", "Alert history cleared and tracking reset")
                messagebox.showinfo("✅ Cleared", "All alerts have been cleared and tracking has been reset.")
        except Exception as e:
            log("ERROR", f"Error clearing alerts: {e}")
            messagebox.showerror("Error", f"Failed to clear alerts:\n{str(e)}")

    def _export_data_with_dialog(self, data, title, default_name, formatter):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=f"{default_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json"), ("All Files", "*.*")],
            title=title
        )
        if not file_path:
            return
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            formatter(file_path, data, "csv")
        else:
            formatter(file_path, data, "json")
        messagebox.showinfo("✅ Export Complete", f"Data exported successfully:\n{file_path}")
        log("INFO", f"Data exported to {file_path}")

    def _format_connection_export(self, file_path, data, format_type):
        if format_type == "csv":
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Protocol", "Local Address", "Remote Address", "State",
                    "PID", "Process", "Classification", "Country",
                    "Organization", "Service", "Suspicious", "Timestamp",
                    "Threat Status", "AbuseIPDB Score", "VirusTotal Detections"
                ])
                for r in data:
                    geo = self.ip_details.get(r.get("remote_ip"), {})
                    suspicious_tag = mark_suspicious_by_ip_or_host(r.get("remote_ip"))
                    remote_port = f":{r.get('remote_port')}" if r.get('remote_port') is not None else ""
                    local_port = f":{r.get('local_port')}" if r.get('local_port') is not None else ""
                    writer.writerow([
                        r.get("proto", ""),
                        f"{r.get('local_ip')}{local_port}",
                        f"{r.get('remote_ip')}{remote_port}",
                        r.get("state", ""),
                        r.get("pid", ""),
                        r.get("process", ""),
                        classify_internal_external(r.get("remote_ip")),
                        geo.get("country", "N/A"),
                        geo.get("org", "N/A"),
                        geo.get("service", "N/A"),
                        suspicious_tag or "None",
                        datetime.datetime.now().isoformat(),
                        geo.get("threat", "N/A"),
                        geo.get("abuse_score", "N/A"),
                        geo.get("vt_positives", "N/A")
                    ])
        else:
            export_data = []
            for r in data:
                geo = self.ip_details.get(r.get("remote_ip"), {})
                suspicious_tag = mark_suspicious_by_ip_or_host(r.get("remote_ip"))
                remote_port = f":{r.get('remote_port')}" if r.get('remote_port') is not None else ""
                local_port = f":{r.get('local_port')}" if r.get('local_port') is not None else ""
                export_data.append({
                    "protocol": r.get("proto", ""),
                    "local_address": f"{r.get('local_ip')}{local_port}",
                    "remote_address": f"{r.get('remote_ip')}{remote_port}",
                    "state": r.get("state", ""),
                    "pid": r.get("pid", ""),
                    "process": r.get("process", ""),
                    "classification": classify_internal_external(r.get("remote_ip")),
                    "suspicious": suspicious_tag,
                    "geo_details": geo,
                    "timestamp": datetime.datetime.now().isoformat()
                })
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)

    def _export_alerts_with_dialog(self, alerts_data, title, default_name):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=f"{default_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json"), ("All Files", "*.*")],
            title=f"Export {title}"
        )
        if not file_path:
            return
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp", "Severity", "Level", "Type", "Message",
                    "Remote IP", "Remote Port", "Local IP", "Local Port",
                    "PID", "Process", "Evidence Summary", "Subtype"
                ])
                for alert in alerts_data:
                    ev = alert.get("evidence", {})
                    evidence_summary = (ev.get("line_raw", "")[:100] + "...") if len(ev.get("line_raw", "")) > 100 else ev.get("line_raw", "")
                    writer.writerow([
                        alert.get("timestamp", ""),
                        alert.get("severity", "unknown"),
                        alert.get("level", ""),
                        alert.get("type", ""),
                        alert.get("message", ""),
                        ev.get("remote_ip", ""),
                        ev.get("remote_port", ""),
                        ev.get("local_ip", ""),
                        ev.get("local_port", ""),
                        ev.get("pid", ""),
                        ev.get("process", ""),
                        evidence_summary,
                        alert.get("subtype", "")
                    ])
        else:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(alerts_data, f, indent=2)
        messagebox.showinfo("✅ Export Complete", f"{title} exported successfully:\n{file_path}")
        log("INFO", f"{title} exported to {file_path}")