# process_connection_monitor.py
# Author: Andrus Kurvits
# Contact: andrusq@gmail.com
# GitHub: https://github.com/andrusq
# Year: 2025

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import psutil
import threading
import time
import queue
import requests
from datetime import datetime
import json
import configparser
import os
import re # Added for parsing PID
import logging # Added for file logging
import ipaddress # Added for IP sorting
import socket # Added for address family constants (AF_INET)

# Constants
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
IP_API_URL = "http://ip-api.com/json/{ip}"
CONFIG_FILE = "config.ini"
# Rate Limiting for VirusTotal API
VT_RATE_LIMIT_COUNT = 4 # Allowed requests per window
VT_RATE_LIMIT_WINDOW = 60 # Time window in seconds
VT_API_CALL_BUFFER = 0.1 # Small buffer to add to wait time
VT_MAX_UNIQUE_LOOKUPS_PER_SESSION = 50 # Limit unique VT lookups per session

class ConnectionMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Connection Monitor")
        self.root.minsize(600, 450)

        # Menu Bar
        menubar = tk.Menu(root)
        root.config(menu=menubar)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)
        # --- End Menu Bar --- # Removed this type of separator

        self.monitoring_thread = None
        self.stop_event = threading.Event()
        self.results_queue = queue.Queue() # For GUI updates (results, snapshots, messages)
        self.lookup_queue = queue.Queue()  # For IPs needing Geo/VT lookups
        self.process_list = []
        self.ip_geo_cache = {}
        self.vt_results_cache = {}
        self.vt_api_key = tk.StringVar()
        self.vt_enabled = tk.BooleanVar(value=False)
        self.scan_interval_var = tk.DoubleVar(value=1.0)
        self.show_only_active_var = tk.BooleanVar(value=True)

        # Rate Limiting State
        self.vt_call_timestamps = [] # List to store timestamps of recent VT API calls
        self.vt_unique_lookups_this_session = 0 # Counter for unique lookups

        # Data for Display
        self.current_display_data = {} # Stores { "ip:port": { details } }

        # Lookup Tracking
        self.pending_lookup_keys = set() # Stores ip:port keys currently in lookup_queue or being processed

        # Timer Variables
        self.monitoring_start_time = None
        self.timer_after_id = None

        self._load_config()

        # Configure Logging
        log_file = "connection_monitor.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=log_file,
            filemode='a' # Append to the log file
        )

        style = ttk.Style()
        style.theme_use('vista')

        # Control Frame
        control_frame = ttk.Frame(root, padding="10")
        control_frame.pack(fill=tk.X, side=tk.TOP)

        # Process selection frame
        self.process_frame = ttk.Frame(control_frame)
        self.process_frame.grid(row=0, column=0, columnspan=3, sticky=tk.EW)
        ttk.Label(self.process_frame, text="Process (Network Active):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.process_combobox = ttk.Combobox(self.process_frame, width=45, state="readonly")
        self.process_combobox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.refresh_button = ttk.Button(self.process_frame, text="Refresh List", command=self.refresh_processes)
        self.refresh_button.grid(row=0, column=2, padx=5, pady=5)
        self.process_frame.columnconfigure(1, weight=1)

        # Process Filter Checkbox
        self.show_active_check = ttk.Checkbutton(
            control_frame,
            text="Show only processes with active connections",
            variable=self.show_only_active_var,
            command=self.refresh_processes # Update list when toggled
        )
        self.show_active_check.grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=(0,5))

        # Start/Stop buttons frame
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W)
        self.start_button = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_button = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        # VirusTotal frame
        self.vt_frame = ttk.LabelFrame(control_frame, text="VirusTotal Check", padding="5")
        self.vt_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=(10, 5), sticky=tk.EW)
        self.vt_enable_check = ttk.Checkbutton(self.vt_frame, text="Enable VT Check", variable=self.vt_enabled, command=self.toggle_vt_key_entry)
        self.vt_enable_check.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        ttk.Label(self.vt_frame, text="API Key:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.vt_api_key_entry = ttk.Entry(self.vt_frame, textvariable=self.vt_api_key, width=40, state=tk.DISABLED, show='*')
        self.vt_api_key_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.show_key_var = tk.BooleanVar(value=False)
        self.show_key_check = ttk.Checkbutton(self.vt_frame, text="Show Key", variable=self.show_key_var, command=self._toggle_api_key_visibility, state=tk.DISABLED)
        self.show_key_check.grid(row=1, column=2, padx=(5, 0), pady=5, sticky=tk.W)
        self.vt_frame.columnconfigure(1, weight=1)

        # Scan Interval Frame
        interval_frame = ttk.Frame(control_frame)
        interval_frame.grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=5, pady=(0, 5))
        ttk.Label(interval_frame, text="Scan Interval (s):").pack(side=tk.LEFT, padx=5)
        self.interval_spinbox = ttk.Spinbox(
            interval_frame,
            from_=0.1,
            to=60.0,
            increment=0.1,
            textvariable=self.scan_interval_var,
            width=6,
            format="%.1f" # Format to one decimal place
        )
        self.interval_spinbox.pack(side=tk.LEFT)

        control_frame.columnconfigure(1, weight=1)

        # Results Frame
        results_frame = ttk.Frame(root, padding="0 10 10 10")
        results_frame.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM)

        self.results_title_var = tk.StringVar(value="Established Connections:")
        ttk.Label(results_frame, textvariable=self.results_title_var).pack(anchor=tk.W, pady=(0, 5))
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, wrap=tk.WORD, state=tk.DISABLED)
        self.results_text.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar()
        self.status_var.set("Idle. Select process and click Start.")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding="2 5")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.populate_process_list()
        self.check_queue()

        # Keyboard Bindings
        self.root.bind('<Return>', self._handle_start_keys)
        self.root.bind('<space>', self._handle_start_keys)
        self.root.bind('<Escape>', self._handle_stop_key)

    def _handle_start_keys(self, event=None):
        """Handle Enter/Space key press to start monitoring if possible."""
        if self.start_button['state'] == tk.NORMAL:
            logging.debug("Start monitoring triggered by keyboard.")
            self.start_monitoring()

    def _handle_stop_key(self, event=None):
        """Handle Escape key press to stop monitoring if possible."""
        if self.stop_button['state'] == tk.NORMAL:
            logging.debug("Stop monitoring triggered by keyboard.")
            self.stop_monitoring()

    def _show_about(self):
        """Displays the About information box."""
        # Using 2025 as requested.
        messagebox.showinfo(
            "About Process Connection Monitor",
            f"Process Connection Monitor v3\n\n"
            f"Author: Andrus Kurvits\n"
            f"Contact: andrusq@gmail.com\n"
            f"https://github.com/andrusq\n"
            f"Year: 2025"
        )

    def toggle_vt_key_entry(self):
        """Enable/disable API key entry AND show key checkbox based on VT enable checkbox."""
        if self.vt_enabled.get():
            self.vt_api_key_entry.config(state=tk.NORMAL)
            self.show_key_check.config(state=tk.NORMAL)
        else:
            self.vt_api_key_entry.config(state=tk.DISABLED)
            self.show_key_check.config(state=tk.DISABLED)

    def populate_process_list(self):
        """Gets processes with active network connections and updates the combobox."""
        self.status_var.set("Refreshing process list...")
        self.root.update_idletasks()

        self.process_list = []
        active_pids = set()

        try:
            # 1. Get all established INET connections and their PIDs
            all_conns = psutil.net_connections(kind='inet')
            for conn in all_conns:
                # If checkbox is ticked, only include PIDs with established connections.
                # Otherwise, include PIDs associated with *any* INET connection.
                if conn.pid:
                    if self.show_only_active_var.get():
                        if conn.status == psutil.CONN_ESTABLISHED:
                            active_pids.add(conn.pid)
                    else:
                        active_pids.add(conn.pid)

            # 2. Get all processes and filter by the active PIDs
            active_processes = {}
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['pid'] in active_pids:
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        if pid and name: # Ensure valid info
                            active_processes[pid] = name
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        # Process might have ended or we lack permissions
                        continue

            # 3. Format list as "name (PID: pid)" and sort
            self.process_list = [
                f"{name} (PID: {pid})" for pid, name in active_processes.items()
            ]
            self.process_list.sort(key=str.lower)

            self.process_combobox['values'] = self.process_list
            if self.process_list:
                self.process_combobox.current(0)
                self.status_var.set(f"{len(self.process_list)} network-active processes found. Select and click Start.")
            else:
                self.process_combobox.set("")
                self.status_var.set("No network-active processes found. Click Refresh List to try again.")

        except psutil.AccessDenied:
            self.status_var.set("Error: Access denied fetching network connections.")
            messagebox.showerror("Permissions Error", "Could not fetch network connections due to insufficient permissions. Try running as administrator.")
            self.process_combobox['values'] = []
            self.process_combobox.set("")
        except Exception as e:
            self.status_var.set(f"Error fetching process list: {type(e).__name__}")
            messagebox.showerror("Error", f"Could not fetch process list:\n{e}")
            self.process_combobox['values'] = []
            self.process_combobox.set("")

    def refresh_processes(self):
        self.populate_process_list()

    def get_ip_info(self, ip):
        """Fetches GeoIP info from ip-api.com, using cache if available."""
        if ip in self.ip_geo_cache:
            return self.ip_geo_cache[ip]
        try:
            resp = requests.get(IP_API_URL.format(ip=ip), timeout=2)
            resp.raise_for_status()
            data = resp.json()
            if data.get('status') == 'success':
                geo_info = f"{data.get('country', 'N/A')}, {data.get('city', 'N/A')}"
                self.ip_geo_cache[ip] = geo_info
                return geo_info
            else:
                fail_reason = data.get('message', 'Failed')
                self.ip_geo_cache[ip] = f"Geo: {fail_reason}"
                return f"Geo: {fail_reason}"
        except requests.exceptions.Timeout:
            self.ip_geo_cache[ip] = "Geo: Timeout"
            return "Geo: Timeout"
        except requests.exceptions.ConnectionError:
            self.ip_geo_cache[ip] = "Geo: Conn Error"
            return "Geo: Conn Error"
        except requests.exceptions.RequestException as e:
            error_msg = f"Geo: HTTP {e.response.status_code}" if e.response else f"Geo: Req Error ({type(e).__name__})"
            logging.error(f"Geo lookup error for {ip}: {e}", exc_info=True)
            self.ip_geo_cache[ip] = error_msg
            return error_msg
        except Exception as e:
            logging.error(f"Unexpected Geo lookup error for {ip}: {e}", exc_info=True)
            self.ip_geo_cache[ip] = f"Geo: Error ({type(e).__name__})"
            return f"Geo: Error ({type(e).__name__})"

    def get_vt_info(self, ip, vt_enabled, api_key):
        """Gets VirusTotal info for an IP. Handles unique lookup limit and caching."""
        if not vt_enabled:
            return "VT: Disabled"
        if not api_key:
            return "VT: No Key"
        if ip in self.vt_results_cache:
            return self.vt_results_cache[ip]

        # Unique Lookup Limit Check (Frequency limit handled in worker thread)
        if self.vt_unique_lookups_this_session >= VT_MAX_UNIQUE_LOOKUPS_PER_SESSION:
            return "VT: Lookup Limit"

        headers = {"x-apikey": api_key}
        try:
            resp = requests.get(VT_API_URL.format(ip=ip), headers=headers, timeout=5)

            # Handle specific known status codes
            if resp.status_code == 429:
                self.vt_results_cache[ip] = "VT: Rate Limit Hit"
                return "VT: Rate Limit Hit"
            if resp.status_code == 401:
                self.vt_results_cache[ip] = "VT: Invalid Key"
                return "VT: Invalid Key"
            if resp.status_code == 403:
                self.vt_results_cache[ip] = "VT: Forbidden"
                return "VT: Forbidden"

            resp.raise_for_status() # Check for other HTTP errors
            data = resp.json()

            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious = last_analysis_stats.get('malicious', 0)
            total = sum(last_analysis_stats.values())
            result = f"VT: {malicious}/{total} malicious"
            self.vt_results_cache[ip] = result
            return result

        except requests.exceptions.Timeout:
            self.vt_results_cache[ip] = "VT: Timeout"
            return "VT: Timeout"
        except requests.exceptions.ConnectionError:
            self.vt_results_cache[ip] = "VT: Conn Error"
            return "VT: Conn Error"
        except requests.exceptions.HTTPError as e:
            error_msg = f"VT: HTTP {e.response.status_code}"
            logging.error(f"VT lookup HTTP error for {ip}: {e}", exc_info=True)
            self.vt_results_cache[ip] = error_msg
            return error_msg
        except requests.exceptions.RequestException as e:
            error_msg = f"VT: Req Error ({type(e).__name__})"
            logging.error(f"VT lookup request error for {ip}: {e}", exc_info=True)
            self.vt_results_cache[ip] = error_msg
            return error_msg
        except json.JSONDecodeError as e:
            logging.error(f"VT JSON Decode Error for {ip}: {e}", exc_info=True)
            self.vt_results_cache[ip] = "VT: Invalid Resp"
            return "VT: Invalid Resp"
        except Exception as e:
            logging.error(f"Unexpected VT lookup error for {ip}: {e}", exc_info=True)
            self.vt_results_cache[ip] = f"VT: Error ({type(e).__name__})"
            return f"VT: Error ({type(e).__name__})"

    def _parse_pid_from_selection(self, selection_str):
        """Extracts PID from strings like 'name (PID: 123)'."""
        match = re.search(r'\(PID:\s*(\d+)\)$', selection_str)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None

    def monitor_loop_single(self, process_pid, vt_enabled, api_key, scan_interval_sec):
        """Monitors a single process, puts lookup tasks and snapshots on queues."""
        process_name = "Unknown"
        try:
            process_name = psutil.Process(process_pid).name()
        except psutil.NoSuchProcess:
            self.results_queue.put(f"Initial Check Error: Process PID {process_pid} not found.")
            self.results_queue.put(None) # Signal stop
            return
        except psutil.AccessDenied:
             self.results_queue.put(f"Initial Check Error: Access denied for PID {process_pid}.")
             self.results_queue.put(None)
             return
        except Exception as e:
             self.results_queue.put(f"Initial Check Error for PID {process_pid}: {e}")
             self.results_queue.put(None)
             return

        logging.debug(f"Monitoring thread started for {process_name} (PID: {process_pid}) with interval {scan_interval_sec}s")
        last_conn_keys = set()
        snapshot_interval = 5 # How often (in seconds) to send a snapshot
        last_snapshot_time = time.time()

        while not self.stop_event.is_set():
            current_conn_keys = set()
            try:
                p = psutil.Process(process_pid)
                conns = p.net_connections(kind='inet')
                for conn in conns:
                    # Filter for established IPv4 connections with a remote address
                    if conn.family == socket.AF_INET and \
                       conn.status == psutil.CONN_ESTABLISHED and \
                       hasattr(conn, 'raddr') and conn.raddr:
                        ip = conn.raddr.ip
                        port = conn.raddr.port
                        conn_key = f"{ip}:{port}"
                        current_conn_keys.add(conn_key)

                        # If this is a new connection not already pending lookup, queue it
                        if conn_key not in last_conn_keys and conn_key not in self.pending_lookup_keys:
                            logging.debug(f"New unique connection found: {conn_key}. Queuing for lookup.")
                            self.pending_lookup_keys.add(conn_key)
                            self.lookup_queue.put((ip, port, vt_enabled, api_key))
                            # Put placeholder data immediately onto results queue for quicker display
                            placeholder_data = {
                                'ip': ip,
                                'port': port,
                                'geo': '(Pending...)',
                                'vt': '(Pending...)'
                            }
                            self.results_queue.put(placeholder_data)

                # Send snapshot of current connections periodically or if changes detected
                now = time.time()
                if now - last_snapshot_time > snapshot_interval or current_conn_keys != last_conn_keys:
                    self.results_queue.put(('snapshot', current_conn_keys.copy()))
                    last_snapshot_time = now

                last_conn_keys = current_conn_keys.copy()

            except psutil.NoSuchProcess:
                self.results_queue.put(f"Monitored process '{process_name}' (PID: {process_pid}) ended.")
                break
            except psutil.AccessDenied:
                self.results_queue.put(f"Access denied querying connections for process '{process_name}'. Stopping monitor.")
                break
            except Exception as e:
                self.results_queue.put(f"Error getting connections for '{process_name}': {e}. Stopping monitor.")
                break

            time.sleep(scan_interval_sec)

        # Signal end to GUI
        self.results_queue.put(None)
        logging.debug(f"Monitoring thread stopped for {process_name} (PID: {process_pid})")

    def start_monitoring(self):
        """Starts monitoring the SINGLE process selected (by PID)."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.status_var.set("Already running. Stop first.")
            return

        selected_process_str = self.process_combobox.get().strip()
        if not selected_process_str:
            messagebox.showerror("Error", "Please select a process from the list or refresh.")
            return

        target_pid = self._parse_pid_from_selection(selected_process_str)
        if target_pid is None:
             messagebox.showerror("Error", f"Could not extract PID from selection: '{selected_process_str}'")
             return

        # Reset session state
        self.vt_unique_lookups_this_session = 0
        self.current_display_data.clear()
        self.pending_lookup_keys.clear()

        try:
            process_name = psutil.Process(target_pid).name()
        except psutil.NoSuchProcess:
             messagebox.showerror("Error", f"Process with PID {target_pid} seems to have ended already.")
             return
        except psutil.AccessDenied:
             process_name = f"PID: {target_pid}" # Fallback if name access denied

        if self.vt_enabled.get() and not self.vt_api_key.get().strip():
            messagebox.showerror("Error", "VirusTotal check is enabled, but the API key is missing.")
            return

        # Validate Scan Interval
        try:
            scan_interval = self.scan_interval_var.get()
            if scan_interval <= 0:
                messagebox.showerror("Error", "Scan interval must be greater than 0 seconds.")
                return
        except tk.TclError:
            messagebox.showerror("Error", "Invalid scan interval value. Please enter a number.")
            return

        logging.info(f"----- Monitoring Session Started for Process: {process_name} (PID: {target_pid}) -----")

        # Update UI for monitoring start
        self.results_title_var.set(f"Connections for '{process_name} (PID: {target_pid})':")
        self.status_var.set(f"Monitoring '{process_name} (PID: {target_pid})'...")
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete('1.0', tk.END)

        # --- Set up initial display text and mark ---
        # Insert static header lines
        self.results_text.insert(tk.END, f"Started monitoring '{process_name} (PID: {target_pid})'...\n\n")
        vt_status = "Enabled" if self.vt_enabled.get() else "Disabled"
        self.results_text.insert(tk.END, f"VirusTotal checks: {vt_status}\n\n")
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.results_text.insert(tk.END, f"[{timestamp}] Performing initial connection check...\n\n")

        # Place the mark *after* the static header content
        self.results_text.mark_set("dynamic_start_mark", tk.END)
        self.results_text.mark_gravity("dynamic_start_mark", tk.LEFT)
        # Add a newline *after* the mark's intended position for the dynamic content
        self.results_text.insert(tk.END, '\n')
        # --- End initial display setup ---

        self.results_text.see(tk.END)

        # Start elapsed time timer
        self.monitoring_start_time = time.time()
        self._update_timer()

        vt_is_enabled = self.vt_enabled.get()
        vt_key = self.vt_api_key.get().strip()
        interval_sec = scan_interval

        # Reset queues
        self.lookup_queue = queue.Queue()
        self.results_queue = queue.Queue()

        # Start Monitor Thread
        self.stop_event.clear()
        self.monitoring_thread = threading.Thread(
            target=self.monitor_loop_single,
            args=(target_pid, vt_is_enabled, vt_key, interval_sec),
            daemon=True,
            name="MonitorThread"
        )
        self.monitoring_thread.start()

        # Start Lookup Worker Thread
        self.lookup_worker_thread = threading.Thread(
            target=self._lookup_worker,
            daemon=True,
            name="LookupWorkerThread"
        )
        self.lookup_worker_thread.start()

        self._set_ui_state('running')

    def stop_monitoring(self):
        """Stops the monitoring threads."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.status_var.set("Stopping...")
            self.stop_event.set()
        else:
            self.status_var.set("Not currently running.")
        # UI state reset is handled by check_queue when it receives the stop signal

    def _set_ui_state(self, state):
         """Configures UI element states based on whether monitoring is active."""
         if state == 'running':
             self.start_button.config(state=tk.DISABLED)
             self.stop_button.config(state=tk.NORMAL)
             self.process_combobox.config(state=tk.DISABLED)
             self.refresh_button.config(state=tk.DISABLED)
             self.vt_enable_check.config(state=tk.DISABLED)
             self.vt_api_key_entry.config(state=tk.DISABLED)
             self.show_key_check.config(state=tk.DISABLED)
             self.interval_spinbox.config(state=tk.DISABLED)

         elif state == 'idle':
             self.start_button.config(state=tk.NORMAL)
             self.stop_button.config(state=tk.DISABLED)
             self.process_combobox.config(state='readonly')
             self.refresh_button.config(state=tk.NORMAL)
             self.vt_enable_check.config(state=tk.NORMAL)
             self.toggle_vt_key_entry() # Handles API key/show key state
             self.interval_spinbox.config(state=tk.NORMAL)

    def check_queue(self):
        """Processes messages from the results_queue (GUI thread)."""
        display_needs_update = False
        try:
            while True: # Process all available items
                result = self.results_queue.get_nowait()

                if result is None: # Monitoring stopped signal
                    self.status_var.set("Stopped.")
                    self._set_ui_state('idle')
                    self.monitoring_thread = None
                    self.lookup_worker_thread = None
                    if self.timer_after_id: # Stop elapsed time timer
                         self.root.after_cancel(self.timer_after_id)
                         self.timer_after_id = None
                         self.monitoring_start_time = None
                    # Don't process further items in this check loop after stop signal
                    break

                elif isinstance(result, dict): # Lookup result from worker
                    conn_key = f"{result['ip']}:{result['port']}"
                    # Update display data if new or changed
                    if conn_key not in self.current_display_data or self.current_display_data[conn_key] != result:
                        self.current_display_data[conn_key] = result
                        display_needs_update = True

                elif isinstance(result, tuple) and len(result) == 2 and result[0] == 'snapshot':
                    # Snapshot of currently active connection keys
                    active_keys = result[1]
                    stale_keys = set(self.current_display_data.keys()) - active_keys
                    if stale_keys:
                        for key in stale_keys:
                            del self.current_display_data[key]
                        display_needs_update = True

                elif isinstance(result, tuple) and len(result) == 2 and result[0] == 'lookup_complete':
                    # Lookup finished message from worker
                    conn_key = result[1]
                    self.pending_lookup_keys.discard(conn_key) # Mark lookup as no longer pending

                elif isinstance(result, str): # Status/Error Message
                    self.results_text.config(state=tk.NORMAL)
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    # Insert message at the very end, ensuring it's below dynamic list
                    self.results_text.insert(tk.END, f"\n[{timestamp}] {result}\n")
                    self.results_text.see(tk.END)
                    self.results_text.config(state=tk.DISABLED)
                    # Update status bar for important messages
                    if "ended" in result or "Error" in result or "Access denied" in result:
                         self.status_var.set(result[:100]) # Show first part in status

                self.results_queue.task_done()

        except queue.Empty:
            pass # No more items for now

        # Update display if data changed
        if display_needs_update:
            self.update_results_display(self.current_display_data)

        # Schedule the next check
        self.root.after(100, self.check_queue)

    def update_results_display(self, display_data):
        """Updates the results text area, clearing old dynamic content using the mark."""
        self.results_text.config(state=tk.NORMAL)

        # --- Mark-based Clearing ---
        delete_start_index = self.results_text.index("dynamic_start_mark")
        if delete_start_index:
            # Delete from the mark position to the end of the text widget
            self.results_text.delete(delete_start_index, tk.END)
        else:
            # Fallback if mark somehow lost
            logging.error("Display mark 'dynamic_start_mark' not found! Clearing estimated area.")
            self.results_text.delete("7.0", tk.END) # Estimate where dynamic content started
            delete_start_index = "7.0"
        # --- End Mark-based Clearing ---

        # Insert new content starting *at* the mark's position (or fallback)
        insert_pos = delete_start_index

        # Insert dynamic header
        timestamp = datetime.now().strftime('%H:%M:%S')
        separator = "-" * 30
        header = f"\n[{timestamp}] Connection Details ({len(display_data)}):\n{separator}\n"
        self.results_text.insert(insert_pos, header)
        # Calculate the index *after* the header for inserting the list
        insert_pos = self.results_text.index(f"{insert_pos}+{len(header)}c")

        if display_data:
            # --- Sort Key for IPs (handles IPv4 & IPv6) ---
            def sort_key(ip_port_str):
                try:
                    ip_str, port_str = ip_port_str.rsplit(':', 1) # Split from right for IPv6
                    ip_obj = ipaddress.ip_address(ip_str)
                    port_part = int(port_str)
                    # Sort by version (IPv4 first), then IP address, then port
                    return (ip_obj.version, ip_obj, port_part)
                except (ValueError, TypeError) as e:
                    logging.warning(f"Could not parse sort key '{ip_port_str}': {e}")
                    return (float('inf'), ip_port_str) # Sort invalid keys last
            # --- End Sort Key ---

            sorted_keys = sorted(display_data.keys(), key=sort_key)
            list_content = "".join([ # Use join for efficiency
                f"- {display_data[key]['ip']}:{display_data[key]['port']} - {display_data[key]['geo']} - {display_data[key]['vt']}\n"
                for key in sorted_keys
            ])
            self.results_text.insert(insert_pos, list_content)
        else:
            self.results_text.insert(insert_pos, "(No established connections found)\n")

        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)

    def on_closing(self):
        """Handles application close: saves config, stops threads, destroys window."""
        print("Closing application...")
        self._save_config()
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            print("Signalling monitoring threads to stop...")
            self.stop_monitoring() # This sets the stop_event
            # Daemons threads will exit automatically when main thread finishes

        # Cancel timer explicitly if still scheduled (might be stopped by check_queue already)
        if self.timer_after_id:
            self.root.after_cancel(self.timer_after_id)
            self.timer_after_id = None

        print("Destroying root window.")
        self.root.destroy()

    # Config Load/Save
    def _load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            try:
                config.read(CONFIG_FILE)
                api_key = config.get('VirusTotal', 'api_key', fallback='')
                self.vt_api_key.set(api_key)
                # Could load enabled state here if desired
            except configparser.Error as e:
                logging.error(f"Error loading config file '{CONFIG_FILE}': {e}")
                messagebox.showwarning("Config Error", f"Could not load configuration:\n{e}")
            except Exception as e:
                logging.error(f"Unexpected error loading config: {e}", exc_info=True)
                messagebox.showwarning("Config Error", f"An unexpected error occurred loading configuration:\n{e}")
        # else: No need to log if file just doesn't exist yet

    def _save_config(self):
        config = configparser.ConfigParser()
        config['VirusTotal'] = {
            'api_key': self.vt_api_key.get().strip(),
            # Could save enabled state here if desired
        }
        try:
            with open(CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            logging.info(f"Configuration saved to '{CONFIG_FILE}'")
        except IOError as e:
            logging.error(f"Error saving config file '{CONFIG_FILE}': {e}")
            messagebox.showerror("Config Error", f"Could not save configuration to '{CONFIG_FILE}':\n{e}")
        except Exception as e:
            logging.error(f"Unexpected error saving config: {e}", exc_info=True)
            messagebox.showerror("Config Error", f"An unexpected error occurred saving configuration:\n{e}")

    # Timer Update
    def _update_timer(self):
        """Updates the elapsed time display in the status bar."""
        if self.monitoring_start_time is None or self.stop_event.is_set():
            return # Stop updating if monitoring stopped or not started

        elapsed_seconds = int(time.time() - self.monitoring_start_time)
        hours, remainder = divmod(elapsed_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{hours:02}:{minutes:02}:{seconds:02}"

        current_status = self.status_var.get()
        # Update status only if it still contains "Monitoring"
        base_status_match = re.match(r"^(Monitoring '.*?\(PID: \d+\)').*$", current_status)
        if base_status_match:
            base_status = base_status_match.group(1)
            self.status_var.set(f"{base_status} ({time_str})")

        # Reschedule
        self.timer_after_id = self.root.after(1000, self._update_timer)

    def _toggle_api_key_visibility(self):
        """Toggles the visibility of the API key in the entry field."""
        if self.show_key_var.get():
            self.vt_api_key_entry.config(show='')
        else:
            self.vt_api_key_entry.config(show='*')

    # Worker Thread for Lookups
    def _lookup_worker(self):
        """Worker thread to perform GeoIP and VT lookups, handling rate limits."""
        logging.info("Lookup worker thread started.")
        while not self.stop_event.is_set():
            try:
                ip, port, vt_enabled, api_key = self.lookup_queue.get(timeout=1)
                conn_key = f"{ip}:{port}"
                result_data = None # Ensure defined

                # --- Check Caches First ---
                geo_cached = self.ip_geo_cache.get(ip)
                vt_cached = self.vt_results_cache.get(ip)
                fully_cached = False
                geo, vt_info = None, None # Ensure defined

                if not vt_enabled:
                    if geo_cached is not None:
                        fully_cached = True
                        geo, vt_info = geo_cached, "VT: Disabled"
                elif geo_cached is not None and vt_cached is not None:
                    fully_cached = True
                    geo, vt_info = geo_cached, vt_cached

                if fully_cached:
                    logging.debug(f"Worker cache hit for {ip}. Skipping lookup.")
                    result_data = {'ip': ip, 'port': port, 'geo': geo, 'vt': vt_info}
                    self.results_queue.put(result_data)
                    self.results_queue.put(('lookup_complete', conn_key)) # Signal completion
                    self.lookup_queue.task_done()
                    continue # Process next item
                # --- End Cache Check ---

                # Perform lookups if not fully cached
                geo = self.get_ip_info(ip) # Uses cache internally if available

                # --- VirusTotal Lookup with Frequency Rate Limiting ---
                vt_info = "VT: Skipped"
                if vt_enabled:
                    # Check unique session limit first
                    if self.vt_unique_lookups_this_session < VT_MAX_UNIQUE_LOOKUPS_PER_SESSION:

                        # Check frequency limit
                        now = time.time()
                        # Remove timestamps older than the window
                        self.vt_call_timestamps = [ts for ts in self.vt_call_timestamps if now - ts < VT_RATE_LIMIT_WINDOW]
                        if len(self.vt_call_timestamps) >= VT_RATE_LIMIT_COUNT:
                            # Limit reached, calculate wait time
                            time_since_oldest = now - self.vt_call_timestamps[0]
                            wait_time = VT_RATE_LIMIT_WINDOW - time_since_oldest + VT_API_CALL_BUFFER
                            logging.warning(f"VT Rate Limit (Frequency): Worker waiting {wait_time:.2f}s for {ip}")
                            # Wait, checking stop event periodically
                            wait_end = time.time() + wait_time
                            while time.time() < wait_end:
                                if self.stop_event.is_set():
                                    logging.info("Lookup worker stopping during rate limit wait.")
                                    return # Exit thread immediately
                                time.sleep(0.1)
                            # Update timestamps again after waiting before proceeding
                            now = time.time()
                            self.vt_call_timestamps = [ts for ts in self.vt_call_timestamps if now - ts < VT_RATE_LIMIT_WINDOW]

                        # Proceed with potential lookup
                        self.vt_unique_lookups_this_session += 1
                        logging.debug(f"Worker VT Lookup #{self.vt_unique_lookups_this_session} for {ip}")
                        self.vt_call_timestamps.append(time.time()) # Record call time
                        vt_info = self.get_vt_info(ip, vt_enabled, api_key) # Calls function which checks cache/unique limit again

                    else:
                        vt_info = "VT: Lookup Limit" # Unique session limit reached
                else:
                    vt_info = "VT: Disabled"
                # --- End VirusTotal Lookup ---

                # Prepare and queue the final result data
                result_data = {'ip': ip, 'port': port, 'geo': geo, 'vt': vt_info}
                self.results_queue.put(result_data)
                self.lookup_queue.task_done()
                self.results_queue.put(('lookup_complete', conn_key)) # Signal completion

                # Log the result after processing
                log_message = (
                    f"Checked IP: {result_data['ip']}, Port: {result_data['port']}, "
                    f"Geo: {result_data['geo']}, {result_data['vt']}"
                )
                logging.info(log_message)

            except queue.Empty:
                continue # Timeout, check stop_event and loop
            except Exception as e:
                logging.error(f"Error in lookup worker: {e}", exc_info=True)
                # Ensure task is marked done even on error to prevent hanging
                try: self.lookup_queue.task_done()
                except ValueError: pass # Might already be done or queue empty
                # Signal completion to potentially unblock monitor thread
                if 'conn_key' in locals():
                    self.results_queue.put(('lookup_complete', conn_key))

        logging.info("Lookup worker thread finished.")

if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        print("Error: psutil is not installed. Please run 'pip install psutil'")
        exit(1)

    try:
        import requests
    except ImportError:
        print("Error: requests is not installed. Please run 'pip install requests'")
        exit(1)

    root = tk.Tk()
    app = ConnectionMonitorApp(root)
    root.mainloop()
