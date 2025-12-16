#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
One-Click Port Killer Tool - English Version
"""
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os
import ctypes


def is_admin():
    """Check if the program has administrator privileges"""
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def find_process_using_port(port):
    """Find process using the specified port"""
    try:
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        lines = result.stdout.split('\n')

        for line in lines:
            if f':{port}' in line and 'LISTENING' in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    return parts[-1]
        return None
    except:
        return None


def kill_process_by_pid(pid):
    """Kill process by PID"""
    try:
        result = subprocess.run(['taskkill', '/PID', pid, '/F'],
                              capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False


def get_all_used_ports():
    """Get all used ports"""
    used_ports = []
    try:
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        lines = result.stdout.split('\n')

        for line in lines:
            if 'LISTENING' in line and 'TCP' in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    local_address = parts[1]
                    if ':' in local_address:
                        port_str = local_address.split(':')[-1]
                        if ']' in port_str:
                            port_str = port_str.split(']')[-1]
                        if port_str.isdigit():
                            port = int(port_str)
                            pid = parts[-1]
                            used_ports.append((port, pid))

        # Remove duplicates and sort by port number
        unique_ports = {}
        for port, pid in used_ports:
            if port not in unique_ports:
                unique_ports[port] = pid

        sorted_ports = sorted(unique_ports.items())
        return sorted_ports

    except:
        return []


def get_port_description(port):
    """Get common service description based on port number"""
    common_ports = {
    # Basic network protocols
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH (Secure Shell)",
    23: "Telnet (Remote Terminal Protocol)",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    67: "DHCP Server (Bootstrap Protocol Server)",
    68: "DHCP Client (Bootstrap Protocol Client)",
    69: "TFTP (Trivial File Transfer Protocol)",
    80: "HTTP (Hypertext Transfer Protocol)",
    110: "POP3 (Post Office Protocol version 3)",
    119: "NNTP (Network News Transfer Protocol)",
    123: "NTP (Network Time Protocol)",
    143: "IMAP (Internet Message Access Protocol)",
    161: "SNMP (Simple Network Management Protocol)",
    162: "SNMP Trap (Simple Network Management Protocol Trap)",
    443: "HTTPS (HTTP Secure)",
    465: "SMTPS (SMTP Secure)",
    587: "SMTP Submission (Mail Submission Agent)",
    993: "IMAPS (IMAP Secure)",
    995: "POP3S (POP3 Secure)",

    # Database services
    1433: "SQL Server (Microsoft Database)",
    1434: "SQL Server Browser (SQL Server Browser Service)",
    1521: "Oracle (Oracle Database)",
    1526: "Oracle XE (Oracle Express Edition)",
    3306: "MySQL (Relational Database)",
    3307: "MySQL Alternate Port",
    3389: "Remote Desktop (RDP, Windows Remote Desktop Protocol)",
    5432: "PostgreSQL (Open Source Relational Database)",
    5433: "PostgreSQL Alternate Port",
    6379: "Redis (Key-Value Database)",
    6380: "Redis Cluster/Encryption Port",
    27017: "MongoDB (Document Database)",
    27018: "MongoDB Replica Set Port",
    27019: "MongoDB Config Server Port",
    9042: "Cassandra (Distributed Database)",
    28017: "MongoDB HTTP Management Port",
    11211: "Memcached (Distributed Cache)",
    11212: "Memcached Alternate Port",
    8086: "InfluxDB (Time Series Database)",
    50000: "DB2 (IBM Database)",

    # Web/Development common
    8080: "HTTP Proxy/Alternate HTTP Port",
    8000: "Development Server (Python/Flask etc)",
    8443: "HTTPS-alt (Alternate HTTPS Port)",
    9000: "Development Server (PHP-FPM/Node.js etc)",
    3000: "Node.js Dev Server/React Development",
    5000: "Flask Dev Server/HTTP Alternate Port",
    7000: "Frontend Development Proxy Port",
    9200: "Elasticsearch (Search Engine HTTP Port)",
    9300: "Elasticsearch (Cluster Communication Port)",
    5601: "Kibana (Elasticsearch Visualization)",
    8888: "Jupyter Notebook/Development Debug Port",
    4200: "Angular Development Server",
    8181: "REST API Service Port",

    # Network services/Remote access
    5900: "VNC (Virtual Network Computing)",
    5901: "VNC Alternate Port",
    2049: "NFS (Network File System)",
    137: "NetBIOS (Network Basic Input/Output System)",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service (SMB)",
    445: "SMB (Server Message Block)/Windows File Sharing",
    636: "LDAPS (LDAP Secure)",
    389: "LDAP (Lightweight Directory Access Protocol)",
    514: "Syslog (System Logging)",
    515: "LPD (Line Printer Daemon)",
    6000: "X11 (Unix Graphics Interface)",

    # Cloud/Container/DevOps
    2375: "Docker HTTP (Unencrypted)",
    2376: "Docker HTTPS (Encrypted)",
    2379: "ETCD (Distributed Key-Value Store)",
    2380: "ETCD Cluster Communication",
    6443: "Kubernetes API Server",
    10250: "Kubernetes Kubelet",
    10251: "Kubernetes Controller Manager",
    10252: "Kubernetes Scheduler",
    8472: "Flannel (K8s Networking)",
    3128: "Squid Proxy Server",
    1080: "SOCKS Proxy",

    # Other common services
    3801: "Radmin (Remote Administration Tool)",
    5060: "SIP (Session Initiation Protocol, VoIP)",
    5061: "SIPS (Secure SIP)",
    873: "Rsync (File Synchronization Tool)",
    9987: "TS3 Server (Teamspeak Voice Server)",
    25565: "Minecraft (Game Server)",
    1900: "UPnP (Universal Plug and Play)",
    49152: "Dynamic Port Start (Ephemeral Port Range)",
    65535: "Dynamic Port End (Ephemeral Port Range)"
}
    return common_ports.get(port, f"Custom Service (Port {port})")


class PortKillerApp:
    def __init__(self, root):
        self.root = root
        self.setup_ui()
        self.refresh_port_list()

    def setup_ui(self):
        """Setup user interface"""
        self.root.title("Port Killer Tool v1.0")
        self.root.geometry("550x650")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f0f0")

        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = tk.Label(main_frame, text="🔧 One-Click Port Killer",
                              font=("Arial", 18, "bold"),
                              fg="#2c3e50", bg="#f0f0f0")
        title_label.pack(pady=(0, 20))

        # Port input frame
        input_frame = ttk.LabelFrame(main_frame, text="📌 Enter Port Number", padding="15")
        input_frame.pack(fill=tk.X, pady=(0, 15))

        # Port input
        port_input_frame = ttk.Frame(input_frame)
        port_input_frame.pack(fill=tk.X)

        ttk.Label(port_input_frame, text="Port:", font=("Arial", 11)).pack(side=tk.LEFT, padx=(0, 10))

        self.port_entry = ttk.Entry(port_input_frame, width=10, font=("Arial", 12))
        self.port_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.port_entry.focus()

        self.close_button = tk.Button(port_input_frame,
                                     text="Kill Port",
                                     command=self.close_port,
                                     font=("Arial", 11, "bold"),
                                     bg="#3498db", fg="white",
                                     activebackground="#2980b9",
                                     relief="raised", padx=15, pady=5)
        self.close_button.pack(side=tk.LEFT)

        # Quick ports
        quick_frame = ttk.Frame(input_frame)
        quick_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(quick_frame, text="Quick Ports:", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

        quick_ports = [80, 443, 8080, 3000, 3306, 5000]
        for port in quick_ports:
            btn = tk.Button(quick_frame, text=str(port),
                           command=lambda p=port: self.set_port(p),
                           font=("Arial", 9), bg="#95a5a6", fg="white",
                           width=5, relief="flat")
            btn.pack(side=tk.LEFT, padx=2)

        # Port list
        list_frame = ttk.LabelFrame(main_frame, text="📋 Local Port Usage", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.port_listbox = tk.Listbox(list_frame,
                                     yscrollcommand=scrollbar.set,
                                     font=("Consolas", 9),
                                     bg="#ffffff", fg="#2c3e50")
        self.port_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.port_listbox.yview)

        self.port_listbox.bind('<<ListboxSelect>>', self.on_port_select)

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        refresh_button = tk.Button(button_frame,
                                 text="🔄 Refresh List",
                                 command=self.refresh_port_list,
                                 font=("Arial", 11, "bold"),
                                 bg="#27ae60", fg="white",
                                 activebackground="#229954",
                                 relief="raised", padx=15, pady=5)
        refresh_button.pack(side=tk.LEFT)

        clear_button = tk.Button(button_frame,
                               text="Clear Input",
                               command=lambda: self.port_entry.delete(0, tk.END),
                               font=("Arial", 11, "bold"),
                               bg="#e74c3c", fg="white",
                               activebackground="#c0392b",
                               relief="raised", padx=15, pady=5)
        clear_button.pack(side=tk.LEFT, padx=(10, 0))

        # Status
        self.status_label = ttk.Label(main_frame, text="✅ Ready",
                                    font=("Arial", 10, "bold"),
                                    foreground="#27ae60")
        self.status_label.pack(pady=(0, 10))

        # Tips
        tip_label = tk.Label(main_frame,
                           text="⚠️ Warning: Closing a port will force terminate the process using it. Please use with caution.",
                           foreground="#e67e22",
                           font=("Arial", 9, "italic"),
                           bg="#f0f0f0")
        tip_label.pack()

        # Keyboard bindings
        self.root.bind('<Return>', lambda e: self.close_port())
        self.root.bind('<Escape>', lambda e: self.port_entry.delete(0, tk.END))

    def set_port(self, port):
        """Set port number"""
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, str(port))

    def on_port_select(self, event):
        """Handle port selection"""
        selection = self.port_listbox.curselection()
        if selection:
            item = self.port_listbox.get(selection[0])
            # Extract port number
            try:
                import re
                match = re.search(r'Port\s+(\d+)', item)
                if match:
                    self.set_port(match.group(1))
            except:
                pass

    def close_port(self):
        """Close port"""
        port = self.port_entry.get().strip()
        if not port:
            messagebox.showerror("Error", "Please enter a port number!")
            return

        if not port.isdigit():
            messagebox.showerror("Error", "Port number must be a digit!")
            return

        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            messagebox.showerror("Error", "Port number must be between 1-65535!")
            return

        # Find process
        self.status_label.config(text="Searching for process using the port...")
        self.root.update()

        pid = find_process_using_port(port_num)
        if not pid:
            messagebox.showinfo("Info", f"Port {port} is not being used by any process!")
            self.status_label.config(text="Operation completed")
            return

        # Ask for confirmation
        result = messagebox.askyesno("Confirm",
                                    f"Port {port} is being used by process {pid}.\nDo you want to terminate this process?")
        if result:
            self.status_label.config(text=f"Terminating process {pid}...")
            self.root.update()
            if kill_process_by_pid(pid):
                messagebox.showinfo("Success", f"Successfully closed port {port}")
                self.status_label.config(text="Operation successful")
                self.refresh_port_list()  # Refresh list
            else:
                messagebox.showerror("Error", "Failed to terminate process!")
                self.status_label.config(text="Operation failed")
        else:
            self.status_label.config(text="Operation cancelled")

    def refresh_port_list(self):
        """Refresh port list"""
        try:
            self.port_listbox.delete(0, tk.END)
            used_ports = get_all_used_ports()

            if not used_ports:
                self.port_listbox.insert(tk.END, "No used ports found")
                return

            # Show title
            title = f"Ports in use (Total: {len(used_ports)}):"
            self.port_listbox.insert(tk.END, title)
            self.port_listbox.insert(tk.END, "-" * 60)

            # Show ports
            for port, pid in used_ports:
                port_desc = get_port_description(port)
                display = f"🔴 Port {port:5d} - PID:{pid:6s} - {port_desc}"
                self.port_listbox.insert(tk.END, display)
                self.port_listbox.itemconfig(tk.END, {'fg': '#e74c3c'})

        except Exception as e:
            self.port_listbox.insert(tk.END, f"Refresh failed: {str(e)}")


def main():
    """Main function"""
    if not is_admin():
        # Re-run with administrator privileges
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                          " ".join(sys.argv), None, 1)
        return

    root = tk.Tk()
    app = PortKillerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()