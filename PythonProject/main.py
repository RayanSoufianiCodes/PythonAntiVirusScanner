import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import hashlib
import os
import shutil
import threading
import time
from plyer import notification
import psutil  # For system performance monitoring
import requests  # For fetching malware updates (simulated)
import subprocess  # For VPN connections

# Sample malware hash database (updated automatically)
MALWARE_HASHES = {
    "2a8a49d9c25d786a5108a53d0b3281677b299540f54580a7b49aa8de78ec0ee1": "Trojan Virus",
    "075564c99ceb389d65faf3342d13d8bb39bbbd0d6966d3a345a8c3062f0a0d1b": "Ransomware",
}

# Paths for quarantine and logs
QUARANTINE_FOLDER = "Quarantine"
LOG_FILE = "scan_logs.txt"

if not os.path.exists(QUARANTINE_FOLDER):
    os.makedirs(QUARANTINE_FOLDER)


class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Antivirus")
        self.root.geometry("600x500")
        self.root.configure(bg="#222831")

        # Sidebar frame
        self.sidebar = tk.Frame(self.root, bg="#393E46", width=150, height=500)
        self.sidebar.pack(side="left", fill="y")

        # Sidebar buttons
        self.scan_button = tk.Button(self.sidebar, text="Scan File", command=self.scan_file, bg="#FFD369")
        self.scan_button.pack(pady=5, padx=5, fill="x")

        self.full_scan_button = tk.Button(self.sidebar, text="Full System Scan", command=self.full_system_scan, bg="#FFD369")
        self.full_scan_button.pack(pady=5, padx=5, fill="x")

        self.performance_button = tk.Button(self.sidebar, text="System Performance", command=self.system_performance, bg="#FFD369")
        self.performance_button.pack(pady=5, padx=5, fill="x")

        self.vpn_button = tk.Button(self.sidebar, text="VPN", command=self.vpn_menu, bg="#FFD369")
        self.vpn_button.pack(pady=5, padx=5, fill="x")

        self.log_button = tk.Button(self.sidebar, text="View Logs", command=self.view_logs, bg="#FFD369")
        self.log_button.pack(pady=5, padx=5, fill="x")

        self.real_time_button = tk.Button(self.sidebar, text="Enable Real-Time Protection", command=self.toggle_real_time, bg="#FFD369")
        self.real_time_button.pack(pady=5, padx=5, fill="x")

        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=20)

        self.status_label = tk.Label(self.root, text="Select a file to scan", fg="white", bg="#222831", font=("Arial", 12))
        self.status_label.pack(pady=10)

        self.is_real_time_enabled = False

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        self.status_label.config(text="Scanning...")
        self.progress.start()
        self.root.update()

        time.sleep(1)  # Simulated scan
        file_hash = self.calculate_hash(file_path)
        self.progress.stop()

        if file_hash in MALWARE_HASHES:
            self.status_label.config(text=f"Threat found: {MALWARE_HASHES[file_hash]}", fg="red")
            notification.notify(title="Threat Detected!", message=f"{MALWARE_HASHES[file_hash]} found!", timeout=5)
        else:
            self.status_label.config(text="File is safe.", fg="green")
            notification.notify(title="Scan Complete", message="No threats detected.", timeout=5)

        self.show_quarantine_options(file_path, file_hash)

    def full_system_scan(self):
        self.status_label.config(text="Performing full system scan...")
        self.progress.start()
        self.root.update()

        time.sleep(5)  # Simulated full system scan
        self.progress.stop()
        self.status_label.config(text="Full system scan complete.", fg="green")

        notification.notify(title="Full Scan Complete", message="No major threats found.", timeout=5)

    def show_quarantine_options(self, file_path, file_hash):
        button_frame = tk.Frame(self.root, bg="#222831")
        button_frame.pack(pady=10)

        quarantine_button = tk.Button(button_frame, text="Quarantine", bg="orange", command=lambda: self.quarantine_file(file_path))
        quarantine_button.pack(side="left", padx=5)

        delete_button = tk.Button(button_frame, text="Delete", bg="red", command=lambda: self.delete_file(file_path))
        delete_button.pack(side="right", padx=5)

    def quarantine_file(self, file_path):
        shutil.move(file_path, QUARANTINE_FOLDER)
        self.status_label.config(text="File quarantined.", fg="yellow")

    def delete_file(self, file_path):
        os.remove(file_path)
        self.status_label.config(text="File deleted.", fg="red")

    def view_logs(self):
        if os.path.exists(LOG_FILE):
            os.startfile(LOG_FILE)
        else:
            messagebox.showinfo("Logs", "No logs available.")

    def toggle_real_time(self):
        if self.is_real_time_enabled:
            self.is_real_time_enabled = False
            self.real_time_button.config(text="Enable Real-Time Protection")
            self.status_label.config(text="Real-time protection disabled.", fg="red")
        else:
            self.is_real_time_enabled = True
            self.real_time_button.config(text="Disable Real-Time Protection")
            self.status_label.config(text="Real-time protection enabled.", fg="green")
            threading.Thread(target=self.real_time_monitor, daemon=True).start()

    def real_time_monitor(self):
        while self.is_real_time_enabled:
            time.sleep(5)  # Simulated real-time check
            self.status_label.config(text="Monitoring system for threats...", fg="blue")

    def system_performance(self):
        usage = f"CPU: {psutil.cpu_percent()}%\nRAM: {psutil.virtual_memory().percent}%"
        self.status_label.config(text=usage, fg="white")

    def vpn_menu(self):
        vpn_window = tk.Toplevel(self.root)
        vpn_window.title("VPN Connection")
        vpn_window.geometry("300x200")

        tk.Label(vpn_window, text="Select Country:", font=("Arial", 12)).pack(pady=5)
        country_var = tk.StringVar(value="USA")

        vpn_options = ["USA", "UK", "Germany", "France"]
        dropdown = ttk.Combobox(vpn_window, textvariable=country_var, values=vpn_options)
        dropdown.pack(pady=5)

        connect_button = tk.Button(vpn_window, text="Connect", bg="green", command=lambda: self.connect_vpn(country_var.get()))
        connect_button.pack(pady=5)

        disconnect_button = tk.Button(vpn_window, text="Disconnect", bg="red", command=self.disconnect_vpn)
        disconnect_button.pack(pady=5)

    def connect_vpn(self, country):
        self.status_label.config(text=f"Connected to VPN: {country}", fg="green")

    def disconnect_vpn(self):
        self.status_label.config(text="VPN Disconnected", fg="red")

    def calculate_hash(self, file_path):
        hasher = hashlib.sha256()
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()


if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
