import customtkinter as ctk
from tkinter import filedialog, messagebox
from scapy.all import ARP, Ether, srp, wrpcap
import ipaddress, csv, json
import requests
import threading

class NetworkScannerApp:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("Network Scanner")

        # Set the window size to 500x500
        self.app.geometry("600x500")

        self.setup_ui()

    def setup_ui(self):
        ctk.CTkLabel(self.app, text="Enter IP address or range:").pack(pady=5)
        self.ip_entry = ctk.CTkEntry(self.app, width=300)
        self.ip_entry.pack(pady=5)

        self.scan_button = ctk.CTkButton(self.app, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.pack(pady=10)

        # Set the Textbox width to 300 and height to 200
        self.result_text_widget = ctk.CTkTextbox(self.app, wrap="none", width=450, height=200, state="normal")
        self.result_text_widget.pack(pady=5)

        self.save_button = ctk.CTkButton(self.app, text="Save Results", command=self.save_results, state="disabled")
        self.save_button.pack(pady=10)

        self.progress_bar = ctk.CTkProgressBar(self.app, width=300)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)

    def validate_ip(self, target_ip):
        try:
            ip = ipaddress.ip_network(target_ip, strict=False)
            return True
        except ValueError:
            return False

    def get_mac_vendor(self, mac_address):
        url = f"https://api.macvendors.com/{mac_address}"
        try:
            response = requests.get(url)
            return response.text
        except requests.RequestException:
            return "Unknown Vendor"

    def scan_network(self, target_ip):
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=5, verbose=0)[0]

        clients = []
        total_packets = len(result)
        for index, (sent, received) in enumerate(result):
            vendor = self.get_mac_vendor(received.hwsrc)
            clients.append({"ip": received.psrc, "mac": received.hwsrc, "vendor": vendor})
            self.progress_bar.set((index + 1) / total_packets)  # Update progress bar
            self.app.update_idletasks()  # Update the GUI

        return clients

    def save_to_pcap(self, clients, filename):
        packets = []
        for client in clients:
            arp = ARP(pdst=client["ip"], hwdst=client["mac"])
            ether = Ether(dst=client["mac"])
            packet = ether / arp
            packets.append(packet)

        wrpcap(filename, packets)
        print(f"Captured packets saved to {filename}")

    def save_to_csv(self, clients, filename):
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["ip", "mac", "vendor"])
            writer.writeheader()
            writer.writerows(clients)
        print(f"Results saved to {filename}")

    def save_to_json(self, clients, filename):
        with open(filename, 'w') as jsonfile:
            json.dump(clients, jsonfile, indent=4)
        print(f"Results saved to {filename}")

    def print_scan_results(self, clients):
        result_str = "Available devices on the network:\n"
        result_str += "{:<16} {:<18} {}\n".format("IP", "MAC", "Vendor")  # Adjust column widths
        for client in clients:
            result_str += "{:<16} {:<18} {}\n".format(client["ip"], client["mac"], client["vendor"])

        # Enable the Text widget to insert text
        self.result_text_widget.configure(state="normal")
        self.result_text_widget.delete(1.0, "end")  # Clear previous content
        self.result_text_widget.insert("end", result_str)
        # Optionally disable the Text widget again to make it read-only
        self.result_text_widget.configure(state="disabled")

    def start_scan(self):
        target_ip = self.ip_entry.get()
        if self.validate_ip(target_ip):
            self.progress_bar.set(0)
            clients = self.scan_network(target_ip)
            self.print_scan_results(clients)
            self.save_button.configure(state="normal")
            self.clients = clients
            self.progress_bar.set(1)
        else:
            messagebox.showerror("Invalid IP", "Please enter a valid IP address or range.")

    def start_scan_thread(self):
        scan_thread = threading.Thread(target=self.start_scan)
        scan_thread.start()

    def save_results(self):
        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("CSV files", "*.csv"), ("JSON files", "*.json")])
        if filename.endswith(".pcap"):
            self.save_to_pcap(self.clients, filename)
        elif filename.endswith(".csv"):
            self.save_to_csv(self.clients, filename)
        elif filename.endswith(".json"):
            self.save_to_json(self.clients, filename)

    def run(self):
        self.app.mainloop()


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.run()
