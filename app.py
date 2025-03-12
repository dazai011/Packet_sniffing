import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import *
import threading

# GUI Setup
root = tk.Tk()
root.geometry("1100x600")
root.configure(bg="#000000")  # Full Black Theme
root.overrideredirect(True)  # Removes the default title bar

# Custom Title Bar
title_bar = tk.Frame(root, bg="#000000", relief="raised", bd=2)
title_bar.pack(fill=tk.X)

title_label = tk.Label(title_bar, text="Packet Sniffer", bg="#000000", fg="#00FF00", font=("Arial", 12, "bold"))
title_label.pack(side=tk.LEFT, padx=10)

# Close button
close_button = tk.Button(title_bar, text="✖", command=root.quit, bg="#222222", fg="#00FF00", font=("Arial", 10, "bold"), bd=0)
close_button.pack(side=tk.RIGHT, padx=5)

# Move window functionality
def move_window(event):
    root.geometry(f"+{event.x_root}+{event.y_root}")

title_bar.bind("<B1-Motion>", move_window)

# Apply Dark Neon Theme
style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", background="#000000", foreground="#00FF00", font=("Arial", 12, "bold"))
style.configure("TFrame", background="#000000")
style.configure("TButton", font=("Arial", 10, "bold"), padding=6)
style.configure("TCombobox", background="#111111", foreground="#00FF00", fieldbackground="#000000",
                selectbackground="#222222", selectforeground="#00FF00")  # Fix for visibility
style.configure("Treeview", background="#111111", foreground="#00FF00", fieldbackground="#111111", font=("Arial", 10))
style.map("Treeview", background=[("selected", "#005500")])  # Dark Green Selection

# Control Panel
top_frame = ttk.Frame(root)
top_frame.pack(fill=tk.X, padx=5, pady=5)

# Start/Stop Button
sniffing = False
def toggle_sniffing():
    global sniffing
    if sniffing:
        sniffing = False
        start_button.config(text="Start", style="Start.TButton")
    else:
        sniffing = True
        start_button.config(text="Stop", style="Stop.TButton")
        threading.Thread(target=sniff_packets, daemon=True).start()

style.configure("Start.TButton", background="#0000FF", foreground="white")
style.configure("Stop.TButton", background="#FF0000", foreground="white")

start_button = ttk.Button(top_frame, text="Start", command=toggle_sniffing, style="Start.TButton")
start_button.pack(side=tk.RIGHT, padx=5)

# Save Button
def save_pcap():
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        wrpcap(file_path, list(packet_store.values()))

save_button = ttk.Button(top_frame, text="Save", command=save_pcap, style="TButton")
save_button.pack(side=tk.RIGHT, padx=5)

# Open PCAP Button
def open_pcap():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        packets = rdpcap(file_path)
        load_packets_into_table(packets)

open_button = ttk.Button(top_frame, text="Open", command=open_pcap, style="TButton")
open_button.pack(side=tk.RIGHT, padx=5)

# Filter Selection
filter_label = ttk.Label(top_frame, text="Filter:")
filter_label.pack(side=tk.LEFT, padx=5)

protocols = ["All", "Ethernet", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "TLS/SSL"]
selected_filter = tk.StringVar(value="All")
filter_menu = ttk.Combobox(top_frame, textvariable=selected_filter, values=protocols, state="readonly")
filter_menu.pack(side=tk.LEFT, padx=5)

# Packet Table with Scrollbar
table_frame = ttk.Frame(root)
table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

columns = ("No.", "Source IP", "Destination IP", "Protocol", "Length")
tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
tree.configure(yscrollcommand=scrollbar.set)

# Auto-scroll functionality
def auto_scroll():
    tree.yview_moveto(1.0)
root.after(1000, auto_scroll)

# Add striping effect for better readability
tree.tag_configure("oddrow", background="#111111")
tree.tag_configure("evenrow", background="#222222")

# Packet Details
packet_details_label = ttk.Label(root, text="Packet Details")
packet_details_label.pack(fill=tk.X, padx=5)

packet_details_text = tk.Text(root, height=7, bg="#111111", fg="#00FF00", font=("Courier", 10), insertbackground="white")
packet_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Hex Dump
hex_dump_label = ttk.Label(root, text="Hex Dump")
hex_dump_label.pack(fill=tk.X, padx=5)

hex_dump_text = tk.Text(root, height=7, bg="#111111", fg="#00FF00", font=("Courier", 10), insertbackground="white")
hex_dump_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Global Variables
packet_count = 0
packet_store = {}

def detect_protocol(packet):
    """Detects and classifies protocols."""
    if packet.haslayer(Ether): return "Ethernet"
    if packet.haslayer(IP): return "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IPv4"
    if packet.haslayer(IPv6): return "IPv6"
    if packet.haslayer(DNS): return "DNS"
    if packet.haslayer(ARP): return "ARP"
    if packet.haslayer(DHCP): return "DHCP"
    if packet.haslayer(TLS): return "TLS/SSL"
    if packet.haslayer(SSH): return "SSH"
    return "Other"

def packet_callback(packet):
    """Processes captured packets."""
    global packet_count
    if not sniffing: return

    protocol = detect_protocol(packet)
    if selected_filter.get() != "All" and protocol != selected_filter.get(): return

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        src_ip, dst_ip = "Unknown", "Unknown"

    packet_count += 1
    length = len(packet)
    tag = "evenrow" if packet_count % 2 == 0 else "oddrow"

    tree.insert("", tk.END, values=(packet_count, src_ip, dst_ip, protocol, length), tags=(tag,))
    tree.yview_moveto(1.0)  # Auto-scroll
    packet_store[str(packet_count)] = packet

def load_packets_into_table(packets):
    """Loads packets from a PCAP file into the table."""
    global packet_count
    for packet in packets:
        packet_callback(packet)

def on_packet_click(event):
    """Displays packet details and hex dump when a packet is clicked."""
    selected_item = tree.selection()
    if not selected_item:
        return

    packet_id = tree.item(selected_item, "values")[0]
    packet = packet_store.get(packet_id)

    if packet:
        packet_details_text.delete(1.0, tk.END)
        packet_details_text.insert(tk.END, packet.show(dump=True))

        hex_dump_text.delete(1.0, tk.END)
        hex_dump_text.insert(tk.END, hexdump(packet, dump=True))

def sniff_packets():
    """Continuously captures packets at a controlled speed in a background thread."""
    while sniffing:
        sniff(prn=packet_callback, store=False, timeout=0.5)  # Controlled speed

tree.bind("<<TreeviewSelect>>", on_packet_click)

root.mainloop()
