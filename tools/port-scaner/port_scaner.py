import tkinter as tk
import socket
import threading
import queue
import subprocess

stop_event = threading.Event()

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_port(port):
    try:
        port = int(port)
        return 0 < port < 65536
    except ValueError:
        return False

def check_ip(ip):
    try:
        subprocess.check_call(["ping", "-n", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def check_port(ip, port, result_queue):
    global ports_checked
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Set timeout for connecting to the port
            s.connect((ip, port))
            result_queue.put((port, True))
    except Exception as e:
        result_queue.put((port, False))
    finally:
        ports_checked += 1
        checked_ports_label.config(text=f"Checked Ports: {ports_checked}")

def start_scan():
    global ports_checked, stop_event
    stop_event.clear()
    ports_checked = 0
    checked_ports_label.config(text="Checked Ports: 0")

    ip = host_entry.get()
    start_port = start_port_entry.get()
    end_port = end_port_entry.get()
    ping_interval = ping_interval_entry.get()
    thread_count = thread_count_entry.get()

    # Check the validity of IP address
    if not is_valid_ip(ip):
        result_text.config(state=tk.NORMAL)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, "Invalid IP address")
        result_text.config(state=tk.DISABLED)
        return

    # Check the validity of ports
    if not is_valid_port(start_port) or not is_valid_port(end_port):
        result_text.config(state=tk.NORMAL)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, "Invalid port")
        result_text.config(state=tk.DISABLED)
        return

    # Check the availability of the IP address
    if not check_ip(ip):
        result_text.config(state=tk.NORMAL)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, "IP address is unreachable")
        result_text.config(state=tk.DISABLED)
        return

    result_text.config(state=tk.NORMAL)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, f"Scanning IP: {ip}\nPort Range: {start_port}-{end_port}\nScanning...\n")
    result_text.config(state=tk.DISABLED)

    def scan_ports():
        result_queue = queue.Queue()

        # Create and start threads for scanning ports
        port_threads = []
        for port in range(int(start_port), int(end_port) + 1):
            if stop_event.is_set():
                break
            t = threading.Thread(target=check_port, args=(ip, port, result_queue))
            t.start()
            port_threads.append(t)

        # Wait for all threads to finish
        for t in port_threads:
            t.join()

        # Collect the results of port scanning
        open_ports = []
        while not result_queue.empty():
            port, status = result_queue.get()
            if status:
                open_ports.append(port)

        result_text.config(state=tk.NORMAL)
        result_text.insert(tk.END, f"\nOpen Ports: {', '.join(map(str, open_ports))}\nScanning completed.\n")
        result_text.config(state=tk.DISABLED)

    threading.Thread(target=scan_ports).start()

def stop_scan():
    global stop_event
    stop_event.set()

def clear_text():
    global ports_checked
    result_text.config(state=tk.NORMAL)
    result_text.delete('1.0', tk.END)
    result_text.config(state=tk.DISABLED)
    ports_checked = 0
    checked_ports_label.config(text="Checked Ports: 0")

root = tk.Tk()
root.title("Port Scanner")

host_label = tk.Label(root, text="IP:")
host_label.grid(row=0, column=0, sticky="e")
host_entry = tk.Entry(root)
host_entry.grid(row=0, column=1)

start_port_label = tk.Label(root, text="Start Port:")
start_port_label.grid(row=1, column=0, sticky="e")
start_port_entry = tk.Entry(root)
start_port_entry.grid(row=1, column=1)

end_port_label = tk.Label(root, text="End Port:")
end_port_label.grid(row=2, column=0, sticky="e")
end_port_entry = tk.Entry(root)
end_port_entry.grid(row=2, column=1)

ping_interval_label = tk.Label(root, text="Ping Interval (ms):")
ping_interval_label.grid(row=3, column=0, sticky="e")
ping_interval_entry = tk.Entry(root)
ping_interval_entry.grid(row=3, column=1)

thread_count_label = tk.Label(root, text="Thread Count:")
thread_count_label.grid(row=4, column=0, sticky="e")
thread_count_entry = tk.Entry(root)
thread_count_entry.grid(row=4, column=1)

scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.grid(row=5, column=0)

stop_button = tk.Button(root, text="Stop Scan", command=stop_scan)
stop_button.grid(row=5, column=1)

clear_button = tk.Button(root, text="Clear Field", command=clear_text)
clear_button.grid(row=6, columnspan=2)

result_text = tk.Text(root, height=10, width=50, state=tk.DISABLED)
result_text.grid(row=7, columnspan=2)

checked_ports_label = tk.Label(root, text="Checked Ports: 0")
checked_ports_label.grid(row=8, columnspan=2)

root.mainloop()
