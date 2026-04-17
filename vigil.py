import urllib.request
from concurrent.futures import ThreadPoolExecutor
from scapy.all import srp, Ether, ARP, conf, show_interfaces
import threading
import argparse
import socket
import time
import json
import sys

banner = f"""\033[1;32m
                ██╗   ██╗██╗ ██████╗ ██╗██╗     
                ██║   ██║██║██╔════╝ ██║██║     
                ██║   ██║██║██║  ███╗██║██║     
                ╚██╗ ██╔╝██║██║   ██║██║██║     
                 ╚████╔╝ ██║╚██████╔╝██║███████╗
                  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝

    (Virtual Interface for Gateway Inspection & Listening)
\033[0m
                    \033[1;31mCreated by: ForwardEcho\033[0m  
"""

timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
print_lock = threading.Lock()
found_ports = []

with open("vendors.json", "r", encoding="utf-8") as f:
    vendors_dict = json.load(f)

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        
        try:
            service = socket.getservbyport(port, "tcp")
        except:
            service = "unknown"
            
        if result == 0:
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = ""
            if banner   :
                print(f"\033[1;32m✓\033[0m {port} is \033[1;32mopen\033[0m | {service} | {banner}")
            else:
                print(f"\033[1;32m✓\033[0m {port} is \033[1;32mopen\033[0m | {service}")

            with print_lock:
                found_ports.append(f"{port} is open | {service} | {banner}")

        sock.close()

    except KeyboardInterrupt:
        return

def discover_network(discover, interface):
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=discover)
        answered, unanswered = srp(packet, timeout=2, verbose=False)

        for sent, received in answered:
            active_ip = received.psrc
            mac_addr = received.hwsrc
            oiu_prefix = mac_addr[:8].lower()
            vendor = vendors_dict.get(oiu_prefix)
            try:
                hostname = socket.gethostbyaddr(active_ip)[0]
            except:
                hostname = "unknown"
            print(f"\033[1;32m✓\033[0m {received.psrc} is active | {hostname} | {vendor}")
        
        print(f"sent {len(packet)} packets, received {len(answered)} packets")

    except PermissionError:
        print("[+] Permission denied. Run as root")
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    arg = argparse.ArgumentParser(
        description="VIGIL - Virtual Interface for Gateway Inspection & Listening",
        epilog="Example: vigil -t [IP_ADDRESS] -w 100 -o output.txt"
    )
    arg.add_argument("--target", "-t", required=False)
    arg.add_argument("--discover", "-d", required=False, type=str, default=None, help="discover active hosts in a network")
    arg.add_argument("--interface", "-i", required=False, type=str, default=None, help="interface to use for discovery")
    arg.add_argument("--show-interfaces", "-si", action="store_true", help="show available interfaces")
    arg.add_argument("--threads", "-w", required=False, type=int, default=100, help="number of threads (default: 100)")
    arg.add_argument("--output", "-o", required=False, type=str, default=None, help="output file")
    args = arg.parse_args()

    target = args.target
    thread = args.threads
    output = args.output
    discover = args.discover
    interface = args.interface
    display_iface = args.show_interfaces

    if len(sys.argv) == 1:
        print(banner)
        arg.print_help()
        sys.exit()

    print(banner)
    print(f"Scanning {target} at time {timestamp}")
    print(f"Visit : https://github.com/ForwardEcho\n")

    if display_iface:
        show_interfaces()

    if interface:
        conf.iface = interface

    if discover:
        discover_network(discover, interface)
        return

    try:
        with ThreadPoolExecutor(max_workers=thread) as executor:
            for port in range(1, 65535):
                executor.submit(scan_port, target, port)
        if output:
            with open(output, "w") as f:
                f.write(f"Scan completed at {timestamp}\n")
                for port in found_ports:
                    f.write(f"{port}\n")

    except KeyboardInterrupt:
        print(f"\033[1;31m⍻\033[0m Canceled by user")

if __name__ == "__main__":
    main()