import nvdlib
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from scapy.all import srp, Ether, ARP, conf, show_interfaces, sniff, sr1, IP, TCP
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

def scan_port(target, port, verbose=False):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.7)
            result = sock.connect_ex((target, port))

            head_payload = b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
            
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "unknown"
                
                banner = ""
                if verbose:
                    try:
                        if service == "http" or "https" in service or port in [80, 443, 8080, 8443]:
                            payload = b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
                            sock.send(payload)
                            raw_response = sock.recv(1024).decode(errors="ignore")

                            for line in raw_response.split("\r\n"):
                                if line.startswith("Server:"):
                                    banner = line.replace("Server: ", "").strip()
                                    break
                            
                            if not banner:
                                banner = raw_response.split("\n")[0].strip()

                        else:
                            banner = sock.recv(1024).decode(errors="ignore").strip().replace("\n", " ")
                    except:
                        banner = ""

                with print_lock:
                    msg = f"\033[1;32m✓\033[0m {port} is \033[1;32mopen\033[0m | {service}"
                    history_msg = f"{port} is open | {service}"
                    if banner:
                        msg += f" | {banner}"
                        history_msg += f" | {banner}"
                    
                    print(msg)
                    found_ports.append(history_msg)

                if banner:
                    lookup_cve(banner)

    except Exception:
        pass

def lookup_cve(banner):
    clean_keyword = banner
    if banner.startswith("SSH-"):
        parts = banner.split('-')
        if len(parts) >= 3:
            clean_keyword = "-".join(parts[2:])
            
    clean_keyword = clean_keyword.split('(')[0].replace('_', ' ').replace('/', ' ').strip()
    
    words = clean_keyword.split()
    if len(words) >= 2:
        clean_keyword = f"{words[0]} {words[1]}"
    elif len(words) == 1:
        clean_keyword = words[0]
    else:
        return

    if len(clean_keyword) < 4 or "HTTP/" in clean_keyword:
        return

    try:
        r = nvdlib.searchCVE(keywordSearch=clean_keyword, limit=3)

        for eachCVE in r:
            try:
                score = eachCVE.score[1] if hasattr(eachCVE, 'score') else "N/A"
            except:
                score = "N/A"
            
            with print_lock:
                print(f"└──> \033[1;31m ⚡︎ CVE Found:\033[0m {eachCVE.id} (Score: {score})")
                if hasattr(eachCVE, 'descriptions') and eachCVE.descriptions:
                    print(f"└──> {eachCVE.descriptions[0].value}")

    except Exception:
        pass
        

def discover_network(discover, interface, verbose=False):
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=discover)
        answered, unanswered = srp(packet, timeout=2, verbose=verbose)

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

def vigilant_mode(interface):
    try:
        print(f"\033[1;31m⍻\033[0m Vigilant mode enabled on interface {interface}")
        print(f"\033[1;31m⍻\033[0m Monitoring network traffic...")
        
        while True:
            packet = sniff(iface=interface, count=1)
            if packet:
                print(f"\033[1;32m✓\033[0m {packet[0].summary()}")

    except KeyboardInterrupt:
        print(f"\033[1;31m⍻\033[0m Vigilant mode disabled")

def main():
    arg = argparse.ArgumentParser(
        description="VIGIL - Virtual Interface for Gateway Inspection & Listening",
        epilog="Example: vigil -t [IP_ADDRESS] -w 30 -o output.txt"
    )
    arg.add_argument("--target", "-t", required=False)
    arg.add_argument("--discover", "-d", required=False, type=str, default=None, help="discover active hosts in a network")
    arg.add_argument("--interface", "-i", required=False, type=str, default=None, help="interface to use for discovery")
    arg.add_argument("--show-interfaces", "-si", action="store_true", help="show available interfaces")
    arg.add_argument("--vigilant", "-v", action="store_true", help="enable vigilant mode")
    arg.add_argument("--verbose", "-vv", action="store_true", help="enable verbose mode")
    arg.add_argument("--threads", "-w", required=False, type=int, default=30, help="number of threads (default: 30)")
    arg.add_argument("--output", "-o", required=False, type=str, default=None, help="output file")
    args = arg.parse_args()

    target = args.target
    thread = args.threads
    output = args.output
    discover = args.discover
    interface = args.interface
    display_iface = args.show_interfaces
    vigilant = args.vigilant
    verbose = args.verbose

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
        discover_network(discover, interface, verbose)
        return

    if vigilant:
        vigilant_mode(interface)
        return

    if verbose:
        print(f"\033[1;32m✓\033[0m Verbose mode enabled (Banner Grabbing & Scapy Debug)")
        print(f"[*] Target IP      : {target}")
        print(f"[*] Thread Count   : {thread}")
        print(f"[*] Interface      : {interface if interface else 'Default'}")
        print(f"[*] Output File    : {output if output else 'None'}")
        print(f"[*] Scapy L3 Conf  : {conf.iface}")
        print(f"[*] Start scanning ports...\n")

    if target:
        try:
            with ThreadPoolExecutor(max_workers=thread) as executor:
                for port in range(1, 65535):
                    executor.submit(scan_port, target, port, verbose)
            if output:
                with open(output, "w") as f:
                    f.write(f"Scan completed at {timestamp}\n")
                    for port in found_ports:
                        f.write(f"{port}\n")

        except KeyboardInterrupt:
            print(f"\033[1;31m⍻\033[0m Canceled by user")

if __name__ == "__main__":
    main()