# 🎧 SoundCloud Fingerprint

A passive reconnaissance and fingerprinting tool designed to analyze the public-facing infrastructure of SoundCloud and its CDN-backed services (e.g., CDN-backed services). It performs multithreaded port scanning, banner grabbing, HTTP fingerprinting, and includes basic CVE vulnerability probes.

> ⚠️ **WARNING**: This tool is for **educational use only** on **authorized infrastructure**. Scanning third-party services without permission may violate Terms of Service and applicable laws.

---

## 🔍 Features

- 🚀 **Fast multithreaded TCP port scan** (1–65535)
- 🧠 **Banner grabbing** on open ports
- 🌐 **HTTP service fingerprinting**
  - HTTP status
  - Page title
  - Headers
- ⚔️ **Exploit detection**:
  - Shellshock (`CVE-2014-6271`)
  - Anonymous FTP login
  - SMB MS17-010 probe (`EternalBlue`)
- 📄 **Nmap XML parser** for existing scan results

---

## 📦 Requirements

- Python 3.7+
- `requests`

Install dependencies:

```bash
pip install requests
```

---

## 🚀 Usage

### Basic scan (ports 1–1024):
```bash
python scanner.py 143.204.29.52
```

### Full port scan (all 65535 ports):
```bash
python scanner.py 143.204.29.52 --full
```

### Parse an existing Nmap XML scan:
```bash
python scanner.py 143.204.29.52 --nmap full_scan.xml
```

---

## 🔐 Exploits

| CVE / Technique         | Description                                      |
|------------------------|--------------------------------------------------|
| Shellshock             | Injects payload into `User-Agent` on `/cgi-bin/` |
| Anonymous FTP          | Attempts login with no credentials               |
| MS17-010 (EternalBlue) | Checks if port 445 is open                        |

> Note: These are passive probes or simulated checks. No live exploit payloads are delivered.

---

## 🧪 Example Output

```text
[*] Starting port scan on 143.204.29.52...
[+] Port 80 is open - Banner: Server: CloudFront
[+] Port 443 is open - Banner: Server: CloudFront

[*] Starting HTTP fingerprinting...

[HTTP 80] Status: 403
Title: Access Denied
Headers:
  Server: CloudFront
  Content-Type: text/html
  X-Cache: Error from cloudfront

[*] Testing for Shellshock...
[-] Not vulnerable.

[*] FTP anonymous test failed: [Errno 111] Connection refused

[*] Port 445 closed – MS17-010 not applicable
```

---

## 🧠 Research Purpose

This tool helps analyze SoundCloud's CDN-backed platform using only public signals (headers, ports, and service banners). Useful for:

- Bug bounty reconnaissance
- Passive cloud exposure mapping
- Learning port/service enumeration techniques
- Academic writeups and security education

---

## ⚠️ Legal & Ethical Disclaimer

> This tool must only be used on systems you own, operate, or have **explicit permission** to test.
>
> SoundCloud and its affiliates are not associated with this project.
>
> You are solely responsible for all actions taken using this tool.

---

## 🛠 TODO

- [ ] Output results to JSON/Markdown
- [ ] Add TLS certificate inspection
- [ ] ASN/org metadata via `ipinfo.io`
- [ ] CDN provider inference

---

## 📄 License

MIT License – Educational Use Only.
