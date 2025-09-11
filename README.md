# Network-scan-sec-Tot
Network Scan Security - simple tools

![Screen Capture](https://raw.githubusercontent.com/gagaltotal/network-scan-sec/refs/heads/main/Screenshot%20from%202025-09-11%2023-19-55.png)

netsec_scan_tot.py — DNS + Public IP + Nmap Vulnerability Scan (Python)

❗ Skrip ini bertujuan untuk audit keamanan defensif.

Fitur:
- Resolusi DNS (A/AAAA/CNAME/MX/TXT/NS jika dnspython terpasang, fallback ke socket untuk A)
- Deteksi IP publik (multi-endpoint, timeout pendek)
- Nmap vuln scan: -sV --script vuln (opsional OS detect, UDP, top-ports/all-ports)
- Output ringkas di konsol + file JSON laporan terstruktur
- Exit code non‑zero bila nmap tidak ditemukan / target unreachable

Prasyarat:
- Python 3.8+
- Nmap terpasang di sistem (https://nmap.org) dan ada di PATH
- (Opsional) dnspython: pip install dnspython
- (Opsional) requests: pip install requests  

# Contoh Pakai :

```sh
$ python netsec_scan_tot.py example.com --vuln --top-ports 200 --json out.json
$ python netsec_scan_tot.py 203.1.113.666 --vuln --all-ports --os-detect --udp
$ python netsec_scan_tot.py --public-ip
$ python netsec_scan_tot.py example.com --dns-only


Lisensi: Open Source