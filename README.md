# NetSec-Scan-Tot

**DNS + Public IP + Nmap Vulnerability Scanner**

A comprehensive security scanning tool for authorized defensive security assessments. Combines DNS resolution, public IP detection, and nmap vulnerability scanning with structured JSON reporting.

![Screen Capture](https://raw.githubusercontent.com/gagaltotal/network-scan-sec/refs/heads/main/Screenshot%20from%202025-09-11%2023-19-55.png)

> **IMPORTANT**: This tool is intended for **authorized defensive security audits only**. Unauthorized network scanning is illegal.

---

## Features

- **DNS Resolution**: Query A, AAAA, CNAME, MX, NS, and TXT records
  - Primary: Uses `dnspython` library (if installed) for full query type support
  - Fallback: Uses socket module for A/AAAA records
  - Configurable timeouts for reliability

- **Public IP Detection**: Identify your machine's public IP address
  - Multiple endpoint support for redundancy (ipify, ifconfig.me, ipinfo.io)
  - Primary: Uses `requests` library
  - Fallback: Uses `curl` command

- **Nmap Vulnerability Scanning**:
  - Service version detection (`-sV`)
  - Vulnerability script scanning (`--script vuln`)
  - Optional TCP/UDP port scanning modes
  - Optional OS detection
  - Configurable timing templates (T0-T5)
  - Support for top-N ports or all-ports scanning
  - Custom nmap arguments support

- **Structured Output**:
  - Human-readable console summary
  - JSON report generation for automation and archiving
  - Timestamped reports with detailed host, port, and service information

---

## Prerequisites

### Required
- **Python 3.8+**
- **Nmap**: Must be installed and in system PATH
  - Install: https://nmap.org
  - Linux: `sudo apt-get install nmap` (Debian/Ubuntu) or `brew install nmap` (macOS)
  - Windows: Download installer from https://nmap.org/download

### Optional (Recommended)
- **dnspython**: Enhanced DNS resolution with support for all query types
  ```bash
  pip install dnspython
  ```

- **requests**: Faster public IP detection
  ```bash
  pip install requests
  ```

---

## Installation

1. Clone or download the repository:
   ```bash
   git clone https://github.com/gagaltotal/network-scan-sec.git
   cd network-scan-tot
   ```

2. Verify Python version:
   ```bash
   python3 --version  # Should be 3.8 or higher
   ```

3. (Optional) Install additional dependencies:
   ```bash
   pip install dnspython requests
   ```

4. Verify nmap installation:
   ```bash
   nmap --version
   ```

---

## Usage

### Basic Command Structure
```bash
python netsec_scan_tot.py [TARGET] [OPTIONS]
```

### Common Examples

**DNS Resolution Only:**
```bash
python netsec_scan_tot.py example.com --dns-only
```

**Vulnerability Scan with Top 200 Ports:**
```bash
python netsec_scan_tot.py example.com --vuln --top-ports 200 --json report.json
```

**Full Port Scan with OS Detection:**
```bash
python netsec_scan_tot.py 192.168.1.1 --vuln --all-ports --os-detect
```

**UDP Scan:**
```bash
python netsec_scan_tot.py example.com --vuln --udp --top-ports 100
```

**Detect Your Public IP:**
```bash
python netsec_scan_tot.py --public-ip
```

**Combined: DNS + Vulnerability Scan + JSON Report:**
```bash
python netsec_scan_tot.py example.com --vuln --json report.json
```

---

## Command-Line Options

| Option | Type | Description |
|--------|------|-------------|
| `target` | positional | Target hostname or IP address (optional if using `--public-ip` only) |
| `--dns-only` | flag | Perform DNS resolution only, skip vulnerability scanning |
| `--public-ip` | flag | Detect and display your machine's public IP address |
| `--vuln` | flag | Run nmap vulnerability scan with `-sV --script vuln` |
| `--top-ports N` | integer | Scan only the top N ports (e.g., 100, 200, 1000) |
| `--all-ports` | flag | Scan all TCP ports (65535) - slower, use with caution |
| `--udp` | flag | Enable UDP scanning (`-sU`) in addition to TCP |
| `--os-detect` | flag | Attempt OS fingerprinting (`-O`) |
| `--timing 0-5` | integer | Set nmap timing template (0=paranoid, 5=insane) |
| `--extra ARGS` | string | Pass additional nmap arguments (e.g., `"--min-rate 500 -Pn"`) |
| `--json FILE` | path | Write structured JSON report to specified file |
| `--version` | flag | Display tool version |
| `-h, --help` | flag | Show help message with all options |

---

## Output Examples

### Console Output
```
[+] Resolusi DNS untuk: example.com
[+] A: 93.184.216.34
[+] AAAA: 2606:2800:220:1:248:1893:25c8:1946
[+] Menjalankan: nmap -sV --script vuln -oX - --top-ports 200 example.com
[+] Ringkasan temuan:
    Host: A:93.184.216.34  Status: up
      - tcp/80 open  http (Apache httpd 2.4.52)
        script:http-vuln-cve2021-41773 -> Apache 2.4.49/2.4.50 allowed...
```

### JSON Report Structure
```json
{
  "timestamp": "2026-04-27T12:34:56.789123+00:00",
  "tool": "netsec_scan_tot.py",
  "version": "2.0.0",
  "target": "example.com",
  "actions": {
    "dns": true,
    "public_ip": false,
    "vuln_scan": true
  },
  "results": {
    "dns": {
      "host": "example.com",
      "records": {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]
      },
      "method": "dnspython"
    },
    "nmap": {
      "hosts": [...],
      "runstats": {...}
    }
  }
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Invalid arguments or validation error |
| 124 | Command timeout |
| 127 | Required command not found (nmap, curl, etc.) |

---

## Performance Tips

- **For large networks**: Use `--top-ports` instead of `--all-ports`
- **For quick scans**: Use `--timing 5` (insane) - faster but noisier
- **For stealthy scans**: Use `--timing 0` (paranoid) - slower but less detectable
- **For scanning behind firewall**: Use `--extra "-Pn"` to skip ping
- **For rate-limited scanning**: Use `--extra "--min-rate 100"` to control packet rate

---

## Troubleshooting

### "Program 'nmap' tidak ditemukan di PATH"
- **Solution**: Install nmap (see Prerequisites section)

### DNS Resolution Fails
- Check your network connectivity
- Try pinging the target: `ping example.com`
- Install dnspython for enhanced resolution: `pip install dnspython`

### Nmap Scan Timeout
- Increase timing template: `--timing 5`
- Reduce scope: `--top-ports 20`
- Add `--extra "-Pn"` if target doesn't respond to ping

### Permission Denied on JSON Output
- Ensure write permissions to target directory
- Use absolute path or check directory ownership

---

## License

Open Source

---

## Author

https://gagaltotal.github.io/

**Disclaimer**: This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems.