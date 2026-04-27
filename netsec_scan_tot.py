#!/usr/bin/env python3
"""
NetSec-Scan-Tot: DNS + Public IP + Nmap Vulnerability Scanner
Defensive security scanning tool for authorized use only.
"""

import argparse
import json
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import xml.etree.ElementTree as ET

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0.0"

DNS_TIMEOUT_LIFETIME: float = 3.0
DNS_TIMEOUT_QUERY: float = 2.0

PUBLIC_IP_TIMEOUT: float = 3.0
PUBLIC_IP_CURL_TIMEOUT: int = 5

PUBLIC_IP_URLS: List[str] = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
]

NMAP_DEFAULT_SCRIPTS: str = "vuln"
NMAP_DEFAULT_TIMING: int = 4

DNS_QUERY_TYPES: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

SERVICE_ATTRIBUTES: List[str] = [
    "name", "product", "version", "extrainfo", 
    "ostype", "hostname", "conf", "method", "cpe"
]

VULN_INDICATORS: List[str] = ["CVE", "VULNERABLE"]

MAX_VULN_OUTPUT_LINES: int = 5

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def info(msg: str) -> None:
    """Print informational message with [+] prefix."""
    print(f"[+] {msg}")


def warn(msg: str) -> None:
    """Print warning message with [!] prefix."""
    print(f"[!] {msg}")


def err(msg: str) -> None:
    """Print error message with [-] prefix to stderr."""
    print(f"[-] {msg}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def which_or_die(cmd: str) -> str:
    """
    Check if a command exists in PATH, exit if not found.
    
    Args:
        cmd: Command name to search for
        
    Returns:
        Full path to the command
        
    Raises:
        SystemExit: If command not found
    """
    path = shutil.which(cmd)
    if not path:
        err(f"Program '{cmd}' tidak ditemukan di PATH. Harap instal terlebih dahulu.")
        sys.exit(2)
    return path


def safe_run(
    cmd: List[str], 
    timeout: Optional[int] = None
) -> Tuple[int, str, str]:
    """
    Safely execute a subprocess command with timeout handling.
    
    Args:
        cmd: Command and arguments as list
        timeout: Maximum execution time in seconds, None for no timeout
        
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Perintah timeout"
    except FileNotFoundError:
        return 127, "", f"Perintah tidak ditemukan: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)


def safe_int(value: Any, default: int = 0) -> int:
    """
    Safely convert value to integer.
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
        
    Returns:
        Converted integer or default
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════════
# DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_dns_via_dnspython(host: str) -> Optional[Dict[str, Any]]:
    """
    Resolve DNS records using dnspython library.
    
    Args:
        host: Hostname to resolve
        
    Returns:
        Dict with DNS records or None if dnspython unavailable/error
    """
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return None

    result: Dict[str, Dict[str, List[str]]] = {"records": {}}
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT_LIFETIME
        resolver.timeout = DNS_TIMEOUT_QUERY

        for qtype in DNS_QUERY_TYPES:
            answers: List[str] = []
            try:
                response = resolver.resolve(
                    host, qtype, raise_on_no_answer=False
                )
                
                if response.rrset is not None:
                    for rr in response:
                        if qtype == "MX":
                            exchange = str(rr.exchange).rstrip(".")
                            answers.append(f"{rr.preference} {exchange}")
                        else:
                            answers.append(str(rr).strip().strip('"'))
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.exception.Timeout,
                dns.resolver.NoNameservers
            ):
                pass
            
            unique_answers = sorted(set(answers))
            if unique_answers:
                result["records"][qtype] = unique_answers

        return result if result["records"] else None

    except Exception:
        return None


def resolve_dns_via_socket(host: str) -> Dict[str, Any]:
    """
    Fallback DNS resolution using socket module (A/AAAA only).
    
    Args:
        host: Hostname to resolve
        
    Returns:
        Dict with A and/or AAAA records
    """
    result: Dict[str, Any] = {"records": {}}
    
    try:
        addr_infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        v4_addresses: List[str] = []
        v6_addresses: List[str] = []
        
        for addr_info in addr_infos:
            ip = addr_info[4][0]
            family = addr_info[0]
            
            if family == socket.AF_INET and ip not in v4_addresses:
                v4_addresses.append(ip)
            elif family == socket.AF_INET6 and ip not in v6_addresses:
                v6_addresses.append(ip)
        
        if v4_addresses:
            result["records"]["A"] = sorted(v4_addresses)
        if v6_addresses:
            result["records"]["AAAA"] = sorted(v6_addresses)
            
    except socket.gaierror as e:
        result["error"] = f"Gagal resolve: {e}"
    
    return result


def resolve_dns(host: str) -> Dict[str, Any]:
    """
    Resolve DNS records for a host using available methods.
    
    Args:
        host: Hostname or IP to resolve
        
    Returns:
        Dict with host info and resolved records
    """
    result: Dict[str, Any] = {
        "host": host,
        "records": {},
        "method": None
    }
    
    dns_result = resolve_dns_via_dnspython(host)
    if dns_result is not None:
        result["records"] = dns_result.get("records", {})
        result["method"] = "dnspython"
        return result
    
    socket_result = resolve_dns_via_socket(host)
    result["records"] = socket_result.get("records", {})
    result["method"] = "socket"
    
    if "error" in socket_result:
        result["error"] = socket_result["error"]
    
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC IP DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def get_public_ip_via_requests() -> Optional[Dict[str, Any]]:
    """
    Detect public IP using requests library.
    
    Returns:
        Dict with IP info or None if failed
    """
    try:
        import requests
    except ImportError:
        return None
    
    for url in PUBLIC_IP_URLS:
        try:
            response = requests.get(url, timeout=PUBLIC_IP_TIMEOUT)
            if response.ok:
                ip = response.text.strip()
                if ip and _is_valid_ip(ip):
                    return {
                        "public_ip": ip,
                        "via": "requests",
                        "url": url
                    }
        except Exception:
            continue
    
    return None


def get_public_ip_via_curl() -> Optional[Dict[str, Any]]:
    """
    Detect public IP using curl command.
    
    Returns:
        Dict with IP info or None if failed
    """
    if not shutil.which("curl"):
        return None
    
    for url in PUBLIC_IP_URLS:
        cmd = [
            "curl", "-sS", "--max-time", str(PUBLIC_IP_CURL_TIMEOUT), url
        ]
        code, stdout, _ = safe_run(cmd, timeout=PUBLIC_IP_CURL_TIMEOUT + 2)
        
        if code == 0 and stdout.strip():
            ip = stdout.strip()
            if _is_valid_ip(ip):
                return {
                    "public_ip": ip,
                    "via": "curl",
                    "url": url
                }
    
    return None


def _is_valid_ip(ip: str) -> bool:
    """
    Validate if string is a valid IPv4 or IPv6 address.
    
    Args:
        ip: String to validate
        
    Returns:
        True if valid IP address
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except (socket.error, OSError):
        pass
    
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (socket.error, OSError):
        pass
    
    return False


def get_public_ip() -> Dict[str, Any]:
    """
    Detect public IP address using available methods.
    
    Returns:
        Dict with public IP info or error
    """
    info("Mendeteksi IP publik...")
    
    result = get_public_ip_via_requests()
    if result:
        return result
    
    result = get_public_ip_via_curl()
    if result:
        return result
    
    warn("Tidak dapat mendeteksi IP publik (butuh internet & requests/curl).")
    return {"error": "public_ip_detection_failed"}


# ═══════════════════════════════════════════════════════════════════════════════
# NMAP XML PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_nmap_host(host_elem: ET.Element) -> Dict[str, Any]:
    """
    Parse a single host element from nmap XML output.
    
    Args:
        host_elem: XML Element for host
        
    Returns:
        Dict with parsed host information
    """
    host_data: Dict[str, Any] = {
        "addresses": {},
        "status": None,
        "ports": [],
        "os": [],
        "hostnames": []
    }
    
    status_elem = host_elem.find("status")
    if status_elem is not None:
        host_data["status"] = status_elem.attrib.get("state")
    
    for addr_elem in host_elem.findall("address"):
        addr_type = addr_elem.attrib.get("addrtype")
        addr_value = addr_elem.attrib.get("addr")
        if addr_type and addr_value:
            host_data["addresses"].setdefault(addr_type, []).append(addr_value)
    
    for hn_elem in host_elem.findall("./hostnames/hostname"):
        hostname = hn_elem.attrib.get("name")
        if hostname:
            host_data["hostnames"].append(hostname)
    
    host_data["ports"] = parse_nmap_ports(host_elem)
    
    host_data["os"] = parse_nmap_os(host_elem)
    
    return host_data


def parse_nmap_ports(host_elem: ET.Element) -> List[Dict[str, Any]]:
    """
    Parse port elements from nmap XML output.
    
    Args:
        host_elem: XML Element for host
        
    Returns:
        List of parsed port information dicts
    """
    ports: List[Dict[str, Any]] = []
    
    for port_elem in host_elem.findall("./ports/port"):
        port_data: Dict[str, Any] = {
            "protocol": port_elem.attrib.get("protocol"),
            "portid": safe_int(port_elem.attrib.get("portid"), 0),
            "state": None,
            "service": {},
            "scripts": []
        }
        
        state_elem = port_elem.find("state")
        if state_elem is not None:
            port_data["state"] = state_elem.attrib.get("state")
        
        port_data["service"] = parse_nmap_service(port_elem)
        
        port_data["scripts"] = parse_nmap_scripts(port_elem)
        
        ports.append(port_data)
    
    ports.sort(key=lambda x: (x.get("protocol", ""), x.get("portid", 0)))
    
    return ports


def parse_nmap_service(port_elem: ET.Element) -> Dict[str, Any]:
    """
    Parse service element from nmap XML output.
    
    Args:
        port_elem: XML Element for port
        
    Returns:
        Dict with service information
    """
    service: Dict[str, Any] = {}
    
    svc_elem = port_elem.find("service")
    if svc_elem is None:
        return service
    
    for attr in SERVICE_ATTRIBUTES:
        value = svc_elem.attrib.get(attr)
        if value:
            service[attr] = value
    
    cpe_elems = svc_elem.findall("cpe")
    cpes = [cpe.text for cpe in cpe_elems if cpe.text]
    if cpes:
        service["cpes"] = cpes
    
    return service


def parse_nmap_scripts(port_elem: ET.Element) -> List[Dict[str, Any]]:
    """
    Parse script elements from nmap XML output.
    
    Args:
        port_elem: XML Element for port
        
    Returns:
        List of script information dicts
    """
    scripts: List[Dict[str, Any]] = []
    
    for script_elem in port_elem.findall("script"):
        scripts.append({
            "id": script_elem.attrib.get("id"),
            "output": script_elem.attrib.get("output"),
        })
    
    return scripts


def parse_nmap_os(host_elem: ET.Element) -> List[Dict[str, Any]]:
    """
    Parse OS match elements from nmap XML output.
    
    Args:
        host_elem: XML Element for host
        
    Returns:
        List of OS match dicts
    """
    os_matches: List[Dict[str, Any]] = []
    
    for os_match in host_elem.findall("./os/osmatch"):
        name = os_match.attrib.get("name")
        accuracy = os_match.attrib.get("accuracy")
        if name:
            os_matches.append({
                "name": name,
                "accuracy": accuracy
            })
    
    return os_matches


def parse_nmap_runstats(root: ET.Element) -> Dict[str, Any]:
    """
    Parse runstats element from nmap XML output.
    
    Args:
        root: Root XML Element
        
    Returns:
        Dict with runstats information
    """
    runstats: Dict[str, Any] = {}
    
    runstats_elem = root.find("runstats")
    if runstats_elem is None:
        return runstats
    
    finished_elem = runstats_elem.find("finished")
    if finished_elem is not None:
        runstats["finished"] = {
            "time": finished_elem.attrib.get("time"),
            "timestr": finished_elem.attrib.get("timestr"),
            "elapsed": finished_elem.attrib.get("elapsed"),
        }
    
    hosts_elem = runstats_elem.find("hosts")
    if hosts_elem is not None:
        runstats["hosts_stats"] = {
            "up": hosts_elem.attrib.get("up"),
            "down": hosts_elem.attrib.get("down"),
            "total": hosts_elem.attrib.get("total"),
        }
    
    return runstats


def parse_nmap_xml(xml_data: str) -> Dict[str, Any]:
    """
    Parse nmap XML output into structured dict.
    
    Args:
        xml_data: Raw XML string from nmap
        
    Returns:
        Dict with parsed nmap results or error
    """
    if not xml_data or not xml_data.strip():
        return {"error": "Output nmap kosong"}
    
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        return {"error": f"Gagal parse XML nmap: {e}"}
    
    result: Dict[str, Any] = {
        "hosts": [],
        "runstats": parse_nmap_runstats(root)
    }
    
    for host_elem in root.findall("host"):
        result["hosts"].append(parse_nmap_host(host_elem))
    
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# NMAP EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

def build_nmap_cmd(target: str, args: argparse.Namespace) -> List[str]:
    """
    Build nmap command based on provided arguments.
    
    Args:
        target: Target hostname or IP
        args: Parsed command line arguments
        
    Returns:
        List of command and arguments
    """
    cmd: List[str] = [
        "nmap",
        "-sV",
        "--script", NMAP_DEFAULT_SCRIPTS,
        "-oX", "-"
    ]
    
    if args.top_ports is not None:
        cmd.extend(["--top-ports", str(args.top_ports)])
    
    if args.all_ports:
        cmd.extend(["-p-", "-T4"])
    
    if args.udp:
        cmd.append("-sU")
    
    if args.os_detect:
        cmd.append("-O")
    
    if args.timing is not None:
        cmd.extend(["-T", str(args.timing)])
    elif not args.all_ports:
        cmd.extend(["-T", str(NMAP_DEFAULT_TIMING)])
    
    if args.extra:
        extra_args = args.extra.split()
        cmd.extend(extra_args)
    
    cmd.append(target)
    
    return cmd


def run_vuln_scan(target: str, args: argparse.Namespace) -> Dict[str, Any]:
    """
    Execute nmap vulnerability scan.
    
    Args:
        target: Target hostname or IP
        args: Parsed command line arguments
        
    Returns:
        Dict with scan results or error
    """
    which_or_die("nmap")
    
    cmd = build_nmap_cmd(target, args)
    info(f"Menjalankan: {' '.join(cmd)}")
    
    code, stdout, stderr = safe_run(cmd)
    
    if code != 0 and not stdout:
        return {
            "error": f"nmap exit code {code}",
            "stderr": stderr,
            "command": " ".join(cmd)
        }
    
    parsed = parse_nmap_xml(stdout)
    parsed["raw_command"] = " ".join(cmd)
    
    if code != 0 and "error" not in parsed:
        parsed["warning"] = f"nmap exit code {code}: {stderr}"
    
    return parsed


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

def format_address_list(addresses: Dict[str, List[str]]) -> str:
    """
    Format address dict into readable string.
    
    Args:
        addresses: Dict of addr_type -> [addr_values]
        
    Returns:
        Formatted string
    """
    parts: List[str] = []
    for addr_type, values in addresses.items():
        for value in values:
            parts.append(f"{addr_type}:{value}")
    return ", ".join(parts)


def format_service_info(service: Dict[str, Any]) -> str:
    """
    Format service information into readable string.
    
    Args:
        service: Service dict from parsed nmap output
        
    Returns:
        Formatted service description
    """
    name = service.get("name") or "unknown"
    product = service.get("product", "").strip()
    version = service.get("version", "").strip()
    
    if product:
        if version:
            return f"{name} ({product} {version})"
        return f"{name} ({product})"
    
    return name


def is_vuln_script(script: Dict[str, Any]) -> bool:
    """
    Check if a script indicates a vulnerability.
    
    Args:
        script: Script dict from parsed nmap output
        
    Returns:
        True if script likely indicates vulnerability
    """
    script_id = script.get("id", "") or ""
    output = script.get("output", "") or ""
    output_upper = output.upper()
    
    if script_id.endswith("vuln"):
        return True
    
    for indicator in VULN_INDICATORS:
        if indicator in output_upper:
            return True
    
    return False


def truncate_output(text: str, max_lines: int = MAX_VULN_OUTPUT_LINES) -> str:
    """
    Truncate multi-line text to specified number of lines.
    
    Args:
        text: Input text
        max_lines: Maximum lines to keep
        
    Returns:
        Truncated text
    """
    lines = text.splitlines()[:max_lines]
    return "\n      ".join(lines)


def summarize_vulns(nmap_parsed: Dict[str, Any]) -> List[str]:
    """
    Generate human-readable summary of vulnerability scan results.
    
    Args:
        nmap_parsed: Parsed nmap results dict
        
    Returns:
        List of formatted summary lines
    """
    lines: List[str] = []
    hosts = nmap_parsed.get("hosts", [])
    
    if not hosts:
        lines.append("Tidak ada host terdeteksi dalam hasil scan.")
        return lines
    
    for host in hosts:
        addresses = host.get("addresses", {})
        status = host.get("status", "unknown")
        
        addr_str = format_address_list(addresses)
        if addr_str:
            lines.append(f"Host: {addr_str}  Status: {status}")
        
        ports = host.get("ports", [])
        open_ports = [p for p in ports if p.get("state") == "open"]
        
        if not open_ports:
            lines.append("  Tidak ada port open terdeteksi.")
            continue
        
        for port in open_ports:
            protocol = port.get("protocol", "?")
            portid = port.get("portid", 0)
            service = port.get("service", {})
            svc_desc = format_service_info(service)
            
            lines.append(f"  - {protocol}/{portid} open  {svc_desc}")
            
            scripts = port.get("scripts", [])
            vuln_scripts = [s for s in scripts if is_vuln_script(s)]
            
            for script in vuln_scripts:
                script_id = script.get("id", "unknown")
                output = script.get("output") or "(no output)"
                snippet = truncate_output(output)
                lines.append(f"      script:{script_id} -> {snippet}")
    
    return lines


def print_dns_summary(dns_result: Dict[str, Any]) -> None:
    """
    Print summary of DNS resolution results.
    
    Args:
        dns_result: DNS resolution result dict
    """
    if "error" in dns_result:
        warn(dns_result["error"])
        return
    
    records = dns_result.get("records", {})
    
    a_records = records.get("A", [])
    aaaa_records = records.get("AAAA", [])
    
    if a_records:
        info(f"A: {', '.join(a_records)}")
    if aaaa_records:
        info(f"AAAA: {', '.join(aaaa_records)}")
    
    other_types = [t for t in DNS_QUERY_TYPES if t not in ("A", "AAAA") and t in records]
    for qtype in other_types:
        info(f"{qtype}: {', '.join(records[qtype])}")


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner() -> None:
    """Print ASCII banner."""
    print("")
    print("=================================   NetSec-Scan-Tot       ===================================")
    print("=   ███╗   ██╗███████╗████████╗███████╗███████╗ ██████╗███████╗ ██████╗ █████╗ ███╗   ██╗   =")
    print("=   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║   =")
    print("=   ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██║     ███████╗██║     ███████║██╔██╗ ██║   =")
    print("=   ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║     ╚════██║██║     ██╔══██║██║╚██╗██║   =")
    print("=   ██║ ╚████║███████╗   ██║   ███████║███████╗╚██████╗███████║╚██████╗██║  ██║██║ ╚████║   =")
    print("=   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   =")
    print(f"==================================  Version {VERSION}  ======================================")
    print("=============================== https://gagaltotal.github.io/ ===============================")
    print("")


# ═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="DNS + Public IP + Nmap vuln scanner (defensive use)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  %(prog)s example.com --dns-only
  %(prog)s example.com --vuln --top-ports 100
  %(prog)s 192.168.1.1 --vuln --all-ports --os-detect
  %(prog)s --public-ip
  %(prog)s example.com --vuln --json report.json
        """
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        help="Target (domain atau IP). Boleh kosong bila hanya --public-ip."
    )
    parser.add_argument(
        "--dns-only",
        action="store_true",
        help="Hanya lakukan resolusi DNS."
    )
    parser.add_argument(
        "--public-ip",
        action="store_true",
        help="Tampilkan IP publik host ini."
    )
    parser.add_argument(
        "--vuln",
        action="store_true",
        help="Jalankan nmap -sV --script vuln."
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=None,
        metavar="N",
        help="Scan top N ports (contoh: 200)."
    )
    parser.add_argument(
        "--all-ports",
        action="store_true",
        help="Scan semua port TCP (penuh)."
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Aktifkan scan UDP (-sU)."
    )
    parser.add_argument(
        "--os-detect",
        action="store_true",
        help="Deteksi OS (-O)."
    )
    parser.add_argument(
        "--timing",
        type=int,
        choices=range(0, 6),
        metavar="0-5",
        help="Timing template Nmap -T0..-T5."
    )
    parser.add_argument(
        "--extra",
        type=str,
        default="",
        help='Argumen tambahan Nmap, contoh: "--min-rate 500 -Pn"'
    )
    parser.add_argument(
        "--json",
        type=str,
        metavar="FILE",
        help="Tulis laporan JSON ke file."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )
    
    return parser.parse_args()


# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def validate_args(args: argparse.Namespace) -> Optional[str]:
    """
    Validate command line arguments.
    
    Args:
        args: Parsed arguments namespace
        
    Returns:
        Error message string or None if valid
    """
    if not args.target and not args.public_ip:
        return "Harap isi target (domain/IP) atau gunakan opsi --public-ip."
    
    if args.vuln and not args.target:
        return "Opsi --vuln memerlukan target."
    
    if args.dns_only and not args.target:
        return "Opsi --dns-only memerlukan target."
    
    if args.top_ports is not None and args.top_ports < 1:
        return "Nilai --top-ports harus lebih dari 0."
    
    if args.all_ports and args.top_ports:
        return "Tidak bisa menggunakan --all-ports dan --top-ports bersamaan."
    
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# JSON REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def write_json_report(report: Dict[str, Any], filepath: str) -> bool:
    """
    Write report to JSON file.
    
    Args:
        report: Report data dict
        filepath: Output file path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        info(f"Laporan JSON ditulis ke: {filepath}")
        return True
    except PermissionError:
        err(f"Tidak memiliki izin untuk menulis ke: {filepath}")
        return False
    except IsADirectoryError:
        err(f"Path adalah direktori, bukan file: {filepath}")
        return False
    except Exception as e:
        err(f"Gagal menulis JSON: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def should_run_dns(args: argparse.Namespace) -> bool:
    """
    Determine if DNS resolution should be performed.
    
    Args:
        args: Parsed arguments namespace
        
    Returns:
        True if DNS should be run
    """
    if not args.target:
        return False
    if args.dns_only:
        return True
    if args.vuln:
        return True
    if not args.public_ip:
        return True
    return False


def main() -> int:
    """
    Main entry point.
    
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    print_banner()
    args = parse_args()
    
    # Validate arguments
    validation_error = validate_args(args)
    if validation_error:
        err(validation_error)
        return 2
    
    # Initialize report
    report: Dict[str, Any] = {
        "timestamp": get_timestamp(),
        "tool": "netsec_scan_tot.py",
        "version": VERSION,
        "target": args.target,
        "actions": {
            "dns": False,
            "public_ip": False,
            "vuln_scan": False
        },
        "results": {}
    }
    
    # DNS Resolution
    if should_run_dns(args):
        info(f"Resolusi DNS untuk: {args.target}")
        dns_result = resolve_dns(args.target)
        report["actions"]["dns"] = True
        report["results"]["dns"] = dns_result
        print_dns_summary(dns_result)
    
    # Public IP Detection
    if args.public_ip:
        pip_result = get_public_ip()
        report["actions"]["public_ip"] = True
        report["results"]["public_ip"] = pip_result
        
        if "public_ip" in pip_result:
            info(f"IP publik host ini: {pip_result['public_ip']}")
        else:
            warn("Gagal mendeteksi IP publik.")
    
    # Vulnerability Scan
    if args.vuln and args.target:
        nmap_result = run_vuln_scan(args.target, args)
        report["actions"]["vuln_scan"] = True
        report["results"]["nmap"] = nmap_result
        
        if "error" in nmap_result:
            err(f"Gagal menjalankan nmap: {nmap_result['error']}")
            if nmap_result.get("stderr"):
                err(f"stderr: {nmap_result['stderr']}")
        else:
            info("Ringkasan temuan:")
            for line in summarize_vulns(nmap_result):
                print(line)
            
            if "warning" in nmap_result:
                warn(nmap_result["warning"])

    if args.json:
        write_json_report(report, args.json)
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        err("Dibatalkan oleh pengguna.")
        sys.exit(130)