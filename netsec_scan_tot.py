#!/usr/bin/env python3

import argparse
import json
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

# -------- Helpers --------

def info(msg: str):
    print(f"[+] {msg}")

def warn(msg: str):
    print(f"[!] {msg}")

def err(msg: str):
    print(f"[-] {msg}", file=sys.stderr)

def which_or_die(cmd: str):
    path = shutil.which(cmd)
    if not path:
        err(f"Program '{cmd}' tidak ditemukan di PATH. Harap instal terlebih dahulu.")
        sys.exit(2)
    return path

def safe_run(cmd: List[str], timeout: int = 0) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout if timeout > 0 else None
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Perintah timeout"
    except Exception as e:
        return 1, "", str(e)

# -------- DNS --------

def resolve_dns(host: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"host": host, "records": {}}
    try:
        import dns.resolver
        import dns.exception
        res = dns.resolver.Resolver()
        res.lifetime = 3.0
        res.timeout = 2.0
        queries = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
        for qtype in queries:
            answers: List[str] = []
            try:
                r = res.resolve(host, qtype, raise_on_no_answer=False)
                if r.rrset is not None:
                    for rr in r:
                        if qtype == "MX":
                            answers.append(f"{rr.preference} {rr.exchange}".strip())
                        else:
                            answers.append(str(rr).strip().strip('"'))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            if answers:
                result["records"][qtype] = sorted(set(answers))
    except Exception:
        # Fallback minimal A record via socket
        try:
            infos = socket.getaddrinfo(host, None)
            v4 = sorted({ai[4][0] for ai in infos if ai[0] == socket.AF_INET})
            v6 = sorted({ai[4][0] for ai in infos if ai[0] == socket.AF_INET6})
            if v4:
                result["records"]["A"] = v4
            if v6:
                result["records"]["AAAA"] = v6
        except socket.gaierror as e:
            result["error"] = f"Gagal resolve: {e}"
    return result

# -------- Public IP --------

PUBLIC_IP_ENDPOINTS = [
    ("curl", ["curl", "-sS", "--max-time", "3", "https://api.ipify.org"]),
    ("curl", ["curl", "-sS", "--max-time", "3", "https://ifconfig.me/ip"]),
    ("requests", None),
]

def get_public_ip() -> Dict[str, Any]:
    info("Mendeteksi IP publik...")
    try:
        import requests
        for url in ["https://api.ipify.org", "https://ifconfig.me/ip", "https://ipinfo.io/ip"]:
            try:
                r = requests.get(url, timeout=3)
                if r.ok and r.text.strip():
                    return {"public_ip": r.text.strip(), "via": "requests", "url": url}
            except Exception:
                continue
    except Exception:
        pass

    # Try curl
    for name, cmd in PUBLIC_IP_ENDPOINTS:
        if name != "curl":
            continue
        if shutil.which("curl"):
            code, out, _ = safe_run(cmd, timeout=5)
            if code == 0 and out.strip():
                return {"public_ip": out.strip(), "via": "curl", "url": cmd[-1]}

    warn("Tidak dapat mendeteksi IP publik (butuh internet & requests/curl).")
    return {"error": "public_ip_detection_failed"}

# -------- Nmap parsing --------

def parse_nmap_xml(xml_data: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {"hosts": []}
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        return {"error": f"Gagal parse XML nmap: {e}"}

    for host in root.findall("host"):
        h: Dict[str, Any] = {"addresses": {}, "status": None, "ports": [], "os": [], "hostnames": []}
        # status
        st = host.find("status")
        if st is not None and "state" in st.attrib:
            h["status"] = st.attrib["state"]

        # addresses
        for addr in host.findall("address"):
            t = addr.attrib.get("addrtype")
            v = addr.attrib.get("addr")
            if t and v:
                h["addresses"].setdefault(t, []).append(v)

        # hostnames
        for hn in host.findall("./hostnames/hostname"):
            name = hn.attrib.get("name")
            if name:
                h["hostnames"].append(name)

        # ports
        for p in host.findall("./ports/port"):
            pd: Dict[str, Any] = {
                "protocol": p.attrib.get("protocol"),
                "portid": int(p.attrib.get("portid", "0")),
                "state": None,
                "service": {},
                "scripts": [],
            }
            st = p.find("state")
            if st is not None:
                pd["state"] = st.attrib.get("state")

            sv = p.find("service")
            if sv is not None:
                for k in ["name", "product", "version", "extrainfo", "ostype", "hostname", "conf", "method", "cpe"]:
                    if k in sv.attrib:
                        pd["service"][k] = sv.attrib[k]
                # collect cpe tags
                cpes = [c.text for c in sv.findall("cpe") if c.text]
                if cpes:
                    pd["service"]["cpes"] = cpes

            for sc in p.findall("script"):
                pd["scripts"].append({
                    "id": sc.attrib.get("id"),
                    "output": sc.attrib.get("output"),
                })

            h["ports"].append(pd)

        # OS matches
        for osm in host.findall("./os/osmatch"):
            name = osm.attrib.get("name")
            accuracy = osm.attrib.get("accuracy")
            if name:
                h["os"].append({"name": name, "accuracy": accuracy})

        res["hosts"].append(h)

    # nmap runstats
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            res["finished"] = {
                "time": finished.attrib.get("time"),
                "timestr": finished.attrib.get("timestr"),
                "elapsed": finished.attrib.get("elapsed"),
            }
    return res

# -------- Nmap runner --------

def build_nmap_cmd(target: str, args) -> List[str]:
    cmd = ["nmap", "-sV", "--script", "vuln", "-oX", "-"]
    if args.top_ports:
        cmd += ["--top-ports", str(args.top_ports)]
    if args.all_ports:
        cmd += ["-p-", "-T4"]
    if args.udp:
        cmd += ["-sU"]
    if args.os_detect:
        cmd += ["-O"]
    if args.timing:
        cmd += ["-T", str(args.timing)]
    if args.extra:
        cmd += args.extra.split()
    cmd.append(target)
    return cmd

def run_vuln_scan(target: str, args) -> Dict[str, Any]:
    which_or_die("nmap")
    cmd = build_nmap_cmd(target, args)
    info(f"Menjalankan: {' '.join(cmd)}")
    code, out, serr = safe_run(cmd, timeout=0)
    if code != 0:
        return {"error": f"nmap exit code {code}", "stderr": serr}
    parsed = parse_nmap_xml(out)
    parsed["raw_command"] = " ".join(cmd)
    return parsed

# -------- Pretty print --------

def summarize_vulns(nmap_parsed: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    for h in nmap_parsed.get("hosts", []):
        addrs = []
        for t, vals in h.get("addresses", {}).items():
            for v in vals:
                addrs.append(f"{t}:{v}")
        if addrs:
            lines.append(f"Host: {', '.join(addrs)}  Status: {h.get('status')}")
        # ports
        for p in sorted(h.get("ports", []), key=lambda x: (x.get("protocol",""), x.get("portid",0))):
            if p.get("state") != "open":
                continue
            svc = p.get("service", {})
            svc_desc = svc.get("name") or "unknown"
            if svc.get("product"):
                svc_desc += f" ({svc['product']} {svc.get('version','').strip()})".strip()
            lines.append(f"  - {p['protocol']}/{p['portid']} open  {svc_desc}")
            for sc in p.get("scripts", []):
                out = sc.get("output") or ""
                if sc.get("id","").endswith("vuln") or "CVE" in out or "VULNERABLE" in out.upper():
                    # show first lines
                    snippet = "\n      ".join(out.splitlines()[:5])
                    lines.append(f"      script:{sc.get('id')} -> {snippet}")
    if not lines:
        lines.append("Tidak ada port open/vuln terdeteksi / atau target tidak merespon.")
    return lines

# -------- Main --------

def parse_args():
    p = argparse.ArgumentParser(description="DNS + Public IP + Nmap vuln scanner (defensive use)")
    p.add_argument("target", nargs="?", help="Target (domain atau IP). Boleh kosong bila hanya --public-ip.")
    p.add_argument("--dns-only", action="store_true", help="Hanya lakukan resolusi DNS.")
    p.add_argument("--public-ip", action="store_true", help="Tampilkan IP publik host ini.")
    p.add_argument("--vuln", action="store_true", help="Jalankan nmap -sV --script vuln.")
    p.add_argument("--top-ports", type=int, default=None, help="Scan top N ports (contoh 200).")
    p.add_argument("--all-ports", action="store_true", help="Scan semua port TCP (penuh).")
    p.add_argument("--udp", action="store_true", help="Aktifkan scan UDP (-sU).")
    p.add_argument("--os-detect", action="store_true", help="Deteksi OS (-O).")
    p.add_argument("--timing", type=int, choices=range(0,6), help="Timing template Nmap -T0..-T5.")
    p.add_argument("--extra", type=str, default="", help="Argumen tambahan Nmap, contoh: \"--min-rate 500 -Pn\"")
    p.add_argument("--json", type=str, default=None, help="Tulis laporan JSON ke file.")
    return p.parse_args()

def main():
    # ASCII Banner
    print("")
    print("=================================   NetSec-Scan-Tot       ===================================")
    print("=   ███╗   ██╗███████╗████████╗███████╗███████╗ ██████╗███████╗ ██████╗ █████╗ ███╗   ██╗   =")
    print("=   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║   =")
    print("=   ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██║     ███████╗██║     ███████║██╔██╗ ██║   =")
    print("=   ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║     ╚════██║██║     ██╔══██║██║╚██╗██║   =")
    print("=   ██║ ╚████║███████╗   ██║   ███████║███████╗╚██████╗███████║╚██████╗██║  ██║██║ ╚████║   =")
    print("=   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   =")
    print("=============================== https://gagaltotal.github.io/ ===============================")
    print("")

    args = parse_args()

    if not args.target and not args.public_ip:
        err("Harap isi target (domain/IP) atau gunakan opsi --public-ip.")
        sys.exit(2)

    report: Dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tool": "netsec_scan_tot.py",
        "target": args.target,
        "actions": {
            "dns": False, "public_ip": False, "vuln_scan": False
        },
        "results": {}
    }

    # DNS
    if args.target and (args.dns_only or args.vuln or not args.public_ip):
        info(f"Resolusi DNS untuk: {args.target}")
        dns_res = resolve_dns(args.target)
        report["actions"]["dns"] = True
        report["results"]["dns"] = dns_res
        if "error" in dns_res:
            warn(dns_res["error"])
        else:
            # Ringkas tampilkan A/AAAA
            A = dns_res.get("records", {}).get("A", [])
            AAAA = dns_res.get("records", {}).get("AAAA", [])
            if A or AAAA:
                info(f"A: {', '.join(A) if A else '-'}")
                if AAAA:
                    info(f"AAAA: {', '.join(AAAA)}")

    # Public IP
    if args.public_ip:
        pip = get_public_ip()
        report["actions"]["public_ip"] = True
        report["results"]["public_ip"] = pip
        if "public_ip" in pip:
            info(f"IP publik host ini: {pip['public_ip']}")
        else:
            warn("Gagal mendeteksi IP publik.")

    # Vuln Scan
    if args.vuln and args.target:
        nres = run_vuln_scan(args.target, args)
        report["actions"]["vuln_scan"] = True
        report["results"]["nmap"] = nres
        if "error" in nres:
            err(f"Gagal menjalankan nmap: {nres['error']}")
        else:
            info("Ringkasan temuan:")
            for line in summarize_vulns(nres):
                print(line)

    # Write JSON if requested
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            info(f"Laporan JSON ditulis ke: {args.json}")
        except Exception as e:
            err(f"Gagal menulis JSON: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        err("Dibatalkan oleh pengguna.")
        sys.exit(130)
