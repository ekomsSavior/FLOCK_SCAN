#!/usr/bin/env python3
"""
flock_tap.py — Passive Flock camera traffic monitor

Captures and analyzes network traffic from Flock Safety cameras to determine:
- Which domains they communicate with (DNS tracking)
- Whether they connect to Flock cloud or a local station
- FRP tunnel detection (ports 7000-7500)
- TLS SNI fingerprinting (HTTPs destinations without decryption)
- Per-camera traffic profiles and bandwidth usage

Modes:
  --tap-interface eth0    Live capture from a network interface
  --tap-pcap file.pcap    Offline analysis of a PCAP file
  --tap-pipe              Read from tcpdump stdin pipe
"""

import re
import os
import sys
import json
import time
import signal
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

# ── Flock-known infrastructure ──
FLOCK_CLOUD_DOMAINS = [
    "api.flocksafety.com", "app.flocksafety.com",
    "users.flocksafety.com", "login.flocksafety.com",
    "websockets.flocksafety.com", "safelist.flocksafety.com",
    "events.flocksafety.com", "docs.flocksafety.com",
    "status.flocksafety.com",
    "flock-hibiki-inbox.s3.us-east-1.amazonaws.com",
    "prod-flock-cd-bymknkftygg5gmc0.edge.tenants.auth0.com",
]

FLOCK_CLOUD_IPS = [
    "198.202.211.1", "52.72.49.79", "34.71.237.120",
    "104.18.16.189", "104.18.17.189",
]

# ── Canonical verdict vocabulary (single source of truth) ──
# Every device maps to exactly one of these so audit summary counts reconcile.
VERDICT_CLOUD = "CLOUD_CONNECTED"
VERDICT_LOCAL = "LOCAL_STATION"
VERDICT_INDETERMINATE = "INDETERMINATE"

# Scapy availability
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, conf
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

# Colors (same as scanner.py)
class C:
    H = '\033[95m'; BL = '\033[94m'; CY = '\033[96m'
    G = '\033[92m'; Y = '\033[93m'; R = '\033[91m'
    END = '\033[0m'; B = '\033[1m'


class FlockTrafficTap:
    """
    Passive traffic monitor for Flock Safety cameras.

    Matches the pseudocode interface:
        tap = FlockTrafficTap(interface="eth0")
        tap.start()
        tap.report()

    Callbacks (called on each packet):
        on_dns_query(hostname, src_ip, resolved_ips, timestamp)
        on_tcp_connect(src, dst, sport, dport, timestamp)
        on_tls_sni(sni, src_ip, dst_ip, timestamp)
    """

    def __init__(self, interface=None, pcap=None, pipe=False, verbose=False,
                 output_file=None, timeout=None, filter_expr=None,
                 max_samples=500, redact_non_flock_ips=False):
        self.interface = interface
        self.pcap = pcap
        self.pipe = pipe
        self.verbose = verbose
        self.output_file = output_file
        self.timeout = timeout
        self.filter_expr = filter_expr

        # Data-minimization knobs (see AUDIT_INTEGRITY_SPEC.md).
        # max_samples caps per-device raw sample lists so a long audit does not
        # accrete an unbounded pile of raw records; integer counters below stay
        # exact regardless. redact_non_flock_ips salt-hashes non-Flock dst IPs
        # in stored samples to protect bystanders (off by default: hashing
        # removes reproducibility a Flock-side auditor may need).
        self.max_samples = max_samples
        self.redact_non_flock_ips = redact_non_flock_ips
        self._redact_salt = os.urandom(16)

        # ── flow_stats: matches pseudocode structure ──
        self.flow_stats = defaultdict(lambda: {
            "cloud_dns": 0,
            "frp_tunnel": False,
            "auth_tls": 0,
            "s3_uploads": 0,
            "cloud_api": 0,
            "bytes_up": 0,
            "bytes_down": 0,
            "connections": 0,
            "first_seen": None,
            "last_seen": None,
        })

        # ── Raw device-level data store ──
        self.devices = defaultdict(lambda: {
            "dns_queries": [],
            "connections": [],
            "frp_tunnels": [],
            "tls_snis": [],
            "http_requests": [],
            "cloud_ip_contacts": [],
            # Exact running totals — always incremented even after the sample
            # lists above stop growing at max_samples, so counts/verdicts hold.
            "counts": {"dns": 0, "conn": 0, "frp": 0, "sni": 0, "flock_dns": 0},
            "bytes_up": 0,
            "bytes_down": 0,
            "packets_seen": 0,
            "first_seen": None,
            "last_seen": None,
        })

        self.seen_domains = set()
        self.frp_ports = {7000, 7500, 7001, 7002}
        # Known Flock cloud IPs: static seed list + IPs learned from DNS answers
        # for Flock domains. Used to catch cameras that talk to cloud IPs without
        # exposing an SNI or issuing their own DNS query.
        self.known_flock_ips = set(FLOCK_CLOUD_IPS)
        self.running = False
        self.packet_count = 0
        self.start_time = None

    # ═══════════════════════════════════════════════════
    #  CALLBACKS  — matches pseudocode interface
    # ═══════════════════════════════════════════════════

    def on_dns_query(self, hostname, src_ip, resolved_ips=None, timestamp=None):
        """Called for every DNS query. Updates flow_stats and learns Flock IPs."""
        h = hostname.lower()
        if "flocksafety" in h or "auth0.com" in h:
            self.flow_stats[src_ip]["cloud_dns"] += 1
            # Learn the resolved addresses so we can later flag cameras that
            # connect straight to these IPs without their own DNS/SNI.
            for rip in (resolved_ips or []):
                self.known_flock_ips.add(rip)

    def on_tcp_connect(self, src, dst, sport, dport, timestamp=None):
        """Called for every TCP packet. Updates flow_stats.

        Byte accounting is handled from real ``ip.len`` in the packet handler;
        this only tracks connection signals so it does not inflate bandwidth.
        """
        fs = self.flow_stats[src]
        fs["connections"] += 1
        if dport in self.frp_ports:
            fs["frp_tunnel"] = True

    def on_tls_sni(self, sni, src_ip, dst_ip, timestamp=None):
        """Called for every TLS SNI. Categorizes and updates flow_stats."""
        cat = self._categorize_sni(sni)
        fs = self.flow_stats[src_ip]
        if cat == "auth":
            fs["auth_tls"] += 1
        elif cat == "s3_upload":
            fs["s3_uploads"] += 1
        elif cat == "cloud_api":
            fs["cloud_api"] += 1

    def _categorize_sni(self, sni):
        """Classify a TLS SNI into a traffic category."""
        s = sni.lower()
        if "auth0" in s or "login" in s:
            return "auth"
        if "s3.amazonaws" in s or ("s3" in s and "amazon" in s):
            return "s3_upload"
        if "flocksafety" in s or "flock" in s:
            return "cloud_api"
        return None

    # ═══════════════════════════════════════════════════
    #  CLASSIFICATION  — matches pseudocode interface
    # ═══════════════════════════════════════════════════

    def _classify(self, ip):
        """Single source of truth for a device verdict.

        Folds flow-stat signals and device-level raw fallback into exactly one
        canonical verdict so audit summary counts always reconcile.
        """
        stats = self.flow_stats[ip]
        # Cloud signals from the per-flow counters.
        if (stats.get("cloud_dns", 0) > 0 or stats.get("frp_tunnel")
                or stats.get("s3_uploads", 0) > 0 or stats.get("auth_tls", 0) > 0
                or stats.get("cloud_api", 0) > 0):
            return VERDICT_CLOUD

        # Cloud signals from the raw device store (fallback when flow_stats is
        # sparse — e.g. SNI/FRP seen but no counter set).
        dev = self.devices.get(ip, {})
        if dev:
            has_flock_sni = any(
                "flock" in s.get("sni", "").lower() or "auth0" in s.get("sni", "").lower()
                for s in dev.get("tls_snis", [])
            )
            if has_flock_sni or dev.get("frp_tunnels") or dev.get("cloud_ip_contacts"):
                return VERDICT_CLOUD

        # Traffic seen but no cloud signal → stays on-prem.
        if stats.get("connections", 0) > 0 or (dev and dev.get("connections")):
            return VERDICT_LOCAL

        return VERDICT_INDETERMINATE

    # Public names kept as thin wrappers so existing callers/tests stay valid.
    def classify_device(self, camera_ip):
        return self._classify(camera_ip)

    def classify_camera(self, ip):
        return self._classify(ip)

    # ── data-minimization helpers ──
    def _append_capped(self, lst, item):
        """Append a raw sample only while under the cap. Counters (kept
        separately) stay exact, so bounding samples never skews verdicts."""
        if len(lst) < self.max_samples:
            lst.append(item)

    def _redact_ip(self, ip):
        """Salt-hash a non-Flock IP for bystander protection. Known-Flock IPs
        pass through unchanged so cloud evidence stays legible."""
        if not self.redact_non_flock_ips or ip in self.known_flock_ips:
            return ip
        import hashlib
        return "redacted:" + hashlib.sha256(self._redact_salt + ip.encode()).hexdigest()[:12]

    # ═══════════════════════════════════════════════════
    #  PACKET HANDLER  — scapy
    # ═══════════════════════════════════════════════════

    def _handle_packet_scapy(self, pkt):
        """Process a packet — dispatches to callbacks."""
        self.packet_count += 1
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        ts = time.time()

        dev = self.devices[src]
        if dev["first_seen"] is None:
            dev["first_seen"] = ts
        dev["last_seen"] = ts
        dev["packets_seen"] += 1
        dev["bytes_up"] += ip.len

        dev_dst = self.devices[dst]
        dev_dst["bytes_down"] += ip.len
        if dev_dst["first_seen"] is None:
            dev_dst["first_seen"] = ts
        dev_dst["last_seen"] = ts
        dev_dst["packets_seen"] += 1

        # ── DNS ──
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode().rstrip(".")
                resolved_ips = []
                if pkt[DNS].ancount > 0:
                    for i in range(pkt[DNS].ancount):
                        try:
                            rr = pkt[DNS].an[i]
                            if hasattr(rr, "rdata"):
                                resolved_ips.append(str(rr.rdata))
                        except Exception:
                            pass

                self.on_dns_query(qname, src, resolved_ips, ts)
                dev["counts"]["dns"] += 1
                if "flock" in qname.lower() or "auth0" in qname.lower():
                    dev["counts"]["flock_dns"] += 1
                self._append_capped(dev["dns_queries"], {
                    "timestamp": ts, "src": src,
                    "query": qname, "resolved_ips": resolved_ips,
                })
                self.seen_domains.add(qname)

                if self.verbose:
                    is_flock = "flock" in qname.lower()
                    tag = f" {C.R}Flock{C.END}" if is_flock else ""
                    rips = f" -> {resolved_ips}" if resolved_ips else ""
                    c = C.R if is_flock else C.CY
                    print(f"  DNS  {c}{src:<16} {qname:<50}{rips}{C.END}{tag}")
            except Exception:
                pass

        # ── TCP connections (FRP detection) ──
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport

            self.on_tcp_connect(src, dst, sport, dport, ts)

            # ── Connection to a known Flock cloud IP (no SNI/DNS needed) ──
            if dst in self.known_flock_ips:
                self.flow_stats[src]["cloud_api"] += 1
                if dst not in dev["cloud_ip_contacts"]:
                    dev["cloud_ip_contacts"].append(dst)

            if tcp.flags & 0x02:  # SYN
                dev["counts"]["conn"] += 1
                self._append_capped(dev["connections"], {
                    "timestamp": ts, "src": src, "sport": sport,
                    "dst": self._redact_ip(dst), "dport": dport, "bytes": ip.len,
                })

            # ── FRP Tunnel Detection ──
            # FRP handshake pattern:
            #   1. Camera connects to port 7000-7500 on a remote server
            #   2. Sends auth + proxy configuration JSON
            #   3. Server opens reverse tunnel
            #
            # Detection signature (Zeek-equivalent):
            #   signature frp-tunnel {
            #     ip-proto == tcp
            #     dst-port in [7000, 7500, 7001, 7002]
            #     payload /frp|auth|proxy_type/
            #     event "FRP TUNNEL DETECTED"
            #   }
            # Port-based signal is evaluated per-packet (fires on the SYN too).
            if dport in self.frp_ports:
                self.flow_stats[src]["frp_tunnel"] = True
                dev["counts"]["frp"] += 1
                self._append_capped(dev["frp_tunnels"], {
                    "timestamp": ts, "src": src, "dst": self._redact_ip(dst),
                    "port": dport, "type": "frp_tunnel",
                })
                if self.verbose:
                    print(f"  {C.R}FRP  {src:<16} -> {dst}:{dport}  [FRP TUNNEL]{C.END}")

            # Raw payload scan for FRP auth. The auth/proxy JSON is sent in a
            # data segment *after* the handshake, so this must run on every TCP
            # packet — not only on the SYN (SYN packets carry no payload).
            if tcp.haslayer(Raw):
                raw = tcp[Raw].load
                low = raw.lower()
                matched = next((k for k in (b"frp", b"auth", b"proxy_type") if k in low), None)
                if matched:
                    self.flow_stats[src]["frp_tunnel"] = True
                    dev["counts"]["frp"] += 1
                    # Store a non-content descriptor, not the raw bytes: which
                    # keyword matched + payload length. Proves FRP detection
                    # without retaining any of the payload (bystander protection).
                    self._append_capped(dev["frp_tunnels"], {
                        "timestamp": ts, "src": src, "dst": self._redact_ip(dst),
                        "port": dport, "type": "frp_auth_payload",
                        "matched_keyword": matched.decode(),
                        "payload_len": len(raw),
                    })
                    if self.verbose:
                        self.log(f"{C.R}FRP_AUTH  {src} -> {dst}:{dport} - auth payload{C.END}")

        # ── TLS SNI ──
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]
            dport = tcp.dport
            raw = tcp[Raw].load
            if dport == 443 and len(raw) > 50 and raw[0] == 0x16 and raw[1] in (0x03,):
                sni = self._extract_sni(raw)
                if sni:
                    self.on_tls_sni(sni, src, dst, ts)
                    dev["counts"]["sni"] += 1
                    self._append_capped(dev["tls_snis"], {
                        "timestamp": ts, "src": src,
                        "dst": self._redact_ip(dst), "sni": sni,
                    })
                    if self.verbose:
                        cat = self._categorize_sni(sni)
                        c = C.R if cat else C.CY
                        tag = f" [{cat}]" if cat else ""
                        print(f"  TLS  {c}{src:<16} -> {dst:<16} {sni:<50}{C.END}{tag}")

    def _extract_sni(self, data):
        """Extract TLS SNI from raw ClientHello bytes."""
        try:
            offset = 5 + 4 + 32
            if offset + 1 > len(data):
                return None
            sid_len = data[offset]
            offset += 1 + sid_len
            if offset + 2 > len(data):
                return None
            cs_len = (data[offset] << 8) | data[offset + 1]
            offset += 2 + cs_len
            if offset + 1 > len(data):
                return None
            cm_len = data[offset]
            offset += 1 + cm_len
            if offset + 2 > len(data):
                return None
            ext_len = (data[offset] << 8) | data[offset + 1]
            offset += 2
            ext_end = offset + ext_len
            while offset + 4 <= ext_end:
                ext_type = (data[offset] << 8) | data[offset + 1]
                ext_data_len = (data[offset + 2] << 8) | data[offset + 3]
                offset += 4
                if ext_type == 0:
                    if offset + 2 <= ext_end:
                        list_len = (data[offset] << 8) | data[offset + 1]
                        offset += 2
                        if offset + 1 <= ext_end:
                            name_type = data[offset]
                            offset += 1
                            if name_type == 0:
                                if offset + 2 <= ext_end:
                                    name_len = (data[offset] << 8) | data[offset + 1]
                                    offset += 2
                                    if offset + name_len <= ext_end:
                                        return data[offset:offset + name_len].decode(errors="replace")
                offset += ext_data_len
        except Exception:
            pass
        return None

    # ═══════════════════════════════════════════════════
    #  TCPDUMP PIPE FALLBACK
    # ═══════════════════════════════════════════════════

    def _parse_tcpdump_line(self, line):
        """Parse a line from tcpdump -l -nn output."""
        try:
            parts = line.split()
            if len(parts) < 5:
                return None
            src_part = parts[2].rstrip(":")
            dst_part = parts[4].rstrip(":")
            src_ip, src_port = src_part.rsplit(".", 1)
            dst_ip, dst_port = dst_part.rsplit(".", 1)
            if dst_port == "53" or src_port == "53":
                result = {"type": "dns", "src": src_ip, "sport": src_port,
                          "dst": dst_ip, "dport": int(dst_port), "raw": line}
                # Try to extract the actual DNS query name
                # Format: "... 12345+ A? hostname.domain.tld. (len)"
                qm = re.search(r'\?\s+([a-zA-Z0-9.-]+)\.?\s', line)
                if qm:
                    result["query"] = qm.group(1).rstrip(".")
                return result
            if "Flags [S]" in line:
                return {"type": "syn", "src": src_ip, "sport": int(src_port),
                        "dst": dst_ip, "dport": int(dst_port), "raw": line}
            return {"type": "other", "src": src_ip, "sport": src_port,
                    "dst": dst_ip, "dport": dst_port, "raw": line}
        except Exception:
            return None

    # ═══════════════════════════════════════════════════
    #  PUBLIC API
    # ═══════════════════════════════════════════════════

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{C.CY}[{ts}]{C.END} {msg}")

    def _install_sigint(self):
        """Stop capture cleanly on Ctrl+C so the report is always produced."""
        def _handler(signum, frame):
            self.running = False
            raise KeyboardInterrupt
        try:
            signal.signal(signal.SIGINT, _handler)
        except (ValueError, RuntimeError):
            # Not on the main thread — fall back to scapy's own handling.
            pass

    def start(self):
        """Start capture in the foreground."""
        self.start_time = time.time()
        self.running = True
        self._install_sigint()
        if self.pcap:
            self._run_pcap()
        elif self.pipe:
            self._run_pipe()
        elif self.interface:
            self._run_live()
        else:
            print(f"{C.R}Error: specify --tap-interface, --tap-pcap, or --tap-pipe{C.END}")
            sys.exit(1)

    def _run_live(self):
        if HAVE_SCAPY:
            self.log(f"Live capture on {C.B}{self.interface}{C.END} (PID {os.getpid()})")
            self.log("Ctrl+C to stop and report")
            print()
            try:
                sniff(iface=self.interface, filter=self.filter_expr or "ip",
                      prn=self._handle_packet_scapy, store=0, timeout=self.timeout)
            except KeyboardInterrupt:
                pass
            self.running = False
        else:
            self.log(f"{C.Y}scapy not installed — falling back to tcpdump pipe{C.END}")
            self._run_pipe()

    def _run_pcap(self):
        if not HAVE_SCAPY:
            print(f"{C.R}Error: scapy required for pcap. pip install scapy{C.END}")
            sys.exit(1)
        self.log(f"Analyzing pcap: {C.B}{self.pcap}{C.END}\n")
        try:
            sniff(offline=self.pcap, prn=self._handle_packet_scapy, store=0,
                  timeout=self.timeout)
        except Exception as e:
            print(f"{C.R}Error: {e}{C.END}")
            sys.exit(1)
        self.running = False

    def _run_pipe(self):
        self.log("Reading from pipe (stdin). Send traffic or Ctrl+C to stop.\n")
        try:
            for line in sys.stdin:
                if not self.running:
                    break
                line = line.strip()
                if not line:
                    continue
                parsed = self._parse_tcpdump_line(line)
                if parsed:
                    self.packet_count += 1
                    src = parsed["src"]
                    dst = parsed.get("dst", "?")
                    dport = parsed.get("dport", 0)
                    dev = self.devices[src]
                    if dev["first_seen"] is None:
                        dev["first_seen"] = time.time()
                    dev["last_seen"] = time.time()
                    dev["packets_seen"] += 1
                    if parsed["type"] == "dns":
                        query = parsed.get("query", "")
                        if query:
                            dev["counts"]["dns"] += 1
                            is_flock = "flock" in query.lower() or "auth0" in query.lower()
                            if is_flock:
                                dev["counts"]["flock_dns"] += 1
                            self._append_capped(dev["dns_queries"], {
                                "timestamp": time.time(),
                                "src": src,
                                "query": query,
                                "resolved_ips": [],
                            })
                            self.seen_domains.add(query)
                            if is_flock:
                                self.flow_stats[src]["cloud_dns"] += 1
                                if self.verbose:
                                    self.log(f"{C.R}Flock DNS  {src} -> {query}{C.END}")
                            elif self.verbose:
                                self.log(f"{C.CY}DNS  {src} -> {query}{C.END}")
                    if parsed["type"] == "syn" and dport in self.frp_ports:
                        self.flow_stats[src]["frp_tunnel"] = True
                        dev["counts"]["frp"] += 1
                        self._append_capped(dev["frp_tunnels"], {
                            "timestamp": time.time(), "src": src,
                            "dst": self._redact_ip(dst), "port": dport, "type": "frp_tunnel",
                        })
                        if self.verbose:
                            self.log(f"{C.R}FRP  {src} -> {dst}:{dport}{C.END}")
        except KeyboardInterrupt:
            pass
        self.running = False

    # ═══════════════════════════════════════════════════
    #  REPORT
    # ═══════════════════════════════════════════════════

    def generate_report(self):
        """Build structured JSON report."""
        report = {
            "type": "FLOCK_TAP_REPORT",
            "capture_info": {
                "interface": self.interface,
                "pcap": self.pcap,
                "start_time": self.start_time,
                "duration": time.time() - self.start_time if self.start_time else 0,
                "total_packets": self.packet_count,
            },
            "flow_stats": {},
            "devices": {},
            "summary": {},
        }

        counts = {VERDICT_CLOUD: 0, VERDICT_LOCAL: 0, VERDICT_INDETERMINATE: 0}

        all_ips = sorted(set(list(self.devices.keys()) + list(self.flow_stats.keys())))
        for ip in all_ips:
            verdict = self._classify(ip)
            counts[verdict] += 1

            # Always include flow_stats
            report["flow_stats"][ip] = dict(self.flow_stats[ip])

            dev = self.devices.get(ip, {})
            if dev.get("packets_seen", 0) < 5:
                continue

            c = dev.get("counts", {})
            snis = sorted(set(s["sni"] for s in dev.get("tls_snis", [])))
            dns_list = sorted(set(q["query"] for q in dev.get("dns_queries", [])))
            cloud_ips = list(dev.get("cloud_ip_contacts", []))

            report["devices"][ip] = {
                "verdict": verdict,
                "packets_seen": dev["packets_seen"],
                "bytes_up": dev["bytes_up"],
                "bytes_down": dev["bytes_down"],
                "first_seen": dev["first_seen"],
                "last_seen": dev["last_seen"],
                # Exact counters (not len() of the capped sample lists).
                "dns_queries_count": c.get("dns", len(dev["dns_queries"])),
                "tls_snis_count": c.get("sni", len(dev.get("tls_snis", []))),
                "frp_tunnels_count": c.get("frp", len(dev.get("frp_tunnels", []))),
                "connections_count": c.get("conn", len(dev.get("connections", []))),
                "samples_capped_at": self.max_samples,
                "flow_stats": dict(self.flow_stats[ip]),
                # Metadata-only destination evidence — who the device talks to,
                # never payload contents.
                "destination_summary": {
                    "dns_domains": dns_list,
                    "tls_snis": snis,
                    "flock_cloud_ips": cloud_ips,
                },
                "frp_tunnels": dev.get("frp_tunnels", []),
            }

        report["summary"] = {
            "total_ips_tracked": len(all_ips),
            "cloud_connected": counts[VERDICT_CLOUD],
            "local_station": counts[VERDICT_LOCAL],
            "indeterminate": counts[VERDICT_INDETERMINATE],
            # Invariant: the three buckets partition every tracked IP.
            "counts_reconcile": (
                counts[VERDICT_CLOUD] + counts[VERDICT_LOCAL]
                + counts[VERDICT_INDETERMINATE] == len(all_ips)
            ),
            "flock_domains_resolved": sorted(
                d for d in self.seen_domains
                if "flock" in d.lower() or "auth0" in d.lower()
            ),
            "total_flock_queries": sum(
                dev.get("counts", {}).get("flock_dns", 0)
                for dev in self.devices.values()
            ),
            "total_frp_tunnels": sum(
                dev.get("counts", {}).get("frp", 0)
                for dev in self.devices.values()
            ),
        }
        return report

    def _extract_s3_from_collected(self):
        """Scan collected traffic data for S3/image URLs."""
        from modules.s3_url_catcher import scan_traffic_for_s3, format_s3_findings_terminal

        # Build payload list from DNS queries (some domains look like S3)
        pcap_bodies = []
        for dev_ip, dev in self.devices.items():
            for dns in dev.get("dns_queries", []):
                q = dns.get("query", "")
                if "s3" in q.lower() or "amazonaws" in q.lower() or "flock-hibiki" in q.lower():
                    pcap_bodies.append(q)
            for sni in dev.get("tls_snis", []):
                s = sni.get("sni", "")
                if "s3" in s.lower() or "amazonaws" in s.lower():
                    pcap_bodies.append(s)
            for conn in dev.get("connections", []):
                # HTTP payloads sometimes appear in connection data
                raw = conn.get("payload", "")
                if raw and ("s3" in raw.lower() or "flock-hibiki" in raw.lower()):
                    pcap_bodies.append(raw)

        return scan_traffic_for_s3(pcap_payloads=pcap_bodies)

    def report(self):
        """Print and optionally save the report."""
        print(f"\n{C.B}{'='*70}{C.END}")
        print(f"{C.B}   FLOCK TRAFFIC TAP REPORT{C.END}")
        print(f"{C.B}{'='*70}{C.END}")

        elapsed = time.time() - self.start_time if self.start_time else 0
        print(f"\n{C.CY}Capture:{C.END}")
        if self.interface:
            print(f"  Interface:   {self.interface}")
        if self.pcap:
            print(f"  PCAP:        {self.pcap}")
        print(f"  Duration:    {elapsed:.1f}s")
        print(f"  Packets:     {self.packet_count:,}")

        # Partition every tracked IP into exactly one bucket (counts reconcile).
        verdicts = {ip: self._classify(ip) for ip in self.devices}
        cloud_cams = [ip for ip, v in sorted(verdicts.items()) if v == VERDICT_CLOUD]
        local_n = sum(1 for v in verdicts.values() if v == VERDICT_LOCAL)
        indet_n = sum(1 for v in verdicts.values() if v == VERDICT_INDETERMINATE)

        print(f"\n{C.CY}Classification:{C.END}")
        print(f"  Cloud-connected:  {len(cloud_cams)}")
        print(f"  Local station:    {local_n}")
        print(f"  Indeterminate:    {indet_n}")

        if cloud_cams:
            print(f"\n{C.R}Cloud-Connected Cameras:{C.END}")
            for ip in cloud_cams:
                dev = self.devices[ip]
                evidence = []
                dns_list = list(set(q["query"] for q in dev.get("dns_queries", [])
                                     if "flock" in q["query"].lower() or "auth0" in q["query"].lower()))
                snis = list(set(s["sni"] for s in dev.get("tls_snis", [])
                                if "flock" in s["sni"].lower() or "auth0" in s["sni"].lower()))
                frps = dev.get("frp_tunnels", [])
                cloud_ips = dev.get("cloud_ip_contacts", [])
                if dns_list:
                    evidence.append(f"DNS({', '.join(dns_list[:3])})")
                if snis:
                    evidence.append(f"SNI({', '.join(snis[:3])})")
                if frps:
                    evidence.append(f"FRP({dev.get('counts', {}).get('frp', len(frps))} tunnels)")
                if cloud_ips:
                    evidence.append(f"CLOUD_IP({', '.join(cloud_ips[:3])})")
                if not evidence:
                    # Cloud via an S3/auth/api SNI category counter with no
                    # retained hostname sample — name the signal so the verdict
                    # is never unexplained.
                    fs = self.flow_stats[ip]
                    sig = [k for k in ("s3_uploads", "auth_tls", "cloud_api") if fs.get(k)]
                    evidence.append(f"TLS_CATEGORY({', '.join(sig)})" if sig else "cloud signal")
                print(f"  {C.R}[!] {ip:<16}{C.END} {' | '.join(evidence[:4])}")

        # All Flock domains seen
        flock_domains = sorted(
            d for d in self.seen_domains
            if "flock" in d.lower() or "auth0" in d.lower()
        )
        if flock_domains:
            print(f"\n{C.CY}Flock Domains Resolved:{C.END}")
            for d in flock_domains:
                print(f"  ﹒ {d}")

        # FRP tunnels (exact counter; the per-tunnel list below is a capped sample)
        total_frp = sum(dev.get("counts", {}).get("frp", 0) for dev in self.devices.values())
        if total_frp > 0:
            print(f"\n{C.R}FRP Tunnels: {total_frp}{C.END}")
            for ip, dev in sorted(self.devices.items()):
                for frp in dev.get("frp_tunnels", []):
                    print(f"  {C.R}[!] {ip} -> {frp['dst']}:{frp['port']} [{frp.get('type','')}]{C.END}")

        # SNI Categorization summary
        auth_count = sum(fs["auth_tls"] for fs in self.flow_stats.values())
        s3_count = sum(fs["s3_uploads"] for fs in self.flow_stats.values())
        api_count = sum(fs["cloud_api"] for fs in self.flow_stats.values())
        if auth_count or s3_count or api_count:
            print(f"\n{C.CY}TLS Traffic Categories:{C.END}")
            if auth_count:
                print(f"   auth:     {auth_count} connections")
            if s3_count:
                print(f"   s3_upload: {s3_count} connections")
            if api_count:
                print(f"   cloud_api: {api_count} connections")

        # S3 URLs from captured traffic
        try:
            s3_urls = self._extract_s3_from_collected()
            if s3_urls:
                from modules.s3_url_catcher import format_s3_findings_terminal
                print(f"\n{C.Y}S3/Image URLs Captured:{C.END}")
                print(format_s3_findings_terminal(s3_urls))
        except Exception:
            pass

        # Save
        if self.output_file:
            report_data = self.generate_report()
            # Add S3 URLs to saved report
            try:
                s3_urls = self._extract_s3_from_collected()
                if s3_urls:
                    report_data["s3_image_urls"] = s3_urls
            except Exception:
                pass
            with open(self.output_file, "w") as f:
                json.dump(report_data, f, indent=2)
            print(f"\n{C.G}Report saved to {self.output_file}{C.END}")

        print(f"\n{C.B}{'='*70}{C.END}\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Flock Traffic Tap — Passive Camera Monitor")
    parser.add_argument("--tap-interface", help="Network interface for live capture")
    parser.add_argument("--tap-pcap", help="PCAP file to analyze")
    parser.add_argument("--tap-pipe", action="store_true", help="Read from stdin pipe")
    parser.add_argument("--tap-output", help="Save report to JSON file")
    parser.add_argument("--tap-verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--tap-timeout", type=int, default=None, help="Capture duration (seconds)")
    parser.add_argument("--tap-filter", default=None, help="BPF filter expression")
    parser.add_argument("--tap-max-samples", type=int, default=500,
                        help="Cap on per-device raw samples kept (data minimization). Default 500.")
    parser.add_argument("--tap-redact-ips", action="store_true",
                        help="Salt-hash non-Flock destination IPs in stored samples (bystander protection).")
    args = parser.parse_args()

    tap = FlockTrafficTap(
        interface=args.tap_interface, pcap=args.tap_pcap, pipe=args.tap_pipe,
        verbose=args.tap_verbose, output_file=args.tap_output, timeout=args.tap_timeout,
        filter_expr=args.tap_filter, max_samples=args.tap_max_samples,
        redact_non_flock_ips=args.tap_redact_ips,
    )
    if not args.tap_interface and not args.tap_pcap and not args.tap_pipe:
        parser.print_help()
        print(f"\n{C.Y}Specify --tap-interface, --tap-pcap, or --tap-pipe{C.END}")
        return
    tap.start()
    tap.report()


if __name__ == "__main__":
    main()
