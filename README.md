<p align="center">
  <img src="https://img.shields.io/badge/Flock_Scan-v3.1-red?style=flat-square&logo=appveyor" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
</p>

```
███████╗██╗     ██████╗  ██████╗██╗  ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║    ██╔═══██╗██╔════╝██║ ██╔╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║
█████╗  ██║    ██║   ██║██║     █████╔╝      ███████╗██║     ███████║██╔██╗ ██║
██╔══╝  ██║    ██║   ██║██║     ██╔═██╗      ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ███████╗╚██████╔╝╚██████╗██║  ██╗     ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

Multi-mode Flock Safety security assessment tool. Flock_scan is intended to see what else we are not seeing. Our hardwear hacker homies are killing it on scanning the phsyical layer so i built flock_scan to help scan the network and application layers.

---

##  Capabilities

### 1) CVE Scanning
| CVE | Score | Description |
|-----|-------|-------------|
| **CVE-2025-59403** | 9.8  | Unauthenticated admin API / ADB RCE |
| **CVE-2025-59407** | CRIT  | Hardcoded keystore crypto key |
| **CVE-2025-47818** | HIGH  | Hardcoded fallback hotspot credentials |
| **CVE-2025-47823** | HIGH  | Hardcoded system password on ALPR firmware |

Disclaimer: For authorized security testing only.

### 2) Flock Instance Discovery
Scans any subnet for all known Flock camera fingerprints.

| Fingerprint | Port | Detection |
|-------------|------|-----------|
| **ADB shell** | 5555 | `getprop ro.product.model` -> Flock/Falcon/Sparrow |
| **Admin web UI** | 80/443 | GainSec's `admin_page_template.html` in HTTP body |
| **ONVIF device** | 80/443/8899 | SOAP `GetDeviceInformation` -> manufacturer string |
| **SpeedPourer** | 21 | FTP banner / admin page references |
| **FRP tunnel** | 7000-7500 | Fast Reverse Proxy banner grab |
| **Cloud DNS** | -- | Admin UI contains `*.flocksafety.com` URLs |
| **All 4 CVEs** | -- | Per-host exploit checks run automatically |

### 3) Traffic Analysis
Determines if a Flock camera sends data to **the cloud** or a **local station**.

```
CLOUD            ->  Sends data to api.flocksafety.com / Flock infrastructure
LOCAL_STATION    ->  Data stays on-prem (no cloud contact detected)
INDETERMINATE   ->  Unable to determine (camera may be offline)
```

Detection methods:
- **DNS resolution** of `api.flocksafety.com` and other Flock domains
- **Admin UI inspection** -- `/metadata`, `/config` endpoints checked for cloud URLs vs internal IPs
- **FRP tunnel detection** -- Reverse Proxy tunnel on ports 7000/7500
- **ADB network config** -- reads gateway and DNS from camera shell

### 4) Traffic Tap -- Passive Monitoring (NEW)

Watch live camera traffic or analyze a PCAP file to see exactly what Flock cameras are communicating with. No decryption needed.

#### What it detects

| Signal | What it reveals |
|--------|----------------|
| **DNS queries** | Every domain the camera resolves -- `api.flocksafety.com`, `flock-hibiki-inbox.s3...`, etc. |
| **TLS SNI** | HTTPS destinations **without decryption** -- just the hostname |
| **FRP tunnels** | Outbound connections on ports 7000-7500 (Fast Reverse Proxy) |
| **TCP connections** | Full connection map -- who talks to whom, how much data flows |
| **Cloud vs Local** | Classification per IP: `CLOUD_CONNECTED`, `LOCAL_STATION`, `UNKNOWN` |

#### Callback Architecture

The tap fires three callbacks for every packet, matching the pseudocode design:

```python
def on_dns_query(self, hostname, src_ip, resolved_ips, timestamp):
    if "flocksafety" in hostname:
        self.flow_stats[src_ip]["cloud_dns"] += 1

def on_tcp_connect(self, src, dst, sport, dport, timestamp):
    if dport in [7000, 7500, 7001, 7002]:
        self.flow_stats[src]["frp_tunnel"] = True

def on_tls_sni(self, sni, src_ip, dst_ip, timestamp):
    cat = self._categorize_sni(sni)  # "auth" | "s3_upload" | "cloud_api"
    self.flow_stats[src_ip][f"{cat} += 1
```

#### Zeek-Equivalent FRP Signature

```python
# signature frp-tunnel {
#   ip-proto == tcp
#   dst-port in [7000, 7500, 7001, 7002]
#   payload /frp|auth|proxy_type/
#   event "FRP TUNNEL DETECTED"
# }
```

#### SNI Traffic Categorization

| Category | Matches | Example |
|----------|---------|---------|
| `auth` | auth0, login | `login.flocksafety.com`, `prod-flock.auth0.com` |
| `s3_upload` | s3.amazonaws | `flock-hibiki-inbox.s3.us-east-1.amazonaws.com` |
| `cloud_api` | flocksafety, flock | `api.flocksafety.com`, `websockets.flocksafety.com` |

#### Report Output

```
============================================================
            FLOCK TRAFFIC TAP REPORT
============================================================

Capture:
  Interface:   eth0
  Duration:    300.5s
  Packets:     142,931

Classification:
  Cloud-connected:  3   
  Local station:    12
  Unknown:          5

Cloud-Connected Cameras:
   192.168.1.104    DNS(api.flocksafety.com)
   192.168.1.107    SNI(login.flocksafety.com)
   192.168.1.110    FRP(2 tunnels)

FRP Tunnels: 2
   192.168.1.110 -> 10.0.0.50:7500 [frp_tunnel]
   192.168.1.110 -> 10.0.0.50:7000 [frp_auth_payload]

Flock Domains Resolved:
  - api.flocksafety.com
  - flock-hibiki-inbox.s3.us-east-1.amazonaws.com
  - login.flocksafety.com
  - prod-flock.auth0.com
  - websockets.flocksafety.com

TLS Traffic Categories:
   auth:       47 connections
   s3_upload:   1887 connections
   cloud_api:  2341 connections
```

---

##  Quick Start

> Most features require root. Run with `sudo` when scanning or capturing.

```bash
pip install requests
sudo python3 scanner.py
```

### CVE Scanning
```bash
sudo python3 scanner.py -t 192.168.1.100
sudo python3 scanner.py -f targets.txt --exploit
sudo python3 scanner.py --output results.json -v
```

### Instance Discovery
```bash
sudo python3 scanner.py --discover 192.168.1.0/24
sudo python3 scanner.py --discover 10.0.0.0/16 --output found.json
```

### Traffic Analysis
```bash
sudo python3 scanner.py --analyze-traffic 192.168.1.100
sudo python3 scanner.py --analyze-traffic 10.0.0.50 --output flow.json
```

### Traffic Tap (Live Capture)
```bash
# Requires scapy: pip install scapy
sudo python3 scanner.py --tap-interface eth0 --tap-output report.json
```

### Traffic Tap (PCAP Analysis)
```bash
sudo python3 scanner.py --tap-pcap capture.pcap --tap-output report.json
```

### Traffic Tap (Pipe from tcpdump)
```bash
sudo tcpdump -i eth0 -l -nn | sudo python3 scanner.py --tap-pipe -v
```

### Enrichment Mode (v3.0+)
```bash
# Add --enrich to any scan for extra data collection
sudo python3 scanner.py -t 192.168.1.100 --enrich
sudo python3 scanner.py -f targets.txt --enrich --output enriched_scan.json
sudo python3 scanner.py --discover 192.168.1.0/24 --enrich -v
```

**What --enrich adds:**
- **Banner grabber** -- HTTP headers (Server, X-Powered-By, Via, cookies), FTP banner (SpeedPourer version), TLS cert (SANs, issuer, expiry), SSH version
- **Cloud provider enrichment** -- IP → ASN/org/provider via ip-api.com + WHOIS fallback (AWS, GCP, Azure, Cloudflare, etc.)
- **Telemetry detection** -- Google Analytics IDs, Hotjar, Sentry, Facebook Pixel, Segment, and 30+ other SaaS services
- **ADB deep collect** -- WiFi SSID/BSSID, gateway, DNS servers, ARP table, uptime, processes, battery state, installed packages, logcat errors
- **Network map** -- Passive subnet discovery via ARP table + MAC OUI vendor resolution
- **Credential extractor** -- Scans HTTP bodies for leaked M2M OAuth client_id/secret, webhook API keys, Auth0 configs, org UUIDs
- **Prometheus scraper** -- Probes local network for open Prometheus/Grafana instances, scrapes targets + metrics
- **S3 URL catcher** -- Extracts signed S3 image URLs from captured traffic (flock-hibiki-inbox, hotlist, webhook payloads)

---

## Drive-By WiFi Recon (Monitor Mode)

```bash
# 1. Put adapter in monitor mode first
iwconfig  # find your interface
sudo airmon-ng start wlan0

# 2. Capture camera traffic (PCAP is best, pipe is for quick checks)
sudo airodump-ng wlan0mon -w capture --output-format pcap
# OR
sudo tcpdump -i wlan0mon -w capture.pcap
# OR pipe live (lightweight, DNS + FRP only)
sudo tcpdump -i wlan0mon -l -nn | sudo python3 scanner.py --tap-pipe -v

# 3. Back home: offline analysis extracts everything
sudo python3 scanner.py --tap-pcap capture.pcap --enrich --output report.json -v
```

> **Why PCAP, not pipe?** `--tap-pcap` uses scapy to extract DNS queries, TLS SNI, and HTTP payloads from every packet. `--tap-pipe` only tracks connections — it cannot capture the HTTP bodies or TLS hostnames you need for credential extraction, S3 URLs, or telemetry. Always record to PCAP first.

### What you'll get from the air

| Signal | Captures | Module |
|--------|----------|--------|
| WiFi packets | Camera DNS queries, HTTP requests, admin page data | tap.py + banner_grabber.py |
| TLS SNI | Every HTTPS hostname the camera talks to (no decryption) | tap.py |
| HTTP bodies | Admin config pages, leaked API keys, webhook URLs | creds_extractor.py |
| S3 URLs | Signed LPR image links from flock-hibiki-inbox bucket | s3_url_catcher.py |
| Prometheus | Monitoring targets if camera's network has Prometheus | prometheus_scraper.py |
| FRP tunnels | Fast Reverse Proxy connections (cloud tunnel detection) | tap.py |
| Telemetry | Google Analytics, Sentry, FB Pixel in admin page JS | telemetry.py |

### Output files created during enrich

When you run `--enrich`, the tool auto-saves findings to your output directory:

```
creds_192_168_1_100.txt   # All leaked credentials found
s3_urls_192_168_1_100.txt  # All S3 signed URLs captured
```

---

## Interactive Menu

```bash
sudo python3 scanner.py
```

```
 1.  Single IP
 2.  IP Range (CIDR)
 3.  From File
 4.  Shodan Query
 5.  Falcon/Sparrow Signatures
 6.  Flock Instance Discovery
 7.  Traffic Analysis
 8.  Traffic Tap -- live monitor
 9.  Traffic Tap -- analyze PCAP
 0.  Return
```

---

##  Shodan Queries

```bash
python3 shodan_queries.py
```

Includes dedicated `FLOCK_DISCOVERY` queries:

| Query | Finds |
|-------|-------|
| `title:"admin_page_template"` | Flock admin portals |
| `"/onvif/device_service" Flock` | ONVIF-capable Flock devices |
| `"SpeedPourer" port:21` | Speed test FTP servers |
| `"FRP" "flock" port:7000` | Reverse proxy tunnels |
| `ssl.cert.subject.cn:"*.flocksafety.com"` | Flock TLS certificates |
| `org:"Flock Safety"` | All Flock-owned infrastructure |

---

##  Safety

- **Exploitation disabled by default** -- requires explicit `--exploit` flag
- **Rate-limited threads** -- default 10, configurable with `-T`
- **Discovery mode is passive** -- only sends probe/identification packets
- **Tap mode is read-only** -- never sends packets, only listens
- **User confirmation** required before any exploit execution

```bash
# Scan only (no exploitation)
sudo python3 scanner.py -t 192.168.1.100

# Scan + exploit (requires confirmation)
sudo python3 scanner.py -t 192.168.1.100 --exploit
```

---

##  All Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Single target IP | -- |
| `-f`, `--file` | File with targets (one per line) | -- |
| `-o`, `--output` | Output file (JSON) | -- |
| `-v`, `--verbose` | Verbose output | off |
| `-T`, `--threads` | Number of scan threads | 10 |
| `--timeout` | Connection timeout (seconds) | 5 |
| `--exploit` | Enable exploitation (requires confirmation) | off |
| `--enrich` | Run enrichment modules (banners, cloud provider, telemetry, ADB deep, network map, creds, Prometheus, S3 URLs) | off |
| `--cve` | Scan specific CVE only | all |
| `--discover` | Discover Flock instances in subnet (CIDR) | -- |
| `--analyze-traffic` | Analyze cloud vs local data flow for a camera IP | -- |
| `--tap-interface` | Traffic Tap: live capture from interface | -- |
| `--tap-pcap` | Traffic Tap: analyze PCAP file | -- |
| `--tap-pipe` | Traffic Tap: read from stdin (tcpdump pipe) | off |
| `--tap-output` | Traffic Tap: save report to JSON file | -- |

---

##  File Layout

```
FLOCK_scan/
├── scanner.py                # Main tool (CVE scan + discovery + traffic analysis)
├── flock_tap.py              # Passive traffic monitor (callbacks, FRP, SNI, DNS)
├── shodan_queries.py         # Shodan dork generator
├── run_scanner.sh            # Quick-launch script
├── masscan_wrapper.sh        # Masscan integration
├── modules/                  # Enrichment modules (v3.1+)
│   ├── __init__.py
│   ├── banner_grabber.py     # HTTP/FTP/TLS/SSH banner collection
│   ├── cloud_enrich.py       # IP → ASN/org/cloud provider
│   ├── telemetry.py          # Analytics, pixels, JS endpoints
│   ├── adb_deep.py           # Extended ADB props (route, wifi, DNS, processes)
│   ├── network_map.py        # ARP-based passive subnet discovery
│   ├── creds_extractor.py    # Leaked M2M tokens, webhook API keys, auth configs
│   ├── prometheus_scraper.py # Prometheus/Grafana discovery on local network
│   └── s3_url_catcher.py     # Signed S3 image URL extraction from traffic
└── README.md
```

---

<p align="center">
  <sub>Authorized security testing only. Use on systems you own or have written permission to test.</sub>
</p>
