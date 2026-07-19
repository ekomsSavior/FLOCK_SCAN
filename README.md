<p align="center">
  <img src="https://img.shields.io/badge/Flock_Scan-v2.0-red?style=flat-square&logo=appveyor" />
  <img src="https://img.shields.io/badge/CVEs-4-brightgreen?style=flat-square" />
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

Multi-mode Flock assessment tool.

DISCALIMER: FOR AUTHORIZED SECURITY TESTING ONLY XO

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

```bash
pip install requests
python3 scanner.py
```

### CVE Scanning
```bash
python3 scanner.py -t 192.168.1.100
python3 scanner.py -f targets.txt --exploit
python3 scanner.py --output results.json -v
```

### Instance Discovery
```bash
python3 scanner.py --discover 192.168.1.0/24
python3 scanner.py --discover 10.0.0.0/16 --output found.json
```

### Traffic Analysis
```bash
python3 scanner.py --analyze-traffic 192.168.1.100
python3 scanner.py --analyze-traffic 10.0.0.50 --output flow.json
```

### Traffic Tap (Live Capture)
```bash
# Requires scapy: pip install scapy
python3 scanner.py --tap-interface eth0 --tap-output report.json
```

### Traffic Tap (PCAP Analysis)
```bash
python3 scanner.py --tap-pcap capture.pcap --tap-output report.json
```

### Traffic Tap (Pipe from tcpdump)
```bash
tcpdump -i eth0 -l -nn | python3 scanner.py --tap-pipe -v
```

---

##  Interactive Menu

```bash
python3 scanner.py
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
python3 scanner.py -t 192.168.1.100

# Scan + exploit (requires confirmation)
python3 scanner.py -t 192.168.1.100 --exploit
```

---

##  File Layout

```
FLOCK_scan/
├── scanner.py            # Main tool (CVE scan + discovery + traffic analysis)
├── flock_tap.py          # Passive traffic monitor (callbacks, FRP, SNI, DNS)
├── shodan_queries.py     # Shodan dork generator
├── run_scanner.sh        # Quick-launch script
├── masscan_wrapper.sh    # Masscan integration
└── README.md
```
### MOS DEF LOOKING TO MAKE THIS TOOL STRONGER AND BETTER. PLEASE DM ME OR SUBMIT A PULL REQUEST IF YOU CAN HELP.
---

<p align="center">
  <sub>Authorized security testing only. Use on systems you own or have written permission to test.</sub>
</p>
