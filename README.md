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
██║     ███████╗╚██████╔╝██████╗██║  ██╗     ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

Multi-mode Flock Safety security assessment tool.

---

## Capabilities

### CVE Scanning (v1)
| CVE | Score | Description |
|-----|-------|-------------|
| **CVE-2025-59403** | 9.8   | Unauthenticated admin API / ADB RCE |
| **CVE-2025-59407** | CRIT  | Hardcoded keystore crypto key |
| **CVE-2025-47818** | HIGH  | Hardcoded fallback hotspot credentials |
| **CVE-2025-47823** | HIGH  | Hardcoded system password on ALPR firmware |

### Flock Instance Discovery (v2 — NEW)
Scans any subnet for all known Flock camera fingerprints.

| Fingerprint | Port | Detection |
|-------------|------|-----------|
| **ADB shell** | 5555 | `getprop ro.product.model` → Flock/Falcon/Sparrow |
| **Admin web UI** | 80/443 | GainSec's `admin_page_template.html` in HTTP body |
| **ONVIF device** | 80/443/8899 | SOAP `GetDeviceInformation` → manufacturer string |
| **SpeedPourer** | 21 | FTP banner / admin page references |
| **FRP tunnel** | 7000-7500 | Fast Reverse Proxy banner grab |
| **Cloud DNS** | — | Admin UI contains `*.flocksafety.com` URLs |
| **All 4 CVEs** | — | Per-host exploit checks run automatically |

### Traffic Analysis (v2 — NEW)
Determines if a Flock camera sends data to **the cloud** or a **local station**.

```
CLOUD            →  Sends data to api.flocksafety.com / Flock infrastructure
LOCAL_STATION    →  Data stays on-prem (no cloud contact detected)
INDETERMINATE   →  Unable to determine (camera may be offline)
```

Detection methods:
- **DNS resolution** of `api.flocksafety.com` and other Flock domains
- **Admin UI inspection** — `/metadata`, `/config` endpoints checked for cloud URLs vs internal IPs
- **FRP tunnel detection** — Reverse Proxy tunnel on ports 7000/7500
- **ADB network config** — reads gateway and DNS from camera shell

---

##  Quick Start

```bash
pip install requests
python3 scanner.py
```

### CVE Scanning
```bash
# Single target
python3 scanner.py -t 192.168.1.100

# From file
python3 scanner.py -f targets.txt --exploit

# Save results
python3 scanner.py --output results.json -v
```

### Instance Discovery
```bash
# Scan a /24 subnet
python3 scanner.py --discover 192.168.1.0/24

# Scan a /16, save findings
python3 scanner.py --discover 10.0.0.0/16 --output found.json
```

### Traffic Analysis
```bash
# Check if a camera phones home
python3 scanner.py --analyze-traffic 192.168.1.100

# Save flow analysis
python3 scanner.py --analyze-traffic 10.0.0.50 --output flow.json
```

---

##  Interactive Menu

```bash
python3 scanner.py
```

```
┌─────────────────────────────────────────┐
│           SELECT INPUT METHOD           │
├─────────────────────────────────────────┤
│  1.  Single IP                          │
│  2.  IP Range (CIDR)                    │
│  3.  From File                          │
│  4.  Shodan Query                       │
│  5.  Falcon/Sparrow Signatures          │
│                                         │
│  ═══ NEW ═══                            │
│  6.  Flock Instance Discovery           │
│  7.  Traffic Analysis                   │
│                                         │
│  8.  Return                             │
└─────────────────────────────────────────┘
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

## Safety

- **Exploitation disabled by default** — requires explicit `--exploit` flag
- **Rate-limited threads** — default 10, configurable with `-T`
- **Discovery mode is passive** — only sends probe/identification packets
- **User confirmation** required before any exploit execution

```bash
# Scan only (no exploitation)
python3 scanner.py -t 192.168.1.100

# Scan + exploit (requires confirmation)
python3 scanner.py -t 192.168.1.100 --exploit
```



<p align="center">
  <sub>Authorized security testing only. Use on systems you own or have written permission to test.</sub>
</p>
