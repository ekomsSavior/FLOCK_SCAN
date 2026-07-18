#!/usr/bin/env python3
"""
shodan_queries.py - Generate Shodan queries for CVE-2025 vulnerabilities + Discovery
"""

QUERIES = {
    'CVE-2025-59403': [
        'title:"Falcon"',
        'title:"Sparrow"',
        '"/api/v1/admin"',
        '"/api/v1/system"',
        '"/api/v1/debug"',
        'port:5555 "Android"',
        '"Android Debug Bridge"',
        'port:5037 adb',
        'http.title:"ADB"',
        '"Falcon" "api" port:443',
        '"Sparrow" "api" port:443',
        '"/api/v1/execute"',
        '"/api/v1/command"',
    ],
    'CVE-2025-59407': [
        '"Android" "v6.35.33"',
        '"keystore" "hardcoded"',
        '"crypto" "key" "Android"',
        '"/api/v1/keystore"',
        '"/api/v1/security"',
        '"hardcoded_key"',
        '"default_key"',
    ],
    'CVE-2025-47818': [
        '"hotspot" "fallback"',
        '"/api/v1/hotspot"',
        '"default" "hotspot" "credentials"',
        '"/api/v1/wifi"',
        '"hotspot" "config"',
        '"wifi" "credentials"',
    ],
    'CVE-2025-47823': [
        '"ALPR" "v2.0"',
        '"ALPR" "v2.1"',
        '"ALPR" "v2.2"',
        '"/api/v1/alpr"',
        '"license plate" "system"',
        '"LPR" "firmware"',
        '"ALPR" "firmware"',
        '"/alpr" "/api"',
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

def generate_shodan_queries():
    """Generate combined Shodan queries"""
    print("# CVE-2025 Vulnerability + Discovery Shodan Queries")
    print("# ==================================================")
    print()
    for cve, queries in QUERIES.items():
        print(f"# {cve}")
        print(" OR ".join(queries))
        print()
    all_q = []
    for qs in QUERIES.values():
        all_q.extend(qs)
    print("# ALL Queries Combined")
    print(" OR ".join(all_q))

if __name__ == "__main__":
    generate_shodan_queries()
