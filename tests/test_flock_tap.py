"""
Unit tests for flock_tap.py — the passive Flock camera traffic monitor.

These lock in the detection/accounting behavior, and in particular guard the
three correctness bugs that were fixed:
  * FRP auth-payload detection must fire on data segments, not only on SYN.
  * on_tcp_connect must not inflate bytes_up (real byte counts come from ip.len).
  * connections to a known Flock cloud IP must be flagged even with no SNI/DNS.

Pure-logic tests run everywhere; packet-level tests are skipped when scapy is
not installed.
"""

import pytest

import flock_tap
from flock_tap import FlockTrafficTap

HAVE_SCAPY = flock_tap.HAVE_SCAPY
requires_scapy = pytest.mark.skipif(not HAVE_SCAPY, reason="scapy not installed")

if HAVE_SCAPY:
    from scapy.all import IP, TCP, Raw


def _rebuild(pkt):
    """Serialize and re-parse so IP.len and offsets are populated like a real capture."""
    return IP(bytes(pkt))


@pytest.fixture
def tap():
    return FlockTrafficTap()


# ── _categorize_sni ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("sni,expected", [
    ("login.flocksafety.com", "auth"),
    ("prod-flock-cd-xxx.edge.tenants.auth0.com", "auth"),
    ("flock-hibiki-inbox.s3.us-east-1.amazonaws.com", "s3_upload"),
    ("api.flocksafety.com", "cloud_api"),
    ("websockets.flocksafety.com", "cloud_api"),
    ("example.com", None),
    ("google.com", None),
])
def test_categorize_sni(tap, sni, expected):
    assert tap._categorize_sni(sni) == expected


# ── on_dns_query ────────────────────────────────────────────────────────────

def test_on_dns_query_flocksafety_counts_cloud_dns(tap):
    tap.on_dns_query("api.flocksafety.com", "10.0.0.5")
    assert tap.flow_stats["10.0.0.5"]["cloud_dns"] == 1


def test_on_dns_query_auth0_counts_cloud_dns(tap):
    # Regression: DNS detection used to match only "flocksafety", ignoring the
    # Flock auth0 tenant that the SNI path already recognized.
    tap.on_dns_query("prod-flock-cd-xxx.edge.tenants.auth0.com", "10.0.0.5")
    assert tap.flow_stats["10.0.0.5"]["cloud_dns"] == 1


def test_on_dns_query_learns_resolved_ips(tap):
    # Regression: resolved IPs for Flock domains are unioned into known_flock_ips
    # so later direct-to-IP connections (no SNI/DNS) can still be correlated.
    tap.on_dns_query("api.flocksafety.com", "10.0.0.5", resolved_ips=["203.0.113.9"])
    assert "203.0.113.9" in tap.known_flock_ips


def test_on_dns_query_ignores_non_flock(tap):
    tap.on_dns_query("example.com", "10.0.0.5", resolved_ips=["203.0.113.9"])
    assert tap.flow_stats["10.0.0.5"]["cloud_dns"] == 0
    assert "203.0.113.9" not in tap.known_flock_ips


# ── on_tcp_connect ──────────────────────────────────────────────────────────

def test_on_tcp_connect_does_not_inflate_bytes(tap):
    # Regression: on_tcp_connect used to add a fixed 64 bytes per packet on top
    # of real ip.len accounting, corrupting bandwidth stats.
    tap.on_tcp_connect("10.0.0.5", "8.8.8.8", 51000, 443)
    assert tap.flow_stats["10.0.0.5"]["bytes_up"] == 0
    assert tap.flow_stats["10.0.0.5"]["connections"] == 1


def test_on_tcp_connect_frp_port_sets_tunnel(tap):
    tap.on_tcp_connect("10.0.0.5", "10.0.0.9", 51000, 7000)
    assert tap.flow_stats["10.0.0.5"]["frp_tunnel"] is True


def test_on_tcp_connect_non_frp_port_no_tunnel(tap):
    tap.on_tcp_connect("10.0.0.5", "10.0.0.9", 51000, 8080)
    assert tap.flow_stats["10.0.0.5"]["frp_tunnel"] is False


# ── on_tls_sni ──────────────────────────────────────────────────────────────

def test_on_tls_sni_categories(tap):
    tap.on_tls_sni("login.flocksafety.com", "10.0.0.5", "1.1.1.1")
    tap.on_tls_sni("flock-hibiki-inbox.s3.us-east-1.amazonaws.com", "10.0.0.5", "1.1.1.1")
    tap.on_tls_sni("api.flocksafety.com", "10.0.0.5", "1.1.1.1")
    fs = tap.flow_stats["10.0.0.5"]
    assert fs["auth_tls"] == 1
    assert fs["s3_uploads"] == 1
    assert fs["cloud_api"] == 1


# ── classify_device ─────────────────────────────────────────────────────────

def test_classify_device_cloud_dns(tap):
    tap.flow_stats["ip"]["cloud_dns"] = 1
    assert tap.classify_device("ip") == "CLOUD_CONNECTED"


def test_classify_device_frp(tap):
    tap.flow_stats["ip"]["frp_tunnel"] = True
    assert tap.classify_device("ip") == "CLOUD_CONNECTED"


def test_classify_device_cloud_api_only(tap):
    # The cloud_api-only branch is what surfaces known-Flock-IP correlation.
    tap.flow_stats["ip"]["cloud_api"] = 1
    assert tap.classify_device("ip") == "CLOUD_CONNECTED"


def test_classify_device_local_station(tap):
    tap.flow_stats["ip"]["connections"] = 3
    assert tap.classify_device("ip") == "LOCAL_STATION"


def test_classify_device_offline(tap):
    # Unified vocabulary: no traffic → INDETERMINATE (was OFFLINE_OR_UNMONITORED).
    assert tap.classify_device("ip") == "INDETERMINATE"


# ── classify_camera (fallback via device data) ──────────────────────────────

def test_classify_camera_no_data(tap):
    # Unified vocabulary: no data → INDETERMINATE (was NO_DATA).
    assert tap.classify_camera("10.0.0.99") == "INDETERMINATE"


def test_classify_camera_flock_sni_fallback(tap):
    tap.devices["ip"]["tls_snis"] = [{"sni": "login.flocksafety.com"}]
    assert tap.classify_camera("ip") == "CLOUD_CONNECTED"


def test_classify_camera_local_fallback(tap):
    tap.devices["ip"]["connections"] = [{"dst": "10.0.0.9"}]
    assert tap.classify_camera("ip") == "LOCAL_STATION"


# ── _parse_tcpdump_line ─────────────────────────────────────────────────────

def test_parse_tcpdump_dns(tap):
    line = "13:37:00.000000 IP 10.0.0.5.54321 > 8.8.8.8.53: 12345+ A? api.flocksafety.com. (36)"
    parsed = tap._parse_tcpdump_line(line)
    assert parsed["type"] == "dns"
    assert parsed["src"] == "10.0.0.5"
    assert parsed["query"] == "api.flocksafety.com"


def test_parse_tcpdump_syn(tap):
    line = "13:37:00.000000 IP 10.0.0.5.44444 > 10.0.0.9.7000: Flags [S], seq 1, win 64240, length 0"
    parsed = tap._parse_tcpdump_line(line)
    assert parsed["type"] == "syn"
    assert parsed["dport"] == 7000


def test_parse_tcpdump_other(tap):
    line = "13:37:00.000000 IP 10.0.0.5.44444 > 10.0.0.9.8080: Flags [P.], seq 1:10, length 9"
    parsed = tap._parse_tcpdump_line(line)
    assert parsed["type"] == "other"


def test_parse_tcpdump_garbage(tap):
    assert tap._parse_tcpdump_line("not a tcpdump line") is None


# ── packet-level regression guards (scapy) ──────────────────────────────────

@requires_scapy
def test_byte_accounting_matches_ip_len(tap):
    # bytes_up on the source device must equal the sum of real ip.len values,
    # with no per-packet inflation.
    pkts = [
        _rebuild(IP(src="10.0.0.5", dst="8.8.8.8") / TCP(dport=443, flags="S")),
        _rebuild(IP(src="10.0.0.5", dst="8.8.8.8") / TCP(dport=443, flags="PA") / Raw(b"x" * 100)),
    ]
    expected = sum(int(p[IP].len) for p in pkts)
    for p in pkts:
        tap._handle_packet_scapy(p)
    assert tap.devices["10.0.0.5"]["bytes_up"] == expected


@requires_scapy
def test_frp_payload_detected_on_non_syn(tap):
    # Regression: the FRP auth-payload scan used to be nested in the SYN-only
    # branch, so it never fired (SYN packets carry no payload). A data segment
    # (PSH/ACK) carrying the auth JSON must now be detected.
    pkt = _rebuild(
        IP(src="10.0.0.5", dst="10.0.0.9")
        / TCP(sport=51000, dport=12345, flags="PA")
        / Raw(b'{"proxy_type":"tcp","auth":"token"}')
    )
    tap._handle_packet_scapy(pkt)
    assert tap.flow_stats["10.0.0.5"]["frp_tunnel"] is True
    types = [t["type"] for t in tap.devices["10.0.0.5"]["frp_tunnels"]]
    assert "frp_auth_payload" in types


@requires_scapy
def test_frp_port_detected_on_syn(tap):
    pkt = _rebuild(IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=51000, dport=7000, flags="S"))
    tap._handle_packet_scapy(pkt)
    assert tap.flow_stats["10.0.0.5"]["frp_tunnel"] is True
    types = [t["type"] for t in tap.devices["10.0.0.5"]["frp_tunnels"]]
    assert "frp_tunnel" in types


@requires_scapy
def test_known_flock_ip_correlation(tap):
    # A camera talking straight to a known Flock cloud IP (no SNI, no DNS of its
    # own) must still be counted as cloud_api.
    flock_ip = flock_tap.FLOCK_CLOUD_IPS[0]
    pkt = _rebuild(IP(src="10.0.0.5", dst=flock_ip) / TCP(sport=51000, dport=443, flags="S"))
    tap._handle_packet_scapy(pkt)
    assert tap.flow_stats["10.0.0.5"]["cloud_api"] >= 1
    assert tap.classify_device("10.0.0.5") == "CLOUD_CONNECTED"


# ── audit-integrity: unified verdict vocabulary ─────────────────────────────

def test_device_and_camera_classifiers_agree(tap):
    """Both public names fold into one canonical verdict."""
    tap.flow_stats["10.0.0.5"]["cloud_dns"] = 1
    assert tap.classify_device("10.0.0.5") == tap.classify_camera("10.0.0.5") == "CLOUD_CONNECTED"


# ── audit-integrity: report buckets partition every tracked IP ──────────────

def test_summary_buckets_reconcile(tap):
    tap.start_time = 0
    tap.flow_stats["10.0.0.1"]["cloud_dns"] = 1        # cloud
    tap.flow_stats["10.0.0.2"]["connections"] = 2      # local
    _ = tap.flow_stats["10.0.0.3"]                      # indeterminate (touched only)
    s = tap.generate_report()["summary"]
    assert s["counts_reconcile"] is True
    assert s["cloud_connected"] + s["local_station"] + s["indeterminate"] == s["total_ips_tracked"]


def test_indeterminate_device_still_counted(tap):
    """Regression: the old report dropped NO_DATA/OFFLINE from every bucket."""
    tap.start_time = 0
    _ = tap.flow_stats["10.0.0.9"]
    assert tap.generate_report()["summary"]["indeterminate"] == 1


# ── audit-integrity: CLOUD_IP evidence is recorded ──────────────────────────

@requires_scapy
def test_cloud_ip_contact_recorded_for_evidence(tap):
    dst = flock_tap.FLOCK_CLOUD_IPS[0]
    pkt = _rebuild(IP(src="192.168.1.120", dst=dst) / TCP(sport=47000, dport=443, flags="A"))
    tap._handle_packet_scapy(pkt)
    assert dst in tap.devices["192.168.1.120"]["cloud_ip_contacts"]


# ── audit-integrity: memory capping keeps counters exact ────────────────────

@requires_scapy
def test_samples_capped_but_counter_exact():
    tap = FlockTrafficTap(max_samples=3)
    for i in range(10):
        pkt = _rebuild(IP(src="192.168.1.130", dst="10.0.0.20") /
                       TCP(sport=48000 + i, dport=8080, flags="S"))
        tap._handle_packet_scapy(pkt)
    dev = tap.devices["192.168.1.130"]
    assert len(dev["connections"]) == 3          # sample list bounded
    assert dev["counts"]["conn"] == 10           # counter exact
    rep = tap.generate_report()
    assert rep["devices"]["192.168.1.130"]["connections_count"] == 10


# ── audit-integrity: FRP auth stores a descriptor, not raw payload ──────────

@requires_scapy
def test_frp_auth_stores_descriptor_not_payload(tap):
    pkt = _rebuild(IP(src="192.168.1.140", dst="10.0.0.30") /
                   TCP(sport=49000, dport=8080, flags="PA") /
                   Raw(load=b'{"proxy_type":"tcp","secret":"topsecret"}'))
    tap._handle_packet_scapy(pkt)
    rec = [f for f in tap.devices["192.168.1.140"]["frp_tunnels"]
           if f["type"] == "frp_auth_payload"][0]
    assert "payload_preview" not in rec
    assert rec["matched_keyword"] == "proxy_type"
    assert rec["payload_len"] == 41
    assert "topsecret" not in str(rec)   # secret bytes must not be retained


# ── audit-integrity: optional non-Flock IP redaction ────────────────────────

@requires_scapy
def test_redaction_hashes_non_flock_ip_keeps_flock_clear():
    tap = FlockTrafficTap(redact_non_flock_ips=True)
    flock = flock_tap.FLOCK_CLOUD_IPS[0]
    p1 = _rebuild(IP(src="192.168.1.150", dst="8.8.8.8") / TCP(sport=50000, dport=8080, flags="S"))
    tap._handle_packet_scapy(p1)
    assert tap.devices["192.168.1.150"]["connections"][0]["dst"].startswith("redacted:")
    p2 = _rebuild(IP(src="192.168.1.151", dst=flock) / TCP(sport=50001, dport=7000, flags="S"))
    tap._handle_packet_scapy(p2)
    assert tap.devices["192.168.1.151"]["frp_tunnels"][0]["dst"] == flock


# ── audit-integrity: destination summary is metadata-only ───────────────────

@requires_scapy
def test_destination_summary_is_metadata_only(tap):
    tap.start_time = 0
    for i in range(6):   # clear the <5-packet filter
        tap._handle_packet_scapy(
            _rebuild(IP(src="192.168.1.160", dst="10.0.0.40") /
                     TCP(sport=51000 + i, dport=8080, flags="S")))
    tap.on_tls_sni("api.flocksafety.com", "192.168.1.160", "10.0.0.40")
    tap.devices["192.168.1.160"]["tls_snis"].append(
        {"timestamp": 0, "src": "192.168.1.160", "dst": "10.0.0.40", "sni": "api.flocksafety.com"})
    tap.devices["192.168.1.160"]["counts"]["sni"] += 1
    dsum = tap.generate_report()["devices"]["192.168.1.160"]["destination_summary"]
    assert set(dsum.keys()) == {"dns_domains", "tls_snis", "flock_cloud_ips"}
    assert "api.flocksafety.com" in dsum["tls_snis"]
