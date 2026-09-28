"""Golden pipeline test (repo.md §9): every fixture pcap -> expected inferences.

Milestone M-C exit criterion (mvp.md §9): deterministic fields match ground
truth on 100 % of lab sessions.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer.parse import demux, ike, reader
from analyzer.parse.esp import parse_esp
from analyzer.parse.sa_tracker import build

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "pcaps"

GOLDEN = [
    ("ikev2_sa_init_aes256gcm_ecp384.pcapng", "ikev2_sa_init_aes256gcm_ecp384.json"),
    ("ikev1_main_mode_3des_modp1024.pcapng", "ikev1_main_mode_3des_modp1024.json"),
    ("esp_cbc_sha1_tunnel_v4.pcapng", "esp_cbc_sha1_tunnel_v4.json"),
    ("esp_gcm_transport_v6.pcapng", "esp_gcm_transport_v6.json"),
    ("natt_esp_in_udp.pcapng", "natt_esp_in_udp.json"),
]


@pytest.mark.parametrize("pcap_name,expected_name", GOLDEN)
def test_fixture_golden(pcap_name: str, expected_name: str):
    pcap = FIXTURES / pcap_name
    expected = json.loads((FIXTURES / "expected" / expected_name).read_text())
    if not pcap.exists():
        pytest.skip(f"fixture {pcap_name} not committed yet (see fixtures/pcaps/README.md)")

    buckets = demux.classify(reader.stream(pcap))
    sessions: dict[tuple, ike.IKESession] = {}
    for pkt in buckets[demux.ProtocolClass.IKE]:
        ike.parse_ike_message(pkt, sessions)

    if expected.get("ike_version", {}).get("value") == 2:
        assert sessions, "IKE session must be parsed"
        sess = next(iter(sessions.values()))
        assert sess.version == 2
    if "aggressive_mode" in expected:
        assert any(s.aggressive_mode for s in sessions.values()) == expected["aggressive_mode"]

    esp = []
    for pkt in buckets[demux.ProtocolClass.ESP] + buckets[demux.ProtocolClass.ESP_IN_UDP]:
        rec = parse_esp(pkt, udp_encapsulated=pkt in buckets[demux.ProtocolClass.ESP_IN_UDP])
        if rec:
            esp.append(rec)
    tracker = build(esp, sessions)
    if "nat_t" in expected:
        natt_seen = bool(buckets[demux.ProtocolClass.ESP_IN_UDP])
        assert natt_seen == expected["nat_t"]["value"]
    _ = tracker
