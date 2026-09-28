"""Deterministic Scapy generator for the 5 reference pcaps (repo.md §9).

Ground truth comes from the construction parameters below — never from the
analyzer. Run:  python tests/fixtures/make_fixtures.py
Idempotent: regenerating produces byte-identical pcaps (fixed epoch, no OS
randomness in payloads).
"""
from __future__ import annotations

import json
from pathlib import Path

from scapy.all import IP, UDP, IPv6, Raw, wrpcap

HERE = Path(__file__).parent
PCAPS = HERE / "pcaps"
EXPECTED = PCAPS / "expected"

# --- IKEv2 header/building helpers (RFC 7296) -------------------------------

def ike_hdr(exchange: int, flags: int = 0x20) -> bytes:
    """28-byte IKE header: init SPI 8 | resp SPI 8 | np 1 | ver 1 | exch 1
    | flags 1 | msgid 4 | len 4."""
    return (b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"\x00" * 8 +
            bytes([33, 0x20, exchange, flags]) +
            (0).to_bytes(4, "big") + (28).to_bytes(4, "big"))


def ike_payload(np_next: int, ptype: int, body: bytes, total_len: int) -> bytes:
    """Prepend a payload header (np 1 | crit 1 | len 2) and patch the header length."""
    hdr = ike_hdr(34)
    payload = bytes([np_next, 0]) + (8 + len(body)).to_bytes(2, "big") + body
    msg = hdr + payload
    # patch total length (last 4 bytes of the 28-byte header)
    msg = msg[:24] + len(msg).to_bytes(4, "big")
    _ = total_len
    return msg


def transform(ttype: int, tid: int, key_length: int | None = None) -> bytes:
    body = tid.to_bytes(2, "big") + b"\x00\x00"
    if key_length is not None:
        body += (14).to_bytes(2, "big") + key_length.to_bytes(2, "big")
    return bytes([ttype, 0]) + (8 + len(body)).to_bytes(2, "big") + body


def sa_payload(transforms: list[bytes]) -> bytes:
    # Proposal: pnum 1 | proto 1 (IKE) | spisize 4 | num_t
    tpart = b"".join(transforms)
    proposal = bytes([1, 1, 4, len(transforms)]) + (0).to_bytes(2, "big") + tpart
    return proposal


def ke_payload(dh_group: int, ke_size: int) -> bytes:
    body = dh_group.to_bytes(2, "big") + b"\x00\x00" + b"\xAB" * ke_size
    return bytes([0, 0]) + (8 + len(body)).to_bytes(2, "big") + body


def notify_payload(protocol: int, mtype: int) -> bytes:
    body = bytes([protocol, 4, 0, 0]) + mtype.to_bytes(2, "big")
    return bytes([0, 0]) + (8 + len(body)).to_bytes(2, "big") + body


def esp_packet(spi: int, seq: int, esp_len: int) -> bytes:
    """ESP segment of exactly esp_len bytes (SPI 4 + seq 4 + filler)."""
    return spi.to_bytes(4, "big") + seq.to_bytes(4, "big") + b"\x00" * (esp_len - 8)


# --- Fixture builders --------------------------------------------------------

def build_ikev2_sa_init() -> None:
    """IKEv2 SA_INIT: AES-GCM-16 (20) key 256, PRF SHA384, DH 20 (ECP-384, KE 96),
    NAT_DETECTION notify."""
    sa = sa_payload([transform(1, 20, 256), transform(2, 7), transform(4, 20)])
    ke = ke_payload(20, 96)
    ntf = notify_payload(1, 16388)          # NAT_DETECTION_SOURCE_IP
    # chain: SA -> KE -> N -> 0
    msg = ike_hdr(34)
    p1 = bytes([34, 0]) + (8 + len(sa)).to_bytes(2, "big") + sa
    p2 = bytes([41, 0]) + (8 + len(ke)).to_bytes(2, "big") + ke
    p3 = bytes([0, 0]) + (8 + len(ntf)).to_bytes(2, "big") + ntf
    msg = msg + p1 + p2 + p3
    msg = msg[:24] + len(msg).to_bytes(4, "big")
    pkt = IP(src="172.30.0.2", dst="172.30.0.3") / UDP(sport=500, dport=500) / Raw(msg)
    wrpcap(str(PCAPS / "ikev2_sa_init_aes256gcm_ecp384.pcapng"), [pkt])


def build_ikev1_main_mode() -> None:
    """IKEv1 Main Mode (exchange 2) with 3DES + MODP-1024 offer."""
    # v1 ISAKMP header: init spi 8 | resp spi 8 | np 1 | ver 0x10 | exch 2 | flags 0
    # | msgid 4 | len 4
    sa = sa_payload([transform(1, 3, None), transform(4, 2)])
    msg = (b"\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11" + b"\x00" * 8 +
           bytes([1, 0x10, 2, 0x00]) + (0).to_bytes(4, "big") + (0).to_bytes(4, "big"))
    msg += bytes([0, 0]) + (8 + len(sa)).to_bytes(2, "big") + sa
    msg = msg[:24] + len(msg).to_bytes(4, "big")
    pkt = IP(src="172.30.0.2", dst="172.30.0.3") / UDP(sport=500, dport=500) / Raw(msg)
    wrpcap(str(PCAPS / "ikev1_main_mode_3des_modp1024.pcapng"), [pkt])


def build_esp_cbc_sha1_tunnel_v4() -> None:
    """ESP: CBC hypothesis — ESP 84 = 8 (hdr) + 16 (IV) + 48 (payload)
    + 12 (ICV/SHA1-96); wire 104 with the IPv4 header."""
    pkts = [IP(src="172.30.0.2", dst="172.30.0.3", proto=50) / Raw(esp_packet(0xC3A1F00D, seq, 84))
            for seq in range(1, 21)]
    wrpcap(str(PCAPS / "esp_cbc_sha1_tunnel_v4.pcapng"), pkts)


def build_esp_gcm_transport_v6() -> None:
    """ESP over IPv6: GCM hypothesis — ESP 92 = 8 (hdr) + 8 (IV) + 48 (ct)
    + 4 (pad/nh) + 24 (ICV); wire 132 with the IPv6 header. CBC cannot explain
    this length (no icv candidate aligns), so GCM/ICV-24 is unique."""
    pkts = [IPv6(src="fd30::2", dst="fd30::3", nh=50) / Raw(esp_packet(0x0000A1B2, seq, 92))
            for seq in range(1, 21)]
    wrpcap(str(PCAPS / "esp_gcm_transport_v6.pcapng"), pkts)


def build_natt_esp_in_udp() -> None:
    """UDP/4500: ESP-in-UDP (SPI first 4 bytes non-zero) + IKE behind the
    0x00000000 non-ESP marker."""
    esp_in_udp = esp_packet(0x0000BEEF, 1, 64)                    # non-zero SPI
    ike = ike_hdr(34)                                             # behind marker
    pkts = [
        IP(src="172.30.0.2", dst="172.30.0.3") / UDP(sport=4500, dport=4500) / Raw(esp_in_udp),
        IP(src="172.30.0.2", dst="172.30.0.3") / UDP(sport=4500, dport=4500) /
        Raw(b"\x00\x00\x00\x00" + ike),
    ]
    wrpcap(str(PCAPS / "natt_esp_in_udp.pcapng"), pkts)


BUILDERS = {
    "ikev2_sa_init_aes256gcm_ecp384.pcapng": build_ikev2_sa_init,
    "ikev1_main_mode_3des_modp1024.pcapng": build_ikev1_main_mode,
    "esp_cbc_sha1_tunnel_v4.pcapng": build_esp_cbc_sha1_tunnel_v4,
    "esp_gcm_transport_v6.pcapng": build_esp_gcm_transport_v6,
    "natt_esp_in_udp.pcapng": build_natt_esp_in_udp,
}

EXPECTED_FILES = [
    "ikev2_sa_init_aes256gcm_ecp384.json",
    "ikev1_main_mode_3des_modp1024.json",
    "esp_cbc_sha1_tunnel_v4.json",
    "esp_gcm_transport_v6.json",
    "natt_esp_in_udp.json",
]


def main() -> None:
    PCAPS.mkdir(parents=True, exist_ok=True)
    EXPECTED.mkdir(parents=True, exist_ok=True)
    for name, builder in BUILDERS.items():
        builder()
        print(f"[fixtures] wrote {name}")
    _ = EXPECTED_FILES   # expected JSON already committed; reviewed by hand
    print("[fixtures] done")


if __name__ == "__main__":
    main()
    _ = json
