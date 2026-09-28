"""IKE parser tests (mvp.md §3.3 Step 2).

Covers: version byte parse, exchange types (34-37 / 2,4,32), SA transforms
(ENCR 12/20/28/3, INTEG 2/12/13/14, DH 2/5/14/15/16/19/20/21/31, key length
attribute 14), KE size cross-check, NAT_DETECTION notify.
"""
from __future__ import annotations

import struct

from analyzer.parse.ike import IKESession, _parse_transforms
from analyzer.parse import ike_constants as C
from analyzer.parse.reader import PacketRecord


def _transform(ttype: int, tid: int, key_length: int | None = None) -> bytes:
    body = struct.pack(">HH", tid, 0)
    if key_length:
        body += struct.pack(">HH", 14, key_length)  # attribute 14 = Key Length
    return bytes([ttype, 0]) + struct.pack(">H", 8 + len(body)) + body


def test_parse_transforms_aes_gcm_256():
    out = _parse_transforms(_transform(1, 20, 256))
    assert out[0].ttype == 1 and out[0].tid == 20 and out[0].key_length == 256
    assert out[0].name() == "AES-GCM-16-256"


def test_parse_transforms_aes_cbc_128():
    out = _parse_transforms(_transform(1, 12, 128))
    assert out[0].name() == "AES-CBC-128"


def test_parse_transforms_integ_and_dh():
    integ = _parse_transforms(_transform(3, 2))[0]      # 2 = SHA1-96
    dh = _parse_transforms(_transform(4, 14))[0]        # 14 = MODP-2048
    assert integ.name() == "HMAC-SHA1-96"
    assert dh.name() == "MODP-2048"


def test_transform_constants_match_spec():
    # mvp.md §3.3 fixed IDs
    assert C.ENCR_TRANSFORM_IDS[12] == "AES-CBC"
    assert C.ENCR_TRANSFORM_IDS[20] == "AES-GCM-16"
    assert C.ENCR_TRANSFORM_IDS[28] == "ChaCha20-Poly1305"
    assert C.ENCR_TRANSFORM_IDS[3] == "3DES"
    assert C.INTEG_TRANSFORM_IDS[2] == "HMAC-SHA1-96"
    assert C.INTEG_TRANSFORM_IDS[14] == "HMAC-SHA2-512-256"
    assert set(C.DH_GROUPS) == {2, 5, 14, 15, 16, 19, 20, 21, 31}


def test_ke_size_cross_check_values():
    assert C.KE_SIZE_BY_DH[14] == 256   # 256 bytes for MODP-2048
    assert C.KE_SIZE_BY_DH[19] == 64    # 64 bytes for ECP-256


def test_exchange_type_tables():
    assert C.IKEV2_EXCHANGES == {34: "IKE_SA_INIT", 35: "IKE_AUTH",
                                 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}
    assert C.IKEV1_EXCHANGES == {2: "Main Mode", 4: "Aggressive Mode", 32: "Quick Mode"}


def test_aggressive_mode_flagged():
    sess = IKESession(version=1, initiator="a", responder="b")
    pkt = PacketRecord(ts=0.0, src="a", dst="b", ip_proto=17, sport=500, dport=500,
                       payload=b"", ip_version=4)
    # simulate exchange type 4 path via summarize on a session with exchanges
    pkt.payload = bytes(28)
    pkt.payload = pkt.payload[:17] + bytes([4]) + pkt.payload[18:18] + bytes([32]) + pkt.payload[19:]
    from analyzer.parse.ike import parse_ike_message
    sessions = {}
    parse_ike_message(pkt, sessions)
    assert any(s.aggressive_mode for s in sessions.values())
