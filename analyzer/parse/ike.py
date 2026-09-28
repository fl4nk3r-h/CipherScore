"""IKEv1 + IKEv2 parser (mvp.md §3.3, Step 2).

IKE_SA_INIT is sent in cleartext, so the MVP reads directly:

* **IKE version** from the header version byte (major 1 or 2) and exchange type
  (IKEv2: 34 IKE_SA_INIT, 35 IKE_AUTH, 36 CREATE_CHILD_SA, 37 INFORMATIONAL;
  IKEv1: 2 Main Mode, 4 Aggressive, 32 Quick Mode).
* **IKE SA proposal offered and chosen**: SA payload transforms are Type 1 ENCR
  (12 AES-CBC, 20 AES-GCM-16, 28 ChaCha20-Poly1305, 3 3DES) with Key Length
  attribute 14, Type 2 PRF, Type 3 INTEG (2 SHA1-96, 12 SHA2-256-128,
  13 SHA2-384-192, 14 SHA2-512-256), Type 4 DH (2, 5, 14, 15, 16, 19, 20, 21, 31).
  The **responder's** SA_INIT carries the single selected proposal.
* **KE payload size** as a cross-check of the DH group (256 bytes for MODP-2048,
  64 bytes for ECP-256).
* **Vendor ID and NOTIFY payloads** such as NAT_DETECTION_* (indicates NAT-T).
* **IKEv1 Aggressive Mode**, which exposes the identity in cleartext (metadata exposure).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from analyzer.parse import ike_constants as C
from analyzer.parse.reader import PacketRecord


@dataclass
class Transform:
    ttype: int
    tid: int
    key_length: int | None = None

    def name(self) -> str:
        if self.ttype == 1:
            base = C.ENCR_TRANSFORM_IDS.get(self.tid, f"ENCR-{self.tid}")
            return f"{base}-{self.key_length}" if self.key_length else base
        if self.ttype == 3:
            return C.INTEG_TRANSFORM_IDS.get(self.tid, f"INTEG-{self.tid}")
        if self.ttype == 4:
            return C.DH_GROUPS.get(self.tid, f"DH-{self.tid}")
        return f"TYPE{self.ttype}-{self.tid}"


@dataclass
class IKESession:
    version: int                     # 1 or 2 (observed, confidence 1.0)
    initiator: str
    responder: str
    exchanges: list[int] = field(default_factory=list)
    offered: list[Transform] = field(default_factory=list)     # initiator SA_INIT
    chosen: list[Transform] = field(default_factory=list)      # responder SA_INIT
    ke_size: int | None = None       # bytes; cross-checks the DH group
    vendor_ids: list[bytes] = field(default_factory=list)
    nat_detection_seen: bool = False
    aggressive_mode: bool = False    # IKEv1: identity exposed in cleartext


def _parse_transforms(body: bytes) -> list[Transform]:
    out: list[Transform] = []
    off = 0
    while off + 8 <= len(body):
        ttype = body[off]
        _ = body[off + 1]                     # reserved
        tlen = int.from_bytes(body[off + 2:off + 4], "big")
        if tlen < 8:
            break
        tid = int.from_bytes(body[off + 4:off + 6], "big")
        transform = Transform(ttype=ttype, tid=tid)
        # Attributes after the 8-byte transform header; Key Length = attribute type 14.
        aoff = off + 8
        while aoff + 4 <= off + tlen:
            a = int.from_bytes(body[aoff:aoff + 2], "big")
            v = int.from_bytes(body[aoff + 2:aoff + 4], "big")
            if a == C.TRANSFORM_ATTR_KEY_LENGTH:
                transform.key_length = v
            aoff += 4
        out.append(transform)
        off += tlen
    return out


def parse_ike_message(pkt: PacketRecord, sessions: dict[tuple, IKESession]) -> None:
    """Parse one UDP/500 or NAT-T IKE datagram, updating the session record."""
    payload = pkt.payload
    if pkt.sport == 4500 or pkt.dport == 4500:
        if payload[:4] == b"\x00\x00\x00\x00":   # non-ESP marker before IKE
            payload = payload[4:]

    if len(payload) < 28:
        return
    initiator_spi = payload[0:8]
    # RFC 7296 header: 0-7 init SPI, 8-15 resp SPI, 16 next payload,
    # 17 version, 18 exchange type, 19 flags, 20-23 msg id, 24-27 length.
    version_byte = payload[17]
    major, minor = version_byte >> 4, version_byte & 0x0F
    if major not in (1, 2):
        return
    exchange = payload[18]
    msg_id = int.from_bytes(payload[20:24], "big")
    length = int.from_bytes(payload[24:28], "big")

    key = (pkt.src, pkt.dst, initiator_spi)
    sess = sessions.setdefault(key, IKESession(
        version=major, initiator=pkt.src, responder=pkt.dst))
    sess.exchanges.append(exchange)

    if major == 2 and exchange in (34, 35, 36, 37):
        pass  # valid IKEv2 exchange; transforms parsed below when SA payload present
    if major == 1 and exchange == 4:
        sess.aggressive_mode = True             # identity in cleartext (§3.3)

    # Walk payloads: next-payload chain starts at the first payload (byte 28).
    # The payload walk uses the "next payload" byte of each preceding payload.
    np = payload[16]
    off = 28
    while np != 0 and off + 4 <= min(len(payload), length or len(payload)):
        plen = int.from_bytes(payload[off + 2:off + 4], "big")
        if plen < 4:
            break
        body = payload[off + 4:off + plen]
        if np == 33:                             # SA payload (IKEv2)
            sess.offered.extend(_parse_transforms(body))
        elif np == 34:                           # KE payload
            sess.ke_size = len(body) - 8         # minus 4 type + 4 reserved
        elif np == 41:                           # NOTIFY
            if len(body) >= 8:
                mtype = int.from_bytes(body[6:8], "big")
                if mtype in C.NOTIFY_NAT_DETECTION:
                    sess.nat_detection_seen = True
        elif np == 43:                           # VENDOR ID
            sess.vendor_ids.append(body)
        np = payload[off]
        off += plen
    _ = msg_id


def summarize_session(sess: IKESession) -> dict:
    """Flat view used by rules_based inference; chosen transforms win when present."""
    enc = [t for t in sess.offered if t.ttype == 1]
    integ = [t for t in sess.offered if t.ttype == 3]
    dh = [t for t in sess.offered if t.ttype == 4]
    chosen_enc = [t for t in sess.chosen if t.ttype == 1]
    return {
        "ike_version": {"value": sess.version, "tag": "observed", "confidence": 1.0}
        if sess.exchanges else {"value": None, "tag": "unknown", "confidence": 0.0},
        "aggressive_mode": sess.aggressive_mode,
        "nat_t_hint": sess.nat_detection_seen,
        "ke_size": sess.ke_size,
        "enc_offered": [t.name() for t in enc],
        "integ_offered": [t.name() for t in integ],
        "dh_offered": [t.name() for t in dh],
        "enc_chosen": chosen_enc[0].name() if chosen_enc else None,
    }
