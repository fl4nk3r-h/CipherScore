"""SA tracker (mvp.md §3.3, Step 3): groups packets by SPI, links rekeys,
computes lifetimes, and runs replay checks.

SA characteristics to surface (mvp.md §1.1(c), §3.3): SPIs, lifetimes, rekeys,
PFS, ESN, NAT-T.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from analyzer.parse.esp import ESPRecord
from analyzer.parse.ike import IKESession


@dataclass
class SATrack:
    spi: int
    peers: list[str]
    first_ts: float | None = None
    last_ts: float | None = None
    packet_count: int = 0
    seqs: list[int] = field(default_factory=list)
    lengths: list[int] = field(default_factory=list)
    udp_encapsulated: bool = False
    rekey_of: int | None = None       # previous SPI this SA replaced
    replay_resets: int = 0
    esn_supported: bool = False       # extended sequence numbers suspected


@dataclass
class TrackerResult:
    sas: dict[int, SATrack]
    ike_sessions: list[IKESession]


def build(esp_packets: list[ESPRecord], ike_sessions: dict[tuple, IKESession]) -> TrackerResult:
    by_spi: dict[int, SATrack] = {}
    for rec in esp_packets:
        tr = by_spi.setdefault(rec.spi, SATrack(spi=rec.spi, peers=[rec.src, rec.dst]))
        tr.first_ts = rec.ts if tr.first_ts is None else min(tr.first_ts, rec.ts)
        tr.last_ts = rec.ts if tr.last_ts is None else max(tr.last_ts, rec.ts)
        tr.packet_count += 1
        tr.seqs.append(rec.seq)
        tr.lengths.append(rec.length)
        tr.udp_encapsulated = tr.udp_encapsulated or rec.udp_encapsulated

    # Rekey detection: a new SPI appearing after an old one stopped, with the
    # same peer pair, links the two SAs (mvp.md §3.3 "a new SPI appears").
    order = sorted(by_spi.values(), key=lambda t: t.first_ts or 0)
    for later in order:
        for earlier in order:
            if earlier is later or earlier.rekey_of is not None:
                continue
            if (earlier.last_ts is not None and later.first_ts is not None
                    and later.first_ts >= earlier.last_ts
                    and set(earlier.peers) == set(later.peers)):
                later.rekey_of = earlier.spi
                break

    # Replay checks (mvp.md §3.3 "Sequence gaps / resets"): sequence numbers
    # repeating or resetting without an SPI change; large seqs suggest ESN.
    for tr in by_spi.values():
        for prev, cur in zip(tr.seqs, tr.seqs[1:]):
            if cur < prev and prev - cur > 0x7FFFFFFF:
                tr.replay_resets += 1
        if any(s > 0xFFFFFFFF for s in tr.seqs):
            tr.esn_supported = True

    return TrackerResult(sas=by_spi, ike_sessions=list(ike_sessions.values()))


def spi_lifetime_s(tr: SATrack) -> float | None:
    """First to last packet of the SPI -> effective key lifetime (mvp.md §3.3)."""
    if tr.first_ts is None or tr.last_ts is None:
        return None
    return tr.last_ts - tr.first_ts


def replay_window_inferred(tr: SATrack) -> int | None:
    """0 when repeats/resets without SPI change were observed; else unknown."""
    return 0 if tr.replay_resets else None


def group_windows(tracks: dict[int, SATrack]) -> dict[int, list[SATrack]]:
    return defaultdict(list, {spi: [t] for spi, t in tracks.items()})
