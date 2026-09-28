"""parse → features → infer → posture → report (repo.md §4, mvp.md §8 sequence).

def run_analysis(pcap_path, rule_pack="ipsec-baseline", on_progress=noop) -> AnalysisResult:
    packets = reader.stream(pcap_path)
    sas, ike_msgs = sa_tracker.build(demux.classify(packets))
    on_progress("parsed", 0.30)
    windows = flow_windows.extract(sas)
    structure = esp_structure.analyze(sas)
    on_progress("features", 0.50)
    inferences = ensemble.infer(sas, ike_msgs, structure, windows)
    on_progress("inferred", 0.70)
    findings = rule_engine.evaluate(inferences, rule_pack)
    posture = score.compute(findings)
    on_progress("assessed", 0.85)
    reports = report.render.all(inferences, findings, posture)
    on_progress("completed", 1.0)
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path

from analyzer import config
from analyzer.features import esp_structure, flow_windows
from analyzer.infer import ensemble, rules_based
from analyzer.models import AnalysisResult, Finding, InferenceSet, TaggedValue
from analyzer.parse import demux, ike, reader, sa_tracker
from analyzer.parse.esp import parse_esp
from analyzer.posture import compliance, exposure, matrix, rule_engine, score
from analyzer.report import build, export, render


def _noop(stage: str, frac: float) -> None:
    _ = stage, frac


def run_analysis(pcap_path: Path, rule_pack: str = config.DEFAULT_RULE_PACK,
                 on_progress: Callable[[str, float], None] = _noop,
                 out_dir: Path | None = None,
                 analysis_id: str | None = None) -> AnalysisResult:
    on_progress = on_progress or _noop
    # Callers (the API job runner) may pin the analysis id so reports, DB rows,
    # and SSE streams all reference the same analysis.
    analysis_id = analysis_id or f"an_{uuid.uuid4().hex[:8]}"

    # --- M3: parse ---------------------------------------------------------
    buckets = demux.classify(reader.stream(pcap_path))
    ike_sessions: dict[tuple, ike.IKESession] = {}
    for pkt in buckets[demux.ProtocolClass.IKE]:
        ike.parse_ike_message(pkt, ike_sessions)
    esp_packets = [rec for pkt in buckets[demux.ProtocolClass.ESP]
                   if (rec := parse_esp(pkt))] + [
        rec for pkt in buckets[demux.ProtocolClass.ESP_IN_UDP]
        if (rec := parse_esp(pkt, udp_encapsulated=True))
    ]
    tracker = sa_tracker.build(esp_packets, ike_sessions)
    on_progress("parsed", 0.30)

    # --- M3: features -------------------------------------------------------
    windows: list[dict] = []
    structures = {}
    offsets_by_spi = {}
    for spi, track in tracker.sas.items():
        recs = [r for r in esp_packets if r.spi == spi]
        windows.extend(flow_windows.extract(recs, sa_id=f"0x{spi:08x}"))
        structures[spi] = esp_structure.analyze(recs)
        offsets_by_spi[spi] = esp_structure.size_offsets(recs)
    on_progress("features", 0.50)

    # --- M4: infer ----------------------------------------------------------
    ike_version_inf = rules_based.ike_version(tracker.ike_sessions)
    ike_suite_inf = rules_based.ike_sa_suite(tracker.ike_sessions)
    ike_enc_chosen = ike_suite_inf.get("enc").value if ike_suite_inf.get("enc") else None

    sas = []
    for spi, track in tracker.sas.items():
        struct = structures.get(spi, esp_structure.StructureResult(
            cipher_mode=None, icv_len=None, consistency=0.0))
        offsets = offsets_by_spi.get(spi, {})
        sa = ensemble.infer_sa(track, struct, tracker, [],
                               models_dir=config.MODELS_DIR,
                               offsets=offsets,
                               ike_enc_chosen=ike_enc_chosen)
        # SA characteristics from the tracker (§3.3 Step 3 table).
        life = sa_tracker.spi_lifetime_s(track)
        # A sub-second lifetime (single burst) is not an observable rekey
        # interval — report unknown rather than a meaningless 0.
        life = life if life and life >= 1.0 else None
        sa.rekey_interval_s = TaggedValue(
            value=round(life) if life else None,
            tag="observed" if life else "unknown",
            confidence=1.0 if life else 0.0)
        sa.replay_window = TaggedValue(
            value=sa_tracker.replay_window_inferred(track),
            tag="inferred" if track.replay_resets else "unknown",
            confidence=1.0 if track.replay_resets else 0.0)
        sa.esn = TaggedValue(
            value=track.esn_supported if track.esn_supported else None,
            tag="observed" if track.esn_supported else "unknown",
            confidence=1.0 if track.esn_supported else 0.0)
        sas.append(sa)
    inferences = InferenceSet(
        ike_version=ike_version_inf,
        ike_suite=ike_suite_inf,
        sas=sas,
    )
    on_progress("inferred", 0.70)

    # --- M5: posture --------------------------------------------------------
    findings: list[Finding] = rule_engine.evaluate(inferences, config.RULES_DIR, rule_pack)
    ai_conf = max((sa.traffic.p for sa in sas if sa.traffic), default=0.0)
    posture = score.compute(findings, ai_confidence=ai_conf)
    posture.threat_matrix = matrix.build(findings)
    for sa in sas:
        compliance.evaluate(sa)
        exposure.assess(sa)
    on_progress("assessed", 0.85)

    # --- M6: reports --------------------------------------------------------
    out_dir = out_dir or (config.REPORTS_DIR / analysis_id)
    context = build.build_context(AnalysisResult(
        analysis_id=analysis_id, status="completed", inferences=inferences,
        findings=findings, posture=posture))
    render.all_reports(context, out_dir)
    export.export_report_json(context, out_dir)
    export.export_findings_csv(context, out_dir)
    on_progress("completed", 1.0)

    return AnalysisResult(
        analysis_id=analysis_id,
        status="completed",
        inferences=inferences,
        findings=findings,
        posture=posture,
    )
