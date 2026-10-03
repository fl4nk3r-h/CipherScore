"""Gateway evidence must never be mistaken for passive inference."""
from analyzer.lab_evidence import (new_rekey_child, normalize_labels,
                                   parse_legacy_state, parse_vici_raw)
from api.routers import lab
from pathlib import Path
from types import SimpleNamespace
import json
import yaml
import pytest


LEGACY = """p01: #29, ESTABLISHED, IKEv2
  AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  p01-child: #41, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-128/HMAC_SHA2_256_128
    in  cdde516d, 100 bytes
    out c6b051c5, 100 bytes
"""

RAW = """list-sa event {p01 {dh-group=MODP_2048 child-sas {p01-child-1
{name=p01-child state=INSTALLED mode=TUNNEL protocol=ESP spi-in=cdde516d
spi-out=c6b051c5 encr-alg=AES_CBC encr-keysize=128 integ-alg=HMAC_SHA2_256_128}}}}
list-sas reply {}
"""


def test_old_labels_use_esp_for_child_group_without_mutating_manifest():
    old = {"ike_proposal": "aes256gcm16-ecp256",
           "esp_proposal": "aes256gcm16-curve25519", "pfs": True, "dh_group": 19}
    assert normalize_labels(old)["ike_dh_group"] == 19
    assert normalize_labels(old)["dh_group"] == 31
    assert old["dh_group"] == 19
    assert normalize_labels({**old, "pfs": False})["dh_group"] is None


def test_legacy_sa_requires_spi_and_keeps_pfs_configured(monkeypatch):
    labels = {"mode": "tunnel", "enc": "AES-CBC", "key_bits": 128,
              "integ": "sha256", "pfs": True, "dh_group": 14}
    analysis = {"id": "a1", "status": "completed"}
    monkeypatch.setattr(lab.analyses_repo, "sas", lambda _: [{"spi": "0xdeadbeef"}])
    result = lab._verification({"sa_state": LEGACY}, analysis, labels)
    assert result["compared"] == 0
    assert result["fields"]["pfs"]["source"] == "configured"
    monkeypatch.setattr(lab.analyses_repo, "sas", lambda _: [{"spi": "0xcdde516d"}])
    result = lab._verification({"sa_state": LEGACY}, analysis, labels)
    assert result["compared"] == result["matched"] == 4
    assert result["fields"]["pfs"]["match"] is None
    assert result["fields"]["dh_group"]["match"] is None


def test_multiple_spis_must_agree_and_no_first_child_guess(monkeypatch):
    second = LEGACY.replace("cdde516d", "aaaaaaaa").replace("c6b051c5", "bbbbbbbb")\
                   .replace("AES_CBC-128", "AES_GCM_16-256")
    monkeypatch.setattr(lab.analyses_repo, "sas", lambda _: [
        {"spi": "0xcdde516d"}, {"spi": "0xaaaaaaaa"}])
    result = lab._verification({"sa_state": LEGACY + second},
                               {"id": "a1", "status": "completed"},
                               {"mode": "tunnel", "enc": "AES-CBC", "key_bits": 128})
    assert result["fields"]["mode"]["value"] == "tunnel"
    assert result["fields"]["enc"]["source"] == "unavailable"
    assert result["fields"]["key_bits"]["source"] == "unavailable"


def test_vici_child_group_is_not_ike_group_and_failed_rekey_is_unknown(monkeypatch):
    before = parse_vici_raw(RAW)
    assert len(before) == 1
    assert before[0]["dh_group"] is None
    assert before[0]["integ"] == "sha256"
    after = parse_vici_raw(RAW.replace("cdde516d", "11223344")
                           .replace("c6b051c5", "55667788")
                           .replace("integ-alg=", "dh-group=CURVE25519 integ-alg="))
    child = new_rekey_child(before, after)
    assert child["dh_group"] == 31
    assert new_rekey_child(before, before) is None
    monkeypatch.setattr(lab.analyses_repo, "sas", lambda _: [{"spi": "0x11223344"}])
    evidence = {"before": before, "after": after,
                "rekey": {"status": "failed", "child": child}}
    labels = {"pfs": True, "dh_group": 31}
    failed = lab._verification({"gateway_evidence": evidence},
                               {"id": "a1", "status": "completed"}, labels)
    assert failed["fields"]["pfs"]["source"] == "unavailable"
    evidence["rekey"]["status"] = "observed"
    verified = lab._verification({"gateway_evidence": evidence},
                                 {"id": "a1", "status": "completed"}, labels)
    assert verified["fields"]["pfs"]["value"] is True
    assert verified["fields"]["dh_group"]["value"] == 31
    evidence["rekey"]["child"] = {**child, "dh_group": None}
    assert lab._verification({"gateway_evidence": evidence},
                             {"id": "a1", "status": "completed"},
                             {"pfs": False, "dh_group": None})["fields"]["pfs"]["value"] is False


def test_unsupported_ikev1_text_unavailable_and_ah_has_no_cipher():
    assert parse_legacy_state("Security Associations (1 up): p14[1]: ESTABLISHED, IKEv1") == []
    ah = parse_vici_raw(RAW.replace("protocol=ESP", "protocol=AH")
                        .replace("encr-alg=AES_CBC encr-keysize=128", "integ-alg=HMAC_SHA2_256_128"))
    assert ah[0]["enc"] == "AH"
    assert ah[0]["key_bits"] is None


@pytest.mark.parametrize("rekey_ok", [True, False])
def test_new_capture_records_rekey_group_and_keeps_pcap_for_reanalysis(tmp_path, monkeypatch, rekey_ok):
    from analyzer.parse import demux, reader
    from lab.runner import orchestrate

    profile_path = next(Path("lab/profiles").glob("p01-*.yaml"))
    profile = yaml.safe_load(profile_path.read_text())
    sid = "p01-bulk-0001"
    capture = tmp_path / "data/sessions" / sid / f"{sid}.pcapng"
    capture.parent.mkdir(parents=True)
    capture.write_bytes(b"saved PCAP")
    after = RAW.replace("cdde516d", "11223344").replace("c6b051c5", "55667788")\
               .replace("integ-alg=", "dh-group=MODP_2048 integ-alg=")
    snapshots = iter((RAW, after))

    def fake_sh(command, **_kwargs):
        if "--raw" in command:
            return SimpleNamespace(stdout=next(snapshots), stderr="", returncode=0)
        if command[-2:] == ["swanctl", "--list-sas"]:
            return SimpleNamespace(stdout="p01 TUNNEL AES_CBC", stderr="", returncode=0)
        if "--rekey" in command:
            return SimpleNamespace(stdout="", stderr="rekey rejected", returncode=0 if rekey_ok else 1)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(orchestrate, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(orchestrate, "_sh", fake_sh)
    monkeypatch.setattr(orchestrate.time, "sleep", lambda _: None)
    monkeypatch.setattr(reader, "stream", lambda _: iter(()))
    monkeypatch.setattr(demux, "classify", lambda _: {
        demux.ProtocolClass.ESP: [object()] * 20,
        demux.ProtocolClass.ESP_IN_UDP: [],
        demux.ProtocolClass.AH: [],
        demux.ProtocolClass.IKE: [object()],
    })
    orchestrate._run_one(profile, "bulk", "data/sessions", sid)
    manifest = json.loads((capture.parent / "manifest.json").read_text())
    assert manifest["gateway_evidence"]["rekey"]["status"] == ("observed" if rekey_ok else "failed")
    if rekey_ok:
        assert manifest["gateway_evidence"]["rekey"]["child"]["dh_group"] == 14
    assert manifest["labels"]["ike_dh_group"] == 14
    assert manifest["labels"]["dh_group"] == 14
    assert capture.read_bytes() == b"saved PCAP"
