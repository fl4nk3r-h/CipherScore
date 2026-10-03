"""ESP cipher / integrity / key-size inference (mvp.md §3.4 table).

| ESP cipher mode (CBC/GCM)      | Model prediction when promoted; structural guesses abstain on ambiguity |
| ESP integrity / ICV length     | Model prediction or supported AEAD inference             |
| ESP key size (128/256)         | **Cannot be observed from ESP bytes.** Inferred from the IKE SA choice (same-suite prior) and the profile-trained model | lower confidence, shown explicitly |
"""
from __future__ import annotations

from analyzer.features.esp_structure import StructureResult
from analyzer.models import TaggedValue

MIN_STRUCTURAL_CONSISTENCY = 0.95


def cipher_mode(struct: StructureResult, model=None,
                features: dict[str, float] | None = None) -> TaggedValue:
    if struct.cipher_mode is None or (model is None and
                                     struct.consistency < MIN_STRUCTURAL_CONSISTENCY):
        return TaggedValue(value=None, tag="unknown", confidence=0.0)
    # CBC-compatible lengths are also possible under GCM (notably fixed-size
    # VoIP packets). Compatibility alone cannot establish the ESP cipher.
    if model is None and struct.cipher_mode == "CBC":
        return TaggedValue(value=None, tag="unknown", confidence=0.0)
    p = struct.consistency
    if model is not None and features is not None:
        p_model = float(model.predict_proba([list(features.values())])[0][1])
        p = 0.7 * struct.consistency + 0.3 * p_model
    return TaggedValue(value=struct.cipher_mode, tag="inferred", confidence=round(p, 4))


def integrity(struct: StructureResult) -> TaggedValue:
    """Abstain when ciphertext lengths cannot establish an integrity family."""
    if struct.consistency < MIN_STRUCTURAL_CONSISTENCY:
        return TaggedValue(value=None, tag="unknown", confidence=0.0)
    if struct.cipher_mode == "GCM":
        return TaggedValue(value="AEAD", tag="inferred", confidence=round(struct.consistency, 4))
    # An ICV length hypothesis cannot identify a hash from ciphertext lengths.
    return TaggedValue(value=None, tag="unknown", confidence=0.0)


def key_size(ike_enc_chosen: str | None, model=None,
             features: dict[str, float] | None = None) -> TaggedValue:
    """Key size (128/256) is NOT observable from ESP bytes.

    Inferred from the IKE SA choice (same-suite prior) and the profile-trained
    model. Lower confidence, shown explicitly (§3.4, §13: "Never presented as
    observed").
    """
    bits = None
    prior = 0.5
    if ike_enc_chosen:
        if "-256" in ike_enc_chosen:
            bits, prior = 256, 0.7
        elif "-128" in ike_enc_chosen:
            bits, prior = 128, 0.7
    if model is not None and features is not None:
        p256 = float(model.predict_proba([list(features.values())])[0][1])
        bits = 256 if p256 >= 0.5 else 128
        prior = 0.5 * prior + 0.5 * p256
    if bits is None:
        return TaggedValue(value=None, tag="unknown", confidence=0.0)
    return TaggedValue(value=bits, tag="inferred", confidence=round(prior, 4))
