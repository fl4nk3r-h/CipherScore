"""Lab-only gateway evidence. Never imported by the passive analysis pipeline."""
from __future__ import annotations

import re

GROUPS = {"modp1024": 2, "modp1536": 5, "modp2048": 14,
          "modp3072": 15, "modp4096": 16, "ecp256": 19,
          "ecp384": 20, "ecp521": 21, "curve25519": 31}


def group(proposal: str | None) -> int | None:
    proposal = (proposal or "").lower().replace("_", "").replace("-", "")
    return next((number for name, number in GROUPS.items() if name in proposal), None)


def normalize_labels(labels: dict) -> dict:
    """Fix old manifests in memory; the capture and its manifest stay immutable."""
    result = dict(labels)
    result["ike_dh_group"] = group(result.get("ike_proposal"))
    result["dh_group"] = group(result.get("esp_proposal")) if result.get("pfs") is True else None
    return result


def _spi(value: str | None) -> str | None:
    if not value or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,8}", value):
        return None
    return f"0x{int(value.removeprefix('0x'), 16):08x}"


def _algorithms(proposal: str, protocol: str) -> dict:
    upper = proposal.upper()
    if protocol == "AH":
        enc, bits = "AH", None
    else:
        match = re.search(r"AES_(GCM_16|CBC)-(128|256)", upper)
        enc = f"AES-{match.group(1).replace('_', '-')}" if match else None
        bits = int(match.group(2)) if match else None
    integ = "AEAD" if "GCM" in upper else next(
        (name for token, name in (("SHA2_512", "sha512"), ("SHA2_384", "sha384"),
                                  ("SHA2_256", "sha256"), ("SHA1", "sha1"),
                                  ("SHA_256", "sha256"), ("SHA_1", "sha1"))
         if token in upper), None)
    return {"mode": None, "enc": enc, "key_bits": bits, "integ": integ}


def parse_legacy_state(state: str) -> list[dict]:
    """Parse only installed CHILD_SAs with explicit SPIs from swanctl text."""
    children = []
    current = None
    header = re.compile(r"^\s*\S+:\s*#\d+.*\bINSTALLED,\s*(TUNNEL|TRANSPORT),\s*(ESP|AH):([^\n]+)", re.I)
    for line in state.splitlines():
        match = header.match(line)
        if match:
            if current:
                children.append(current)
            current = {**_algorithms(match.group(3), match.group(2).upper()),
                       "mode": match.group(1).lower(), "spis": []}
            continue
        if current:
            match = re.match(r"^\s*(?:in|out)\s+([0-9a-fA-F]{8})(?:\s|,)", line)
            if match:
                current["spis"].append(_spi(match.group(1)))
            elif re.match(r"^\S+:\s*#", line):
                children.append(current)
                current = None
    if current:
        children.append(current)
    return [child for child in children if child["spis"]]


def parse_vici_raw(raw: str) -> list[dict]:
    """Extract structured CHILD_SA fields from swanctl --list-sas --raw."""
    tokens = re.findall(r"\{|\}|[^\s{}]+", raw.split("list-sas reply", 1)[0])
    if "{" not in tokens:
        return []

    def section(pos: int) -> tuple[dict, int]:
        result = {}
        while pos < len(tokens) and tokens[pos] != "}":
            token = tokens[pos]
            if pos + 1 < len(tokens) and tokens[pos + 1] == "{":
                result[token], pos = section(pos + 2)
            else:
                if "=" in token:
                    key, value = token.split("=", 1)
                    result[key] = value
                pos += 1
        return result, pos + 1

    root, _ = section(tokens.index("{") + 1)
    children = []
    for ike in root.values():
        if not isinstance(ike, dict):
            continue
        for child in ike.get("child-sas", {}).values():
            if not isinstance(child, dict):
                continue
            if child.get("state") != "INSTALLED":
                continue
            spis = [_spi(child.get("spi-in")), _spi(child.get("spi-out"))]
            if not any(spis):
                continue
            alg = child.get("encr-alg", "")
            protocol = child.get("protocol", "ESP").upper()
            bits = child.get("encr-keysize")
            proposal = f"{alg}-{bits}" if bits else alg
            fields = _algorithms(proposal, protocol)
            integrity = child.get("integ-alg")
            if integrity:
                fields["integ"] = _algorithms(integrity, "AH")["integ"]
            dh = child.get("dh-group")
            children.append({**fields, "mode": child.get("mode", "").lower() or None,
                             "spis": [spi for spi in spis if spi],
                             "dh_group": group(dh), "name": child.get("name")})
    return children


def new_rekey_child(before: list[dict], after: list[dict]) -> dict | None:
    old = {spi for child in before for spi in child["spis"]}
    candidates = [child for child in after if any(spi not in old for spi in child["spis"])]
    return candidates[0] if len(candidates) == 1 else None
