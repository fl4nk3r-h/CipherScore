"""Profile YAML -> strongSwan config (mvp.md §3.1).

Tunnel mode renders through templates/swanctl.conf.j2; IKEv1 profiles
additionally render templates/ipsec.conf.ikev1.j2.
"""
from __future__ import annotations

import pathlib
import re
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader

TEMPLATES = pathlib.Path(__file__).resolve().parent.parent / "templates"

ALLOWED_KEYS = {
    "id", "ike_version", "mode", "ip_family", "nat_t", "ike_proposal",
    "esp_proposal", "pfs", "ike_lifetime", "child_rekey_time",
    "replay_window", "traffic", "duration_per_traffic",
}


def load_profile(path: pathlib.Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    extra = set(data) - ALLOWED_KEYS
    if extra:
        raise ValueError(f"{path.name}: unknown keys {sorted(extra)}")
    return data


def swan_prop(value: str) -> str:
    """Map profile cipher spellings to strongSwan's registered tokens.

    strongSwan registers AES-CBC as plain ``aes128/192/256`` (no mode suffix);
    GCM/CCM keep their keysize suffix. Without this, ``aes128cbc-...`` is
    rejected at load time as an unknown algorithm.
    """
    toks = str(value).split("-")
    return "-".join(t[:-3] if re.fullmatch(r"aes(?:128|192|256)cbc", t) else t for t in toks)


# Peer gateway addresses per lab/network/bridges.yaml. The initiator (gw-a)
# dials gw-b's static address; the responder (gw-b) accepts any peer, because
# docker's address pool is dynamic.
PEER_ADDR = {
    "gw-a": {"ipv4": "172.30.0.3", "ipv6": "fd30::3"},
    "gw-b": {"ipv4": "%any", "ipv6": "%any"},
}


def select_profiles(profiles_dir: pathlib.Path, spec: str) -> list[dict[str, Any]]:
    """spec is 'all' or 'p01,p07'. Profiles validate against lab/profiles/_schema.json."""
    files = sorted(p for p in profiles_dir.glob("p*.yaml"))
    if spec != "all":
        wanted = {s.strip() for s in spec.split(",") if s.strip()}
        files = [p for p in files if yaml.safe_load(p.read_text())["id"] in wanted]
    return [load_profile(p) for p in files]


def render_config(profile: dict[str, Any], psk: str = "lab-only-psk",
                  role: str = "gw-a") -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), keep_trailing_newline=True)
    env.filters["swan_prop"] = swan_prop
    if profile["ike_version"] == 1:
        tpl = env.get_template("ipsec.conf.ikev1.j2")
    else:
        tpl = env.get_template("swanctl.conf.j2")
    fam = "ipv6" if profile["ip_family"] == "ipv6" else "ipv4"
    remote_id = "gw-b" if role == "gw-a" else "gw-a"
    # Traffic selectors are per-side and per-mode: tunnel profiles protect the
    # client/server stubs (10.1<->10.2, fd01<->fd02); transport profiles
    # protect the gateway addresses themselves (bridges.yaml static IPs).
    if profile["mode"] == "transport":
        nets = (("fd30::2/128", "fd30::3/128") if fam == "ipv6"
                else ("172.30.0.2/32", "172.30.0.3/32"))
    else:
        nets = (("fd01::/64", "fd02::/64") if fam == "ipv6"
                else ("10.1.0.0/24", "10.2.0.0/24"))
    local_ts, remote_ts = nets if role == "gw-a" else (nets[1], nets[0])
    return tpl.render(profile=profile, psk=psk, peer_addr=PEER_ADDR[role][fam],
                      local_id=role, remote_id=remote_id,
                      local_ts=local_ts, remote_ts=remote_ts)
