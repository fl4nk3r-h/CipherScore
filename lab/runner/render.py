"""Profile YAML -> strongSwan config (mvp.md §3.1).

Tunnel mode renders through templates/swanctl.conf.j2; IKEv1 profiles
additionally render templates/ipsec.conf.ikev1.j2.
"""
from __future__ import annotations

import pathlib
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


def select_profiles(profiles_dir: pathlib.Path, spec: str) -> list[dict[str, Any]]:
    """spec is 'all' or 'p01,p07'. Profiles validate against lab/profiles/_schema.json."""
    files = sorted(p for p in profiles_dir.glob("p*.yaml"))
    if spec != "all":
        wanted = {s.strip() for s in spec.split(",") if s.strip()}
        files = [p for p in files if yaml.safe_load(p.read_text())["id"] in wanted]
    return [load_profile(p) for p in files]


def render_config(profile: dict[str, Any], psk: str = "lab-only-psk") -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), keep_trailing_newline=True)
    if profile["ike_version"] == 1:
        tpl = env.get_template("ipsec.conf.ikev1.j2")
    else:
        tpl = env.get_template("swanctl.conf.j2")
    return tpl.render(profile=profile, psk=psk)
