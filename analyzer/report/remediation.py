"""Remediation snippets (repo.md §4): strongSwan config per finding.

The Technical Report includes remediation config snippets for strongSwan
(mvp.md §3.6). Snippets follow the §3.1 swanctl.conf vocabulary (proposals,
esp_proposals, rekey_time, replay_window).
"""
from __future__ import annotations

SNIPPETS = {
    "CRYPTO-001": """# Replace weak DH with an ECC group (RFC 8247 §2.4)
connections.<conn>
  proposals = aes256gcm16-prfsha384-ecp384""",
    "PFS-001": """# Enable PFS: add a DH group to esp_proposals (NIST SP 800-77r1 §4.2)
connections.<conn>.children.<child>
  esp_proposals = aes256gcm16-ecp384""",
    "LIFE-001": """# Shorten CHILD_SA lifetime (rekey at most every 8 h)
connections.<conn>.children.<child>
  rekey_time = 8h""",
    "LIFE-002": """# Shorten IKE SA lifetime (rekey at most every 24 h)
connections.<conn>
  rekey_time = 24h""",
    "REPLAY-001": """# Enable replay protection (window > 0)
connections.<conn>.children.<child>
  replay_window = 64""",
    "META-001": """# Hide inner endpoints: prefer tunnel mode over transport
connections.<conn>.children.<child>
  mode = tunnel""",
    "META-002": """# Avoid IKEv1 Aggressive Mode identity leak: use IKEv2 (or Main Mode)
connections.<conn>
  version = 2""",
    "META-003": """# Add TFC padding so packet sizes stop revealing the application
connections.<conn>.children.<child>
  tfc_padding = mtu""",
}


def snippet_for(rule_id: str) -> str:
    return SNIPPETS.get(rule_id, "# no snippet for this rule yet")
