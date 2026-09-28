"""IKE constants read directly from captures (mvp.md §3.3, Step 2)."""
from __future__ import annotations

# IKEv2 header: version byte (major 1 or 2); exchange types:
IKEV2_EXCHANGES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

# IKEv1 exchange types:
IKEV1_EXCHANGES = {
    2: "Main Mode",
    4: "Aggressive Mode",
    32: "Quick Mode",
}

# SA payload transform types:
TRANSFORM_TYPES = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "DH",
}

# Type 1 ENCR transform IDs named in mvp.md §3.3:
ENCR_TRANSFORM_IDS = {
    3: "3DES",
    12: "AES-CBC",
    20: "AES-GCM-16",
    28: "ChaCha20-Poly1305",
}

# Key Length attribute (type 14) carries the AES key size in bits.
TRANSFORM_ATTR_KEY_LENGTH = 14

# Type 3 INTEG transform IDs named in mvp.md §3.3:
INTEG_TRANSFORM_IDS = {
    2: "HMAC-SHA1-96",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}

# Type 4 DH groups named in mvp.md §3.3:
DH_GROUPS = {
    2: "MODP-1024",
    5: "MODP-1536",
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
    31: "Curve25519",
}

# KE payload size cross-checks (mvp.md §3.3): e.g. 256 bytes for MODP-2048,
# 64 bytes for ECP-256.
KE_SIZE_BY_DH = {
    2: 128, 5: 192, 14: 256, 15: 384, 16: 512,
    19: 64, 20: 96, 21: 132, 31: 32,
}

# Notify payloads of interest (mvp.md §3.3): NAT_DETECTION_* indicates NAT-T.
NOTIFY_NAT_DETECTION = {16388, 16389, 16390, 16391}  # SRC_IP, DST_IP, SRC_PORT, DST_PORT
