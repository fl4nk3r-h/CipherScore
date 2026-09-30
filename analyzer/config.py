"""Central configuration (repo.md §4): paths, thresholds, feature window size."""
from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("CS_DATA_DIR", "./data"))
MODELS_DIR = Path(os.environ.get("CS_MODELS_DIR", "./models"))
RULES_DIR = Path(os.environ.get("CS_RULES_DIR", "./rules"))
# strongSwan profile matrix served by GET /lab/profiles (api/routers/lab.py).
LAB_PROFILES_DIR = Path(os.environ.get("CS_LAB_PROFILES_DIR", "./lab/profiles"))

UPLOADS_DIR = DATA_DIR / "uploads"
SESSIONS_DIR = DATA_DIR / "sessions"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "cipherscope.sqlite3"

# mvp.md §3.3: one FlowWindow per 5 s window of each SA.
FLOW_WINDOW_SECONDS = 5

# mvp.md §3.3: ESP hypothesis tests.
CBC_IV_LEN = 16
CBC_BLOCK = 16
GCM_IV_LEN = 8
GCM_PAD = 4
CANDIDATE_ICV_LENS = (12, 16, 24, 32)

# mvp.md §3.3: first 32 packet sizes and directions feed the traffic classifier.
PACKET_SIZE_HEAD = 32

# mvp.md §3.4: conformal alpha.
CONFORMAL_ALPHA = 0.1

DEFAULT_RULE_PACK = "ipsec-baseline"
