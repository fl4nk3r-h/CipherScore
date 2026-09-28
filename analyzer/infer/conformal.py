"""Split-conformal prediction sets (mvp.md §3.4 training loop, step 4):
"compute conformal quantiles on a held-out calibration fold (α = 0.1)"; traffic
panel shows conformal sets (§3.6 technical report; sample SA record §5)."""
from __future__ import annotations

import numpy as np


def conformal_quantile(scores: np.ndarray, alpha: float = 0.1) -> float:
    """q-hat from held-out calibration scores (nonconformity)."""
    n = len(scores)
    level = min(1.0, np.ceil((n + 1) * (1 - alpha)) / n)
    return float(np.quantile(scores, level, method="higher"))


def prediction_set(proba: np.ndarray, qhat: float) -> list[int]:
    """Class indices whose cumulative proba mass is within q-hat (APS method)."""
    order = np.argsort(proba)[::-1]
    total, out = 0.0, []
    for idx in order:
        out.append(int(idx))
        total += float(proba[idx])
        if total >= 1.0 - qhat:
            break
    return out
