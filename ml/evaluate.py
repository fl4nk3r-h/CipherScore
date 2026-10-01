"""Summarize held-out IPsec metrics from promoted model artifacts."""
from __future__ import annotations

import json
from pathlib import Path

TASKS = ("mode", "cipher", "integ", "pfs", "dh_group", "traffic")


def main() -> None:
    root = Path("models")
    registry = json.loads((root / "registry.json").read_text())
    metrics = {}
    for task in TASKS:
        version = registry.get(task)
        path = root / task / str(version) / "metrics.json" if version else None
        metrics[task] = json.loads(path.read_text()) if path and path.exists() else {
            "status": "not_trained"}
    report = Path("ml/reports")
    report.mkdir(exist_ok=True)
    (report / "metrics_eval.json").write_text(json.dumps(metrics, indent=2))
    lines = ["# CipherScope IPsec model card", "", "## Intended use", "",
             "Passive IPsec SA and encrypted traffic classification. Predictions are evidence, not proof.",
             "", "## Training and validation", "",
             "Lab PCAPs require IKE plus at least 20 ESP packets. Profiles are disjoint across",
             "fitting, probability calibration, conformal calibration, and testing.", "",
             "| Head | Version | Macro F1 | ECE | Coverage |", "|---|---|---:|---:|---:|"]
    for task, row in metrics.items():
        lines.append(f"| {task} | {registry.get(task) or 'untrained'} | "
                     f"{row.get('macro_f1', '—')} | {row.get('ece', '—')} | "
                     f"{row.get('conformal_coverage', '—')} |")
    lines += ["", "## Limits", "",
              "Key size cannot be read from ESP bytes. PFS and CHILD_SA DH are unknown",
              "without a captured rekey. Lab-only training may not generalize to other VPNs."]
    (report / "model_card.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
