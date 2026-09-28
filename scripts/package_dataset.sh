#!/bin/bash
# Package the dataset deliverable for a release asset (repo.md §9; mvp.md §7).
set -euo pipefail
OUT="${1:-dist/cipherscope-dataset.zip}"

mkdir -p "$(dirname "$OUT")"
# pcaps are huge; the release carries features + labels + splits by default.
# Add dataset/pcaps for the full 5-15 GB deliverable (Git LFS or release asset).
zip -r "$OUT" \
  dataset/README.md \
  dataset/labels.csv \
  dataset/features \
  dataset/splits \
  || { echo "zip failed"; exit 1; }

echo "packaged: $OUT"
echo "note: include dataset/pcaps and dataset/keys in the full release (mvp.md §7)."
