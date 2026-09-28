#!/bin/bash
# Demo script for the demonstration video (mvp.md §10) — runs the exact sequence:
# 1. Show the problem: raw ESP capture in Wireshark shows only SPIs and seq numbers.
# 2. Show the lab: profiles p03 (weak) and p07 (strong), run VoIP + Web on both.
# 3. Analyze: upload the PCAPs (progress stream shows parse -> infer -> assess -> report).
# 4. Weak tunnel (p03): score ~40, grade E; findings DH 2, SHA1-96, PFS off;
#    VoIP predicted at 0.9 confidence though fully encrypted (metadata exposure).
# 5. Strong tunnel (p07): score ~90, grade A; PQ-readiness info + TFC recommendation.
# 6. Ground truth vs prediction on the Lab screen (per-field match rate).
# 7. Reports: Executive PDF, then Technical PDF (evidence to packet numbers).
# 8. Live mode: start a VoIP call through the tunnel, predictions update every 10 s.
set -euo pipefail
STEP="${1:-all}"

case "$STEP" in
  lab)
    echo "[demo 2] running weak (p03) and strong (p07) profiles with VoIP + Web"
    make lab-up
    make lab-run PROFILES=p03,p07 TRAFFIC=voip,web
    ;;
  analyze)
    echo "[demo 3] analyzing latest p03/p07 sessions"
    python -m analyzer.cli "$(ls -t data/sessions/p03-voip-*/*.pcapng | head -1)" --out data/reports/p03
    python -m analyzer.cli "$(ls -t data/sessions/p07-voip-*/*.pcapng | head -1)" --out data/reports/p07
    ;;
  sanity)
    echo "[demo 6] ground truth vs predicted over all lab sessions"
    python scripts/sanity_check.py
    ;;
  seed)
    echo "[demo] seeding 3 pre-analyzed captures"
    python scripts/seed_demo_data.py
    ;;
  live)
    echo "[demo 8] live mode: start a VoIP call through the tunnel; dashboard /live updates every 10 s"
    docker compose -f docker-compose.yml up -d
    echo "open http://localhost:3000/live and CS_LIVE_ENABLED=true in .env"
    ;;
  all|*)
    bash "$0" lab
    bash "$0" analyze
    bash "$0" sanity
    bash "$0" seed
    ;;
esac
