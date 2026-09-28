# CipherScope MVP — demo video script

Follows `mvp.md` §10 verbatim (8 steps). Exit criterion (§9 M-F): runs without manual fixes.

1. **Show the problem.** Open a raw ESP capture in Wireshark: only SPIs and sequence numbers are visible. Reading it takes an expert.
2. **Show the lab.** Pick profiles `p03` (weak) and `p07` (strong) on the Lab screen. Run VoIP + Web on both.
3. **Analyze.** Upload the resulting PCAPs, or click "analyze session". The progress stream shows parse → infer → assess → report.
4. **Weak tunnel (p03).** Score around 40, grade E. Findings: DH group 2, SHA1-96, PFS off. The traffic panel predicts **VoIP at 0.9 confidence** even though every packet is encrypted, which is the metadata exposure finding.
5. **Strong tunnel (p07).** Score around 90, grade A. Remaining findings: lack of PQ readiness (info) and traffic still classifiable (recommendation: TFC padding).
6. **Ground truth vs prediction.** The Lab screen shows the per-field match rate.
7. **Reports.** Open the Executive PDF (one page of plain language), then the Technical PDF (evidence down to packet numbers).
8. **Live mode.** Start a new VoIP call through the tunnel and watch predictions update every 10 s.

Run it with: `bash scripts/demo.sh all` (steps map to `lab`, `analyze`, `sanity`, `seed`, `live`).
