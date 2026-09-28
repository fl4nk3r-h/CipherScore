# agent.md — `web/` (Next.js 16 dashboard)

**Source of truth: `docs/mvp.md` §0, §4 (screens), §5 (API consumed), §8 (flow), §10 (demo behavior); layout per `docs/repo.md` §8. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Provide the MVP's interactive dashboard: upload/live entry points, per-analysis drill-down with inference tags and confidence, reports, the lab accuracy-proof screen, and the SSE live view.

## What this folder must do (from mvp.md)

**Implement exactly the 9 screens (§4):**

| # | Screen | Key elements |
|---|---|---|
| 1 | **Overview** | Recent analyses, overall Security Score trend, top findings across captures |
| 2 | **New Analysis** | Drag-and-drop PCAP upload · or pick a lab session · or start live capture on an interface |
| 3 | **Analysis Detail: Summary** | Score gauge, Risk Score, AI Confidence meter, Threat Matrix heatmap |
| 4 | **Analysis Detail: Tunnels/SAs** | Table of SAs (SPI, peers, mode, cipher, integrity, DH, PFS, lifetime), each value tagged **Observed / Inferred / Unknown** with confidence |
| 5 | **Analysis Detail: Traffic** | Traffic-type donut, per-window timeline, packet-size and IAT histograms, **metadata exposure panel** |
| 6 | **Analysis Detail: Findings** | Filterable findings list → evidence drawer (packets, features, rule, references, fix) |
| 7 | **Reports** | Preview and download of the Executive and Technical PDFs + JSON |
| 8 | **Lab** | Profile matrix, run a profile, session list with **ground-truth vs predicted** comparison (accuracy proof) |
| 9 | **Live** | Rolling **10 s** windows streamed over SSE with evolving predictions and alerts |

Screen 8 must show **predicted versus actual** for lab sessions so the model's accuracy is visible during the demo (§4, §10 step 6).

## Backend contract (§5 — consume only this API)

Base URL `http://localhost:8000/api/v1` (`NEXT_PUBLIC_API_URL`). Endpoints: `POST /captures`, `POST /analyses`, `GET /analyses/{id}` (summary: score, grade, risk, confidence, counts, top findings), `/sas`, `/traffic`, `/findings`, `/threat-matrix`, `/reports/{executive|technical}.pdf`, `/events` (SSE), `/lab/profiles`, `/lab/runs`, `/lab/sessions`, `/live/start|stop|events`.

Progress stream stages (§8): parsed 0.30 → features 0.50 → inferred 0.70 → assessed 0.85 → completed 1.0. SA values arrive as `{value, tag, confidence}`; traffic as `{top, p, conformal_set}` — render unknowns honestly, never as facts (§3.4 credibility contract).

## Stack (§0, repo.md §12)

Next.js 16 + React 19, shadcn/ui primitives, Recharts, SWR, `lucide-react`, Tailwind.

## Inputs / outputs

- **Inputs:** the §5 REST + SSE API.
- **Outputs:** the screens above; nothing is computed client-side — the dashboard renders API results only.

## Boundaries (do not do)

- No analysis logic, no pcap parsing in the browser.
- No new backend endpoints; if data is missing, call the existing API (repo.md §7/§8 split).
- No auth/login screens — single analyst MVP (§1.2).
- Don't hide "unknown"/low-confidence values — display them with their tags (§3.4).
