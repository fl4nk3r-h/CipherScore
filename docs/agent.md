# agent.md — `docs/` (documentation)

**Owners: shared** — `team_split.md` is the authority for who owns which folder (see [team_split.md](./team_split.md)).

**Source of truth: the documents themselves (`mvp.md`, `repo.md`) and their companion references. Nothing here adds, removes, or reinterprets an MVP requirement.**

## Mission

Keep the specification set that every other folder's `agent.md` defers to, plus the demo video script deliverable.

## Contents (repo.md §9 docs/)

| File | Role |
|---|---|
| `mvp.md` | **The MVP specification.** Every folder's agent.md cites it; the traceability matrix in its §11 maps problem-statement items (a)–(e) to components; §14 is the definition of done. |
| `repo.md` | The exact repository layout for this MVP; folder names match the full-platform monorepo so it can grow without restructuring. |
| `api.md` | MVP subset of the API reference (mirrors `mvp.md` §5). To be written from §5 — no endpoint may appear here that is not in §5. |
| `model_card.md` | Symlink/pointer to `../ml/reports/model_card.md` (§3.4 training loop output 5). |
| `demo_video_script.md` | The demo narration built from `mvp.md` §10 (8-step sequence). |

## Boundaries (do not do)

- `mvp.md` and `repo.md` are the source of truth: never edit them to match code; change code to match them.
- Documentation must not promise full-platform features (multi-sensor, Kafka, Postgres, RBAC, deep models, vendor config ingestion) as MVP capabilities — those are deferred (mvp.md §1.2).
