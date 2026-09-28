# CipherScope MVP — API reference (subset)

Mirrors `mvp.md` §5 exactly. Base URL `http://localhost:8000/api/v1`. The full contract is API_REFERENCE.md in the full platform; the MVP implements only this subset.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/captures` | Upload PCAP (multipart). Returns `capture_id` |
| `POST` | `/analyses` | `{capture_id \| lab_session_id, rule_pack}`. Starts a job and returns `analysis_id` |
| `GET` | `/analyses/{id}` | Status + summary (score, risk, confidence) |
| `GET` | `/analyses/{id}/sas` | SA table with inference tags |
| `GET` | `/analyses/{id}/traffic` | Traffic classification + histograms |
| `GET` | `/analyses/{id}/findings` | Findings with evidence |
| `GET` | `/analyses/{id}/threat-matrix` | 5 × 5 matrix |
| `GET` | `/analyses/{id}/reports/{executive\|technical}.pdf` | Download report |
| `GET` | `/analyses/{id}/events` | SSE progress stream |
| `GET` | `/lab/profiles` | List profiles |
| `POST` | `/lab/runs` | `{profile_ids, traffic_types}`. Starts a lab run |
| `GET` | `/lab/sessions` | Sessions + ground truth |
| `POST` | `/live/start` · `/live/stop` | Live mode on a configured interface |
| `GET` | `/live/events` | SSE stream of window predictions |

## Sample summary response (mvp.md §5)

```json
{
  "analysis_id": "an_01J9Z3",
  "status": "completed",
  "security_score": 58,
  "grade": "D",
  "risk_score": 21.4,
  "ai_confidence": 0.91,
  "sa_count": 4,
  "findings": { "critical": 0, "high": 2, "medium": 3, "low": 1 },
  "top_findings": ["CRYPTO-001 Weak DH group 2", "PFS-001 PFS disabled"]
}
```

## Sample SA record (mvp.md §5)

```json
{
  "spi": "0xc3a1f00d",
  "peers": ["172.30.0.2", "172.30.0.3"],
  "ike_version": { "value": 2, "tag": "observed", "confidence": 1.0 },
  "mode": { "value": "tunnel", "tag": "inferred", "confidence": 0.96 },
  "enc": { "value": "AES-CBC", "tag": "inferred", "confidence": 0.99 },
  "key_bits": { "value": 256, "tag": "inferred", "confidence": 0.74 },
  "integ": { "value": "HMAC-SHA1-96", "tag": "inferred", "confidence": 0.98 },
  "dh_group": { "value": 2, "tag": "observed", "confidence": 1.0 },
  "pfs": { "value": false, "tag": "inferred", "confidence": 0.88 },
  "rekey_interval_s": { "value": 3600, "tag": "observed", "confidence": 1.0 },
  "traffic": { "top": "voip", "p": 0.87, "conformal_set": ["voip", "messaging"] }
}
```

Notes: uploads are capped at 500 MB (§13); live mode requires `CS_LIVE_ENABLED=true` and is disabled by default (§13); progress SSE events carry `stage`/`frac` per the §8 sequence.
