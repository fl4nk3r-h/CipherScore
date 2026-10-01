# CipherScope: Technical Documentation

> **Current implementation (2026-10-01):** IPsec analysis and passive threat PCAP replay are implemented; live threat ingest requires a configured mirror interface. Six IPsec and four learned threat heads are wired but have no promoted training artifacts. See the [run sequence](docs/RUN_SEQUENCE.md), [API reference](docs/api.md), and [training status](docs/threat_training.md). The architecture material below also describes planned capabilities.

> **CipherScope** is an IPsec protocol analyzer and security assessment framework with a separate passive threat workflow. The lab generates labeled traffic, and the analyzer reports observable evidence, rule-based assessments, and model predictions when trained artifacts are available.

This folder is the engineering source of truth for the proposed system. The slide deck in `app/` summarizes the idea. These documents give the detail needed to build it.

| # | Document | What it covers |
|---|----------|----------------|
| 1 | [ARCHITECTURE.md](.docs/ARCHITECTURE.md) | High-Level Design (HLD): context, containers, data flow, deployment topologies, quality attributes |
| 2 | [LOW_LEVEL_DESIGN.md](.docs/LOW_LEVEL_DESIGN.md) | Low-Level Design (LLD): packet parsing, feature algebra, ML models, scoring math, database schema, sequence diagrams |
| 3 | [MODULES.md](.docs/MODULES.md) | Specification of each module (M1–M6 plus platform services): responsibilities, interfaces, dependencies |
| 4 | [API_REFERENCE.md](.docs/API_REFERENCE.md) | REST, WebSocket, and internal gRPC/stream contracts with request/response schemas |
| 5 | [REPO_STRUCTURE.md](.docs/REPO_STRUCTURE.md) | Monorepo layout, ownership, and naming and coding conventions |
| 6 | [IMPLEMENTATION_STRATEGY.md](.docs/IMPLEMENTATION_STRATEGY.md) | Phased roadmap, milestones, testing, MLOps, risk register, definition of done |

---

## 1. Problem to requirement mapping

| Problem requirement | Delivered by | Doc reference |
|---|---|---|
| (a) VPN Testbed Generation: Tunnel/Transport, AES-128/256, AES-GCM, AES-CBC+HMAC, DH groups, PFS on/off, IPv4/IPv6, traffic types | **M1 LabForge** | MODULES §M1, LLD §2 |
| (b) Traffic Capture: IKE, ESP, AH, normal traffic via Wireshark/tcpdump/custom | **M2 CaptureMesh** | MODULES §M2, LLD §3 |
| (c) AI Protocol Identification: IPsec, IKE version, mode, enc/auth algorithm, key exchange, SA characteristics, traffic type in ESP | **M3 Evidence Fusion + M4 Classifier Ensemble** | LLD §4–§6 |
| (d) Security Assessment: crypto strength, compliance, SA params, key lifetime, replay protection, PFS, cipher suite, metadata exposure | **M5 Posture Engine** | LLD §7 |
| (e) Security score, traffic analysis, metadata inference, Executive and Technical Report, Risk Score, Threat Matrix, AI Confidence | **M6 Report Studio + Dashboard** | LLD §8, API §9 |
| Deliverables: prototype, AI engine, dashboard, report, video, documentation, dataset | Entire platform | IMPLEMENTATION_STRATEGY §6 |

## 2. Glossary

| Term | Meaning |
|---|---|
| **IKE** | Internet Key Exchange (v1: RFC 2409, v2: RFC 7296). Negotiates the Security Associations. |
| **ESP** | Encapsulating Security Payload (RFC 4303), IP protocol 50. |
| **AH** | Authentication Header (RFC 4302), IP protocol 51. |
| **SA / CHILD_SA** | Security Association: one-directional crypto state identified by an SPI. |
| **SPI** | Security Parameter Index, a 32-bit identifier in every ESP/AH packet. |
| **PFS** | Perfect Forward Secrecy: a fresh DH exchange on each CHILD_SA rekey. |
| **NAT-T** | NAT Traversal (RFC 3948): ESP encapsulated in UDP/4500. |
| **ICV** | Integrity Check Value, the authentication tag at the end of ESP. |
| **TFC** | Traffic Flow Confidentiality padding (RFC 4303 §2.7). |
| **Finding** | A single assessed fact with severity, likelihood, confidence, and evidence. |
| **Evidence** | A reference to the packets, fields, or features that support a finding. |
| **Posture** | The aggregated security state of a tunnel, gateway, or estate. |
| **Conformal set** | A set of labels guaranteed to contain the truth with probability ≥ 1−α. |

## 3. Scope of this repository

This repository now contains a working IPsec analysis service, strongSwan lab, and a passive threat replay/mirror workflow. The machine-learning registries are still untrained pending sufficient valid, independently split data. See [threat detection and training](docs/threat_training.md) for collection, model gates, API controls, and current verification limits. The `.docs/` design documents describe broader target architecture and may contain proposed paths.

## 4. Two-person team split (equal burden)

The MVP implementation is split between two engineers with **equal workload and no skill assumptions**: **Person A — Testbed & Data** (`lab/`, `capture/`, `ml/`, `models/`, `dataset/`; milestones M-A, M-B, M-D) and **Person B — Engine & Product** (`analyzer/`, `rules/`, `api/`, `web/`; milestones M-C, M-E, M-F). Ownership, the frozen interface contract, and the week-by-week plan are in [`docs/team_split.md`](docs/team_split.md). Every module folder also carries an `agent.md` pinning its MVP responsibilities, inputs, outputs, and boundaries.
