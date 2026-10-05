# CipherScore: Detailed Product Idea Description

AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

This description defines the complete product from the repository architecture, low-level design, module specifications, presentation and problem statement. It covers automated laboratories, distributed capture, evidence fusion, AI, assessment, reporting and enterprise operations. Performance figures are acceptance targets. Engineering documents use the name CipherScope for the product presented as CipherScore.

## 1. The Problem and Product Opportunity

IPsec VPNs connect offices, cloud workloads, remote users and critical infrastructure across untrusted networks. Protection depends on negotiated encryption, integrity, peer authentication, key exchange, forward secrecy and operational policy. A working tunnel can still retain weak proposals, unsuitable key management or excessive metadata exposure. CipherScore addresses this gap between connectivity and assessed security.

Packet tools require specialists to connect decoded fields to tunnel behaviour. Configuration reviews show intended settings but cannot establish every runtime outcome. ESP encryption hides inner protocols, while lengths, timing, direction and exposed addresses can still reveal activity patterns. Analysts need to interpret both what encryption conceals and what the trace exposes.

The product identifies protocols, separates observations from inferences, highlights controls needing confirmation and prioritizes changes. Evidence links to standards and organizational policy support SOC teams, engineers, auditors and management. [RFC 4301](https://www.rfc-editor.org/rfc/rfc4301.html) establishes the IPsec framework; [NIST SP 800-77 Rev. 1](https://csrc.nist.gov/pubs/sp/800/77/r1/final) provides deployment guidance.

## 2. Our Solution and Product Objectives

An analyst uploads PCAP/PCAPNG, selects a lab session or connects an authorized mirror feed. CipherScore builds a tunnel inventory, tracks SA behaviour, predicts hidden characteristics where supported, evaluates controls and recommends fixes. Outputs include Security Score, Risk Score, Threat Matrix, AI Confidence Score, traffic analysis, metadata inference, Executive Report and Technical Report.

Passive mode uses visible fields and encrypted-traffic metadata. Authorized active mode tests gateway proposals; key-assisted mode uses supplied session material to verify protected information. Each source remains identifiable so the analyst can review how a conclusion was obtained.

Six modules cover generation, capture, evidence fusion, classification, assessment and reporting. Five services provide API access, identity/audit, storage, MLOps and integrations. Continuous monitoring, custom policy packs, distributed sensors, model governance and local reporting extend the same workflow across organizations. A useful unknown result preserves trust when evidence cannot establish a property.

## 3. Innovation and Uniqueness

The laboratory-to-assessment loop generates repeatable traffic with independently checked labels, then trains classifiers and tests them against known configurations. It reduces manual annotation and supports reproducible expansion across profiles, vendors and applications.

Protocol-informed inference combines ESP length algebra, encrypted exchange sizes and timing with statistical and sequence models. These features identify plausible configurations; ground-truth validation establishes their usefulness, and overlapping hypotheses remain conditional.

Explicit uncertainty separates observed fields, predictions, active tests and key-assisted verification. Calibration, prediction sets, explanations and abstention prevent conclusions from exceeding evidence. Missing negotiation or rekey packets are visible coverage limitations.

Metadata-leakage assessment measures how much timing and sizes reveal application classes. Padding/shaping experiments test whether countermeasures reduce classification success. Transparent scoring, standards-linked local reports and quantum migration assessment connect this research to enterprise decisions.

## 4. Complete Product Architecture

Collection, streaming, analysis, application and storage scale independently. Edge sensors normalize packets; offline files enter through resumable upload. Both paths share parsers, feature schemas, evidence models, classifiers and rules. Reports use immutable snapshots so later model or policy updates do not silently alter existing results.

| Module | Main responsibility | Product output |
|---|---|---|
| M1 LabForge | Establish VPN configurations and generate traffic | Labeled sessions and datasets |
| M2 CaptureMesh | Acquire files and live mirrored traffic | Packet records and capture segments |
| M3 Evidence Fusion | Parse, track SAs and reconcile sources | Tunnel models and provenance |
| M4 Classifier Ensemble | Infer protocol attributes and traffic classes | Predictions, confidence and explanations |
| M5 Posture Engine | Evaluate policies and aggregate findings | Scores, compliance states and threat matrix |
| M6 Report Studio | Explain results and support investigation | Dashboard, reports and exports |

Rust handles capture-sensitive and parsing work; Python implements feature processing, inference coordination, assessment and reporting. Redis Streams connects stages, FastAPI exposes control and results, PostgreSQL/TimescaleDB stores analysis and time-series metadata, and object storage retains captures and artifacts. Next.js provides the interactive interface. The laboratory and training services operate independently of production observation, preserving the distinction between ground truth and predictions. This structure follows [the product architecture](ARCHITECTURE.md) and [module specifications](MODULES.md).

## 5. LabForge: VPN Testbed Generation

LabForge establishes real IPsec sessions across an expandable configuration matrix. Tunnel profiles use site-to-site gateway pairs with protected hosts behind them. Transport profiles terminate IPsec on communicating hosts. The topology makes the mode difference meaningful and avoids labeling gateway transit traffic as host-to-host transport. Containerlab, Docker, Linux network namespaces and Linux XFRM provide repeatable isolation, addressing and controlled capture locations.

The matrix includes AES-128/256, CBC+HMAC, GCM, PFS on/off, IPv4/IPv6, IKE versions, NAT-T, replay settings and lifetimes. DH variants include legacy MODP-1024/1536, MODP-2048/3072/4096, ECP-256/384/521 and Curve25519. IKE and CHILD_SA proposals vary independently. Strong and deliberately weak profiles test acceptable and problematic deployments; optional AH profiles test authentication-only operation.

The orchestrator validates YAML, expands valid combinations, renders configuration, starts endpoints and waits for negotiated SAs. It captures negotiation, drives traffic, records rekeys and exports gateway state. Failed negotiation, insufficient packets or inconsistent labels reject a session with a reason. Provisioning, negotiation, generation, capture, labeling and validation states support retry/resume without silently reusing damaged data.

Full, pairwise and sampled sweeps control experiment count. Repeated sessions vary seeds, durations, sizes and network conditions; vendor/version profiles test generalization. Usable combinations are counted after compatibility constraints, and dataset size comes from validated runs. Hybrid profiles extend the matrix where supported. Per-profile evidence proves that the intended VPN operated.

## 6. Traffic Generation and Ground-Truth Dataset

Traffic covers every required category: SIPp/RTP VoIP with codec and duration variation; browser-driven web sessions; SMTP/IMAP email with varied attachments; ICMP size/interval sweeps; FFmpeg and HLS/DASH video; and messaging with text, images and voice notes. Bulk transfers add a class and control. Controlled services and authorized external sessions provide both repeatability and deployment diversity.

WhatsApp simulation and genuine traffic are separate sources. Simulations enable controlled experiments; authorized phone/emulator sessions provide application-specific validation. Genuine WhatsApp recognition requires genuine held-out samples. Non-VPN workloads measure what encryption removes and provide IPsec negative controls; mixed-application runs test SAs carrying several activities.

Ground truth combines negotiated gateway state, generator timestamps and controlled-laboratory decryption. strongSwan's [save-keys plugin](https://docs.strongswan.org/docs/latest/plugins/save-keys.html) exports Wireshark-compatible material for label verification. Packet or interval labels associate an activity with the correct SPI and time range, so a later ICMP health check does not inherit a VoIP label. Keys used to validate training labels are excluded from passive inference inputs.

Each dataset release contains capture hashes, manifests, labels, feature tables, split assignments, generator and gateway versions, rejected-session reasons and a dataset card. Laboratory decryption coverage, expected SA counts and recorded rekeys form quality checks. Sensitive keys and personally identifying data have separate access and release policies. This delivers the required training/testing dataset as a reproducible research artifact with known coverage and limitations.

## 7. CaptureMesh: Offline and Live Traffic Acquisition

CaptureMesh accepts PCAP and PCAPNG files, tcpdump or Wireshark-compatible capture rings and authorized SPAN/TAP streams. It retains IKE negotiation, ESP, UDP-encapsulated ESP, optional AH and sampled normal traffic. UDP ports 500/4500 and IP protocol numbers 50/51 guide filtering, followed by validation that distinguishes protocol candidates from confirmed evidence. Keepalives, malformed packets and unrelated traffic using familiar ports receive explicit categories.

The full sensor uses eBPF/XDP filtering and AF_XDP reception where the host and network adapter support them, with an AF_PACKET fallback. A normalized PacketRecord contains timestamp, outer endpoints, ports, IP family, wire length, captured length, protocol, direction, selected header bytes and a flow identifier. Keeping wire length separate from captured bytes allows metadata analysis without retaining full payloads. Raw capture segments remain available under configured evidence-retention rules.

Records are batched by stable tunnel/flow key. Sensors measure drops, queue delay, timestamps and completeness. Under pressure, policy reduces retained bytes or samples data while prioritizing negotiation. Loss and sampling propagate to evidence coverage; negotiation packets cannot be assumed physically lossless.

Offline ingest verifies file structure and checksums, supports resumable uploads and avoids using original filenames as storage paths. Live sensors rotate closed segments, preserve session state across windows and buffer during core outages. NAT-T lengths are normalized consistently with bare ESP, following [RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html). Bounded fragment handling prevents later ciphertext fragments from being interpreted as fresh ESP headers. The resulting capture layer meets both forensic and continuous-monitoring needs.

## 8. Deterministic Protocol Identification

The first analysis tier reads fields that the protocol exposes. The parser validates link-layer and IP framing, follows supported IPv6 extension headers and classifies IKE, ESP, AH, NAT-T keepalives and other traffic. Memory-safe Rust parsing with bounded lengths protects the service from malformed captures. Python bindings expose normalized results to feature processing, and parser errors become recorded evidence rather than guessed fields.

IKE parsing follows the header, payload chain, proposal substructures, transforms and attributes. It correlates request and response using endpoints, initiator/responder SPIs and message IDs. Offered transforms and the responder's selected IKE suite are stored separately. Visible fields identify IKE version, exchange type, encryption and PRF transforms, integrity choices, DH group, key-length attributes, negotiation notifications and implementation hints. IKEv1 Main and Aggressive exchanges have distinct decoding and assessment paths.

The parser respects the division between initial IKE negotiation and protected later exchanges. IKEv2 IKE_AUTH carries peer-authentication information and initial CHILD_SA negotiation under encryption, so passive visibility of the IKE SA is not evidence of every ESP parameter. [RFC 7296](https://www.rfc-editor.org/rfc/rfc7296.html) defines these exchange roles. ESP contributes SPI and sequence metadata; AH contributes authentication-header observations under [RFC 4302](https://www.rfc-editor.org/rfc/rfc4302.html). AH input receives its own association and assessment path, including the absence of confidentiality where encryption is not provided.

## 9. Evidence Fusion and Security Association Tracking

Evidence Fusion builds tunnel, IKE SA and CHILD_SA records. A Security Association (SA) holds directional cryptographic state; its Security Parameter Index (SPI) is scoped to the relevant peers/protocol. Negotiated data or uncertain temporal correlation links directions. Parallel SAs, rekey overlap and reused SPIs remain distinct.

The tracker records first/last observation, packet and byte counts, sequence patterns, SPI replacement and exchange timing. Capture duration is stored separately from a confirmed rekey interval or configured lifetime. A short recording provides a lower bound on an association's observed activity, not proof of its full lifetime. Rekey history links predecessor and replacement records while retaining the supporting events.

Sources are reconciled for the same attribute and scope. Verified data can resolve an inference; accepting a probe suite does not establish its use by an observed tunnel. Conflicts retain both values, timestamps and packet references. Provenance includes capture hash, packet indices, feature version, model bundle and rule revision.

Authorized probes have a target allowlist, rate limits and an authorization reference. Key-assisted analysis keeps supplied material encrypted and short-lived, verifies applicable authentication tags, and retains only necessary derived results. Observed, inferred and unknown tags remain visible throughout the product; additional sources are labeled explicitly. This is the practical meaning of the full design's three analysis modes, allowing confirmation without disguising supporting evidence as passive AI discovery.

## 10. Structural Features: ESP Length, Mode and Rekey Inference

ESP length algebra represents a normalized packet length as L = 8 + IV + C + ICV: eight bytes for SPI and sequence number, an explicit initialization value, encrypted data including the trailer, and an integrity tag where applicable. For a candidate CBC structure, the feature extractor calculates r_h(L) = (L - 8 - IV_h - ICV_h) mod block_h. The fraction of packets consistent with each valid hypothesis, size-difference patterns and length distributions form classifier inputs.

AES-CBC uses block alignment and its specified IV structure; AES-GCM has its own explicit IV and permitted authentication-tag sizes. Candidate definitions therefore follow [RFC 3602](https://www.rfc-editor.org/rfc/rfc3602.html), [RFC 4106](https://www.rfc-editor.org/rfc/rfc4106.html) and [RFC 4868](https://www.rfc-editor.org/rfc/rfc4868.html). NAT-T headers and outer IP framing are removed before the calculation. Truncated or unreassembled packets are excluded from structural voting. Alignment consistency is evidence for a hypothesis, not a calibrated probability or a uniquely identified algorithm.

Mode inference combines length distributions, plausible encapsulation overhead, endpoint roles, peer diversity and relevant confirmed negotiation data. Tunnel mode carries an inner IP packet, whereas Transport mode protects the upper-layer portion under the original IP header. Traffic types, MTU and padding can mimic size offsets, so no single minimum-length threshold establishes mode. Endpoint comparison uses available baseline or authorized supporting evidence; hidden inner addresses are not invented.

For PFS and CHILD_SA DH inference, encrypted rekey message size, direction and timing are compared with controlled examples and candidate key-exchange overheads. Notifications, selectors, cipher padding and IKE SA rekeys can also alter size. The engine therefore requires appropriate exchange correlation and calibrated evidence, returning unknown when an exchange is ambiguous or absent. AES-128 and AES-256 length patterns alone cannot identify the key size. These limits guide confirmation requests and prevent an incomplete capture from producing an unsupported security judgment.

## 11. AI Classifier Ensemble and Encrypted Applications

The second tier uses LightGBM models for structured SA and flow features. Separate heads address mode, cipher family, integrity family, PFS and DH group. The third tier models application sequences using packet length, direction and logarithmically bucketed inter-arrival times. A compact Transformer with the design's four-layer, 128-dimension configuration processes a bounded sequence, while a tabular model handles aggregate statistics. A stacking model combines complementary outputs only after independent validation.

Traffic features include length and timing percentiles, burst counts, active/idle intervals, byte ratios and periodicity. The design starts with bounded sequences such as the first 64 packets and rolling windows. Bidirectional features require a defensibly paired association; a single directional SPI does not provide a real upload/download ratio. Padding, packet loss and mixed applications are represented in evaluation. Traffic predictions remain window-specific so changes within an SA are preserved.

Classes cover VoIP, messaging/WhatsApp where validated, email, web, ICMP, video and bulk transfer, with abstention for unsupported or mixed patterns. Predictions describe application categories from metadata; they do not recover messages or identify malicious content hidden in ESP. Sequence learning is informed by [ET-BERT](https://arxiv.org/abs/2202.06335) and [Deep Packet](https://arxiv.org/abs/1709.02656), while CipherScore's own models use the feature and privacy constraints established for this product. ONNX Runtime provides a common serving format across CPU and optional GPU deployments.

## 12. AI Confidence, Calibration and Explainability

Each prediction includes a selected label, calibrated probabilities, a prediction set, source, explanation and model version. Probability calibration uses independent examples rather than fitting and checking on the same sessions. Conformal calibration then estimates a nonconformity threshold: for a simple score 1 - p(label), labels satisfying the threshold enter the prediction set. Multiple eligible labels express ambiguity and permit abstention.

Nominal 90%/95% coverage depends on exchangeability assumptions. Shift, correlated windows and vendor changes require checking empirical coverage, set size and abstention by class/deployment. A display indicator may reduce certainty for multiple labels, but remains separate from calibrated probability, following [Angelopoulos and Bates](https://arxiv.org/abs/2107.07511).

[SHAP](https://arxiv.org/abs/1705.07874) explains contributions to tree predictions; token attribution can highlight sequence positions relevant to the Transformer. Explanations reveal what influenced a decision without claiming causation. A finding's confidence depends conservatively on the evidence it needs. Overall AI Confidence is presented with assessed coverage and per-head status, rather than taking the highest traffic probability as confidence in the entire security assessment. Missing models or essential features produce unknown values and a clear operational status.

## 13. Training, Evaluation and Model Governance

Training extracts the same feature schema used in serving. Captures are first checked for usable negotiation, protected packets, label consistency and task-specific evidence. PFS and rekey-group labels require verified applicable exchanges. Configuration, session, host and scenario identifiers prevent related windows from crossing dataset partitions. Vendor-held-out evaluations measure whether a model learned transferable behaviour rather than one gateway's defaults.

Fitting, probability calibration, conformal calibration and final testing use separate groups. Metrics include per-class precision/recall, macro-F1, confusion matrices, calibration error, empirical coverage, abstention and class balance. Controlled jitter, loss, MTU changes, fragmentation and padding test robustness; external traces add deployment diversity. [ISCXVPN2016](https://www.unb.ca/cic/datasets/vpn.html) contains OpenVPN traffic, so it supports application research without supplying IPsec cipher, mode, PFS or DH ground truth.

MLflow records dataset hashes, code revision, parameters and metrics. Bundles include estimators, calibrators, ordered features, labels, conformal parameters, model cards, results and signatures. Independent gates and shadow deployment govern promotion; drift triggers review/retraining. Reports retain versions and reanalysis creates new results. Registry declarations and successfully loaded artifacts have separate health states.

## 14. Posture Engine: All Required Assessment Dimensions

The Posture Engine evaluates readable, versioned YAML rules against the fused tunnel model. A rule states its scope, condition, required evidence, minimum confidence, severity, likelihood, references and remediation. A sandboxed interpreter permits defined comparisons and logical operators without executing arbitrary code. IKE and CHILD_SA controls have separate contexts. Organizational requirements are named and versioned rather than presented as universal restrictions. All eight problem-statement dimensions are covered:

1. Cryptographic strength: evaluate established algorithms and key sizes against the selected policy, including legacy encryption and weak key-exchange groups. Unknown ESP key size remains unknown. Hash collision results are not automatically treated as a demonstrated failure of every HMAC use.
2. Configuration compliance: map supported evidence to controls from the selected standards or custom baseline. Results use pass, fail, suspected, unknown and not-applicable states. Missing evidence does not create a pass. [RFC 8221](https://www.rfc-editor.org/rfc/rfc8221.html) and [RFC 8247](https://www.rfc-editor.org/rfc/rfc8247.html) inform ESP/AH and IKE algorithm requirements, alongside organizational deployment policy.
3. SA parameters: evaluate association identity, negotiated mode, suite combinations, NAT traversal and observed lifecycle behaviour. Parallel associations and ESN-related observations receive correct context. An on-wire 32-bit sequence value cannot directly establish unseen ESN high bits.
4. Key lifetime: compare confirmed IKE and CHILD_SA rekey intervals with the applicable time or byte limits. Capture span, observed replacement and configured lifetime remain separate fields. Missing renewal during a short capture becomes a coverage limitation.
5. Replay protection: report duplicates, regressions, resets and wrap-related events per association. Reordering, mirror duplication and loss are considered before alleging failure. Receiver anti-replay settings or acceptance behaviour require confirming evidence; seeing a repeated packet alone does not prove the receiver accepted it.
6. Forward secrecy: assess fresh key-exchange evidence during applicable CHILD_SA renewal, the group used and its policy suitability. Missing or ambiguous rekeys leave PFS unassessed. Initial IKE DH and CHILD_SA rekey PFS are distinct properties.
7. Cipher-suite strength: assess encryption, integrity, key exchange and authentication together, including authenticated-encryption semantics. GCM supplies an integrated authentication tag; an AH-only deployment receives an authentication assessment and an explicit confidentiality status.
8. Metadata exposure: evaluate endpoint visibility, relevant identity or implementation disclosure, application-class inference and resistance to padding/shaping. IKEv1 Aggressive Mode exposure requires evidence of that exchange type. High classification confidence indicates exploitable structure, without proving that TFC padding is absent.

Each result provides supporting packets/features, the policy clause, uncertainty and a proposed fix. Custom packs can express stricter requirements for a workspace. Indian-sector baselines require identified applicable controls and review; an invented generic CERT-In badge cannot establish compliance. Post-quantum readiness is an additional product dimension, complementing the eight required assessments.

## 15. Security Score, Risk Score and Threat Matrix

Scoring is published and reproducible. Following the full low-level design, a finding contributes risk_f = w_severity x likelihood_f x confidence_f. Severity weights are 0 for informational, 1 for low, 3 for medium, 6 for high and 10 for critical findings. These are assessment weights; the resulting risk value is not a measured probability of a future breach.

Within dimension d, saturation is R_d = 1 - product(1 - risk_f / 10). The Security Score is S = 100 x (1 - sum(W_d x R_d)), with dimension weights summing to one. Default weights are crypto 0.20, forward secrecy 0.15, cipher suite 0.15, compliance 0.10, lifetime 0.10, replay 0.10, metadata 0.10, SA parameters 0.05 and quantum readiness 0.05. Workspace changes are recorded, and grading follows published bands. The Risk Score and contributing findings remain available beside the security score.

Repeated observations of one configuration weakness are grouped so directions, packet count and successive rekeys do not multiply the same issue. Assessment coverage is reported separately, and an empty or largely unknown assessment does not receive an unqualified secure verdict. A 5-by-5 matrix places findings by likelihood and impact, with drill-down to evidence and threat mappings.

Metadata leakage is measured using labeled experiments. The design's chance-adjusted indicator compares application macro-F1 with a declared K-class baseline, recording class balance and sample size. For a production tunnel without ground truth, the interface reports inference confidence and exposure indicators rather than a fabricated F1 measurement. Before/after padding experiments test whether recommended countermeasures actually reduce leakage.

## 16. Post-Quantum Readiness and Migration Planning

CipherScore inventories key-establishment and authentication evidence relevant to future cryptographic migration. Long confidentiality requirements can make captured traffic valuable to an adversary who later gains stronger computing capability. [RFC 9370](https://www.rfc-editor.org/rfc/rfc9370.html) provides multiple key exchanges in IKEv2; [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) standardizes ML-KEM. The product relates supported gateway evidence and negotiated exchanges to these mechanisms and the selected CNSA 2.0 policy.

Readiness distinguishes advertised capability, negotiated use and verified deployment configuration. Classical elliptic-curve groups alone do not establish post-quantum resistance. Multiple exchanges are evaluated for their actual algorithms, and key-establishment readiness is separated from signature/authentication readiness. Incomplete passive evidence remains unknown. The output prioritizes gateway compatibility checks, policy changes and controlled migration trials according to data sensitivity and retention. LabForge supplies hybrid scenarios where supported, while [NSA's resources](https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/) guide the relevant policy interpretation.

## 17. Report Studio: Grounded Automated Reporting

Report Studio produces Executive, Technical, Compliance and machine-readable reports from a frozen snapshot. A planner defines sections; retrieval selects findings, packet references and approved clauses from evidence and pgvector. A local model generates constrained narrative. Validators check citations, numbers and supported wording, with bounded retries and template fallback.

The Executive Report gives the score with coverage, major risks, business implications and prioritized actions in plain language. The Technical Report contains tunnel inventory, IKE/CHILD_SA tables, exchange and rekey timelines, traffic windows, inference explanations, full findings, policy mappings and evidence references. It includes model versions, applicability limits and configuration guidance. The Compliance Report provides control-by-control states and unresolved evidence needs.

Jinja2 renders HTML and WeasyPrint produces PDF; JSON, CSV, SARIF and CEF support automation where appropriate. Reported observations, suspicions and confirmations retain their wording and source. The language model explains existing analysis; it cannot choose the risk score or invent protocol facts. Local retrieval, model execution and rendering allow sensitive organizations to generate reports without sending captures or findings to an external AI service.

## 18. Interactive Dashboard and Analyst Experience

Next.js/TypeScript connect investigation, laboratory and governance. Overview shows tunnels, score/coverage trends, findings and leakage/readiness. Capture pages provide upload, history, progress and versioned reanalysis. Live views include predictions, sensor health and capture limitations.

The Tunnel Inspector displays peers, SPIs, IKE and CHILD_SA relationships, proposals, observed timelines and per-attribute source/confidence. Traffic views retain window-level changes, size/timing histograms and prediction sets. Finding drawers show evidence, explanation, standard and remediation. The matrix links directly to relevant findings; compliance views distinguish unknown controls from failures. Reports can be previewed and exported.

LabForge's console provides matrix editing, run queues, dataset browsing and ground-truth comparisons. Model views show bundle health, per-class metrics, calibration and drift. Settings manage workspaces, users, roles, integrations and scoring policy. Management, analysts and auditors see views appropriate to their roles, while the underlying evidence remains consistent across the interface and exported reports.

## 19. Platform Services, Storage and Integrations

P1, the API Gateway, provides validated REST contracts, OpenAPI schemas, progress events and rate limits. P2 supplies OIDC, scoped API keys, RBAC and audit. P3 manages relational metadata, time series, object storage and encrypted key access. P4 governs datasets, training, bundles and promotion. P5 exports findings and integrates with existing security operations.

A canonical schema covers workspaces, captures, analyses, tunnels, IKE SAs, CHILD_SAs, flows, predictions, findings, evidence, scores and reports. PostgreSQL maintains relationships; TimescaleDB stores live trends; pgvector indexes the reporting corpus; MinIO/S3-compatible storage retains large objects. Versioned Pydantic, Protobuf and TypeScript contracts keep representations consistent. Records retain capture, rule and model identifiers for reproduction.

Redis consumer groups connect stages with ordering, acknowledgements and recovery. Idempotent writes handle repeated delivery, and work queues isolate batch/report tasks from live analysis. SIEM/SOAR exports, Zeek/Suricata enrichment, webhooks and ticketing carry evidence into existing response processes. A complementary passive threat workflow can assess visible scans, floods, beaconing, DNS anomalies and suspicious TLS/QUIC metadata; those observations are kept distinct from application predictions inside encrypted ESP.

## 20. Deployment, Platform Security and Operations

Docker-based deployment supports a local analysis workstation or a single server. Enterprise installations use Kubernetes, distributed sensors and independently scaled workers, with database availability and object-store redundancy appropriate to the service. Branch probes can forward compact records and buffer during disconnection. Air-gapped installations package models, the standards corpus and signed updates locally, avoiding an outbound dependency for analysis or reporting.

User access uses OIDC and workspace-scoped RBAC; sensor communication uses mutual TLS. Keys receive encrypted temporary storage and restricted access, while logs redact secrets. Capture retention and header-only collection policies limit unnecessary data exposure. Active testing requires recorded authorization and bounded targets. Supply-chain controls include image/artifact signatures, dependency inventories and vulnerability checks. Prometheus, Grafana and tracing expose packet loss, queue lag, inference latency, report failures and drift, enabling operators to distinguish capture problems from changing security posture.

## 21. Feasibility, Viability, Impact and Benefits

Technical feasibility comes from interoperable open-source components and a repeatable laboratory. Modular contracts allow capture, models, rules and reporting to evolve independently. Commodity deployment and optional accelerated inference support different budgets. Standardized protocol structures provide useful features, while independent vendor and network-condition testing establishes where those features generalize. Operating cost depends on capture volume, retention, redundancy and local model resources.

Recurring review, audit and migration support product viability. Offline assessment extends to continuous monitoring using the same model; SOC/ticketing integration makes findings actionable. An open core can support deployment, policy maintenance and training services, with revenue and savings treated as opportunities requiring validation.

Analysts gain faster triage; engineers gain prioritized fixes; auditors gain reproducible evidence; management gains understandable risks. Government, defense and CERT users gain local analysis. Labs/datasets support research and education, and metadata analysis limits payload inspection. Compact models, retention limits and edge processing offer measurable efficiency opportunities. Fresh before/after evidence verifies remediation.

## 22. Verification Targets and Product Deliverables

The architecture defines targets of at least 0.95 macro-F1 for mode/cipher classification, at least 0.90 for seven-class application inference, and empirical conformal coverage close to the stated nominal level. These are checked on independent configurations and sessions with per-class results and abstention, not claimed as attained measurements. Throughput targets include a 1 Gbps single-server profile and distributed scaling toward 10 Gbps; end-to-end benchmarks include decoding, persistence, capture loss and delivery delay. Metadata verdicts require sufficient packets, and rekey conclusions require the applicable observation interval.

Acceptance combines genuine IKEv1/v2 negotiations, ESP/NAT-T equivalence, AH scenarios, negative controls, fragments, parallel SAs, rekeys and unavailable evidence. Upload-to-report tests validate citations and downloads; live tests preserve state across rotations and outages. A demonstration compares deliberately weak and stronger lab configurations, checks predictions against ground truth, exports both required reports and repeats assessment after remediation. Scores and accuracy come from results, with no predetermined demonstration numbers.

Deliverables are the working software platform, evaluated AI classification engine, interactive dashboard, Executive/Technical assessment reports, recorded demonstration video, technical/operator documentation and versioned training/testing dataset. Model artifacts, schemas, hashes, evaluation summaries and reproducible scripts accompany the release. Completion is established by acceptance evidence for each requirement, with independently verified claims and disclosed unassessed properties.

## 23. Problem-Statement Coverage

| Requirement | Complete product coverage | Acceptance evidence |
|---|---|---|
| (a) VPN testbed | Tunnel/Transport; AES-128/256; GCM/CBC+HMAC; DH variants; PFS on/off; IPv4/IPv6; VoIP, messaging/WhatsApp validation, email, web, ICMP and video | Negotiated state, validated captures and labeled sessions |
| (b) Traffic capture | Offline/live Wireshark-compatible acquisition of IKE, ESP, optional AH and normal traffic | Capture quality, protocol coverage and retained evidence |
| (c) Identification | IPsec, IKE version, mode, encryption, integrity/authentication, key exchange, SA characteristics and traffic classes inside ESP | Observations or evaluated predictions with source/confidence |
| (d) Assessment | All eight required dimensions through policy rules and supporting evidence | Control states, findings, references and remediation |
| (e) Outputs | Security/Risk scores, traffic/metadata analysis, Threat Matrix, AI Confidence and Executive/Technical reports | Dashboard, reproducible scoring and report exports |
| Deliverables | Software, AI engine, dashboard, reports, video, docs and dataset | Versioned release and requirement acceptance record |

## 24. References and Design Sources

Repository sources: [ARCHITECTURE.md](ARCHITECTURE.md), [LOW_LEVEL_DESIGN.md](LOW_LEVEL_DESIGN.md) and [MODULES.md](MODULES.md) define the complete product. [models.md](models.md) supplies the feature/artifact contract, [threat_training.md](threat_training.md) explains dataset boundaries and the complementary threat workflow, and [rules/references.yaml](../rules/references.yaml) identifies standards used by assessment. The supplied CipherScore_ppt.pdf, Team SAMARAGS, SIH 2026 problem 26160, provides the presentation context.

Protocol standards: [RFC 4301](https://www.rfc-editor.org/rfc/rfc4301.html), IPsec architecture; [RFC 4302](https://www.rfc-editor.org/rfc/rfc4302.html), AH; [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303.html), ESP and TFC; [RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html), UDP encapsulation; [RFC 7296](https://www.rfc-editor.org/rfc/rfc7296.html), IKEv2; RFCs 3602, 4106 and 4868, AES-CBC, AES-GCM and HMAC-SHA2; RFCs 8221/8247, IPsec/IKE algorithm guidance; [RFC 9370](https://www.rfc-editor.org/rfc/rfc9370.html), multiple IKEv2 key exchanges.

Government guidance: [NIST SP 800-77 Rev. 1](https://csrc.nist.gov/pubs/sp/800/77/r1/final), Guide to IPsec VPNs, 2020; [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), ML-KEM, 2024; [NSA CNSA 2.0 resources](https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/).

Research: Draper-Gil et al., [Characterization of Encrypted and VPN Traffic Using Time-Related Features](https://www.unb.ca/cic/datasets/vpn.html), ICISSP 2016; Lotfollahi et al., [Deep Packet](https://arxiv.org/abs/1709.02656), Soft Computing 2020; Lin et al., [ET-BERT](https://arxiv.org/abs/2202.06335), WWW 2022; Lundberg and Lee, [A Unified Approach to Interpreting Model Predictions](https://arxiv.org/abs/1705.07874), NeurIPS 2017; Angelopoulos and Bates, [A Gentle Introduction to Conformal Prediction](https://arxiv.org/abs/2107.07511), 2021. Adrian et al., [Imperfect Forward Secrecy](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf), CCS 2015, and Felsch et al., [The Dangers of Key Reuse](https://www.usenix.org/conference/usenixsecurity18/presentation/felsch), USENIX Security 2018, motivate key-exchange and key-management assessment. strongSwan's [save-keys documentation](https://docs.strongswan.org/docs/latest/plugins/save-keys.html) supports controlled dataset verification.
