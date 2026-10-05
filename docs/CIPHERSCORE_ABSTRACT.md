**CipherScore: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework**

### The Problem

IPsec VPNs protect enterprise, government, military and cloud communications, but their security depends on the algorithms, authentication, key exchanges and policies actually used. Weak Diffie-Hellman groups, legacy suites, missing forward secrecy, excessive key lifetimes and implementation flaws can undermine a tunnel. Encryption conceals assessment information, while sizes, timing and endpoints may still expose application behaviour. Packet tools require expert interpretation, and configuration reviews alone cannot establish runtime behaviour. The problem is to turn captured or live traffic into a trustworthy security assessment with actionable recommendations.

### Our Solution

CipherScore proposes an explainable, self-labeling IPsec intelligence platform with six modules: LabForge, CaptureMesh, Evidence Fusion Engine, AI Classifier Ensemble, Posture Engine and Report Studio. Analysts upload PCAP/PCAPNG files or monitor authorized SPAN/TAP feeds to obtain tunnel inventories, Security Association (SA) characteristics, application predictions, risk assessments and fixes. Passive analysis is the default. Optional authorized active probes assess gateway-supported proposals, while key-assisted analysis verifies hidden parameters, including peer authentication. Results retain sources, packet references, model versions and uncertainty.

### VPN Testbed and Dataset Generation

LabForge generates labeled data using strongSwan and Libreswan. An expandable matrix covers Tunnel/Transport, AES-128/AES-256, AES-GCM, AES-CBC with HMAC, multiple DH groups, PFS on/off, IPv4/IPv6, IKEv1/IKEv2, NAT traversal, lifetimes and replay settings. Generators produce VoIP, email, browsing, ICMP, video, messaging and bulk transfers, with non-VPN controls and optional AH scenarios. WhatsApp-like simulations are labeled and supplemented by real-device validation. Ground truth is checked against negotiated gateway state and controlled-lab key exports. Versioned captures, manifests, feature tables and dataset cards support repeatable training and independent evaluation.

### Technical Approach

The technical pipeline captures, parses, extracts features, fuses evidence, classifies, assesses and reports. CaptureMesh accepts Wireshark/tcpdump traces and live streams containing IKE, ESP, ESP-in-UDP, optional AH and normal traffic. Parsing identifies IPsec, IKE version, visible proposals, selected IKE algorithms, key-exchange groups, SPIs, sequence numbers and NAT-T. Per-peer SA tracking reconstructs observed lifecycles, rekeys and sequence anomalies. IKE SA observations remain separate from encrypted CHILD_SA parameters, following [RFC 7296](https://www.rfc-editor.org/rfc/rfc7296.html); initial IKE transforms alone cannot establish the ESP suite.

### Innovation and Uniqueness

Innovation combines protocol structure, explainable inference and a self-audit of leakage. ESP length algebra tests cipher and integrity hypotheses using header, IV, padding and authentication-tag overheads. Encrypted rekey size and timing provide candidate evidence for PFS and DH characteristics. These conditional side-channel inferences require validation because configurations can produce similar observations. Length sequences, direction, timing, bursts and periodicity support application classification without decrypting content. Classification success becomes evidence of metadata leakage, informing traffic shaping and Traffic Flow Confidentiality padding recommendations under [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303.html).

### AI Classification and Explainability

The AI design combines LightGBM for structured features, a compact Transformer for sequences and stacking for fusion. Prediction heads target mode, cipher family, integrity, PFS, DH group and traffic class. Probability calibration and conformal prediction provide confidence and prediction sets; SHAP explains tree-model decisions. Coverage is checked on independent data under conformal assumptions. Outputs distinguish observed, inferred and unknown attributes, with key-assisted verification identified separately. ESP lengths cannot reveal AES key size, and missing rekey evidence leaves CHILD_SA PFS unknown. These methods draw on [Angelopoulos and Bates](https://arxiv.org/abs/2107.07511) and [Lundberg and Lee](https://arxiv.org/abs/1705.07874).

### Security Assessment and Scoring

The Posture Engine covers all eight required dimensions: cryptographic strength, configuration compliance, SA parameters, key lifetime, replay protection, forward secrecy, cipher-suite strength and metadata exposure. Versioned YAML rules map findings to IPsec guidance and organizational policy. Severity, likelihood and evidence confidence drive a transparent 0-100 Security Score, Risk Score and grade; an AI Confidence Score states inference certainty, and a 5-by-5 Threat Matrix displays likelihood and impact. Assessment coverage accompanies scores, preserving insufficient-evidence states. Sequence anomalies are distinguished from verified receiver replay settings. Policy mapping draws on [NIST SP 800-77 Rev. 1](https://csrc.nist.gov/pubs/sp/800/77/r1/final) and RFC 8221/8247.

### Post-Quantum Readiness and Reporting

Post-quantum readiness assessment addresses long-lived secrets and harvest-now, decrypt-later exposure. It tracks multiple or hybrid key-exchange evidence and supports migration planning against [RFC 9370](https://www.rfc-editor.org/rfc/rfc9370.html), ML-KEM in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), and CNSA 2.0 guidance. Report Studio is designed to generate Executive, Technical and Compliance reports using a local language model restricted to verified findings and curated standards. Citation and numeric validation, with template fallback, constrain unsupported narrative. The dashboard presents SA timelines, confidence, traffic distributions, evidence, compliance and prioritized fixes, with PDF, HTML and machine-readable exports.

### System Architecture and Deployment

The target architecture uses Rust/eBPF capture, Python analysis, ONNX inference, FastAPI, Redis Streams, PostgreSQL/TimescaleDB, pgvector and object storage. Next.js/TypeScript provide the dashboard; MLflow manages provenance and promotion, and Prometheus/Grafana support operations. Docker enables local deployment; Kubernetes and distributed sensors support expansion. Air-gapped operation, RBAC, workspace isolation, temporary encrypted key storage and audit logs address sensitive deployments. SIEM/SOAR, Zeek and Suricata integrations extend workflows. A complementary passive threat workflow assesses scans, floods, beaconing, DNS anomalies and visible TLS/QUIC metadata.

### Feasibility and Viability

Feasibility rests on open-source components, commodity hardware and repeatable laboratory data. Existing ingestion, lab orchestration, feature extraction, dashboard and report generation provide an integration base. Model delivery, protocol correctness, multi-vendor generalization and sustained live throughput remain acceptance requirements. Validation separates configurations and sessions across fitting, probability calibration, conformal calibration and testing, with loss, jitter, fragmentation, NAT-T and padding checked. [ISCXVPN2016](https://www.unb.ca/cic/datasets/vpn.html) supports application research but uses OpenVPN, so it cannot validate IPsec mode, cipher or PFS labels. Viability follows recurring VPN audits and integration with SOC workflows.

### Impact and Benefits

Expected benefits include faster VPN audits, reduced dependence on protocol experts, clearer remediation priorities and stronger evidence. Analysts and engineers gain traceable findings; enterprises and MSSPs gain consistent assessment; defense, government and CERT teams gain local analysis and migration planning. Passive metadata analysis limits payload exposure. Reproducible labs and datasets support research and education, while commodity deployment can reduce hardware and licensing dependence. Deliverables include the software platform, evaluated AI engine, dashboard, assessment reports, demonstration video, technical documentation and reproducible training/testing data.

### References

IETF RFCs 4301/4302/4303, 3948, 4106, 7296, 8221/8247 and 9370; NIST SP 800-77 Rev. 1 (2020) and FIPS 203 (2024); [NSA CNSA 2.0 resources](https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/); Draper-Gil et al., “Characterization of Encrypted and VPN Traffic Using Time-Related Features” (ICISSP 2016); Lin et al., [“ET-BERT”](https://arxiv.org/abs/2202.06335) (WWW 2022); Lundberg and Lee, “A Unified Approach to Interpreting Model Predictions” (NeurIPS 2017); Angelopoulos and Bates, “A Gentle Introduction to Conformal Prediction” (2021).
