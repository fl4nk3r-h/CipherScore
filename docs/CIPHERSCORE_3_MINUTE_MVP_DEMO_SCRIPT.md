# CipherScore — Three-Minute MVP Demonstration Script

**Duration:** 3:00. Start on the Overview dashboard. Read only the quoted narration; screen directions and captions are production notes. The interface currently uses the engineering name **CipherScope**; introduce it as **CipherScore**.

## 0:00–0:15 — Dashboard and Problem

**Show:** Overview. Move across average security score, average risk, high-severity findings, security associations, AI confidence and lab-session count. Briefly scroll past trends, traffic mix and recent analyses.

**Say:**

> “This is CipherScore, our IPsec VPN analysis dashboard. Encryption alone does not guarantee a secure configuration. This overview brings security scores, risks, confidence, traffic patterns and recent findings into one place.”

## 0:15–0:35 — VPN Lab and Dataset

**Show:** Open **Lab**. Select **p03** and **p07**. Show the **Run selected (voip + web)** button and an already completed run. Expand a session to show passive field matches and the separate gateway-verification section.

**Caption:** “16 profiles • Tunnel / Transport • AES-128 / AES-256 • CBC + HMAC / GCM • DH variations • PFS on / off • IPv4 / IPv6.” Briefly replace it with “Traffic: ICMP, Web, Email, VoIP, Video, Messaging, Bulk.”

**Say:**

> “Our Lab generates labelled VPN captures across sixteen configurable profiles, varying operating mode, cryptography, forward secrecy and IP version. Here are weak and strong configurations. Saved sessions compare passive analysis with ground truth, while gateway verification is shown separately.”

## 0:35–0:50 — Capture Upload and Analysis

**Show:** Open **New Analysis**. Drop a prepared `.pcap` or `.pcapng` into the upload area. Briefly show the saved-session analysis option, then the analysis progress stream. Cut processing waits.

**Say:**

> “New Analysis accepts PCAP and PCAPNG captures, or a saved lab session. The pipeline parses packets, extracts evidence and features, evaluates security rules, and generates reports, with progress visible on screen.”

## 0:50–1:05 — Security Summary

**Show:** Completed analysis → **Summary**. Point to the Security Score and grade, Risk Score, AI Confidence, SA count and Threat Matrix. Briefly switch to the comparison analysis.

**Say:**

> “The summary presents a security score, risk score, AI confidence and threat matrix. Comparing our two captures shows how supported findings affect the assessment. The matrix helps prioritize issues by likelihood and impact.”

## 1:05–1:25 — Protocol and Security Associations

**Show:** Open **SAs**. Move across SPI, peers, IKE, mode, encryption, key size, integrity, DH group, PFS, NAT-T, rekey interval and replay-window columns. Point to the observed, inferred or unknown tags and their confidence percentages.

**Caption:** “IKEv1 / IKEv2 • ESP / NAT-T • Optional AH • Observed / Inferred / Unknown.”

**Say:**

> “The Security Associations tab organizes peer addresses, SPIs, IKE version and available encryption, integrity, mode and key-exchange evidence. It also exposes NAT traversal, rekey and replay information. Field tags distinguish observations from inferences, show confidence, and mark unsupported properties unknown.”

## 1:25–1:45 — AI Traffic Classification and Metadata

**Show:** Open **Traffic**. Highlight the traffic-type chart, mean-packet-size histogram and metadata-exposure panel. Briefly return to an SA traffic entry to show its predicted class, confidence and candidate labels.

**Say:**

> “Our trained traffic classifier predicts likely activity inside encrypted ESP using packet sizes, timing and flow patterns. The chart shows application predictions, alongside feature distributions and metadata exposure. Confidence and candidate labels communicate uncertainty, helping analysts judge predictions without decrypting payloads.”

## 1:45–2:05 — Findings and Recommendations

**Show:** Open **Findings**. Filter by **high** or another severity with actual results, then open one finding’s evidence drawer. Point to the evidence, source rule, references and remediation.

**Caption:** “Assessment: Crypto • Compliance • SA parameters • Key lifetime • Replay • PFS • Cipher suite • Metadata.”

**Say:**

> “Findings turn supported evidence into actionable security checks across cryptographic strength, compliance, association settings, lifetimes, replay protection, forward secrecy, cipher suites and metadata exposure. We can filter by severity, inspect the supporting evidence and references, and follow the recommended remediation.”

## 2:05–2:20 — Executive and Technical Reports

**Show:** Open **Reports**. Preview the Executive PDF, switch to the Technical PDF, then point to PDF, JSON and CSV download controls.

**Say:**

> “Report Studio produces an executive report for decision makers and a technical report for analysts. Both can be previewed and downloaded. JSON and CSV exports make the results reusable in other workflows.”

## 2:20–2:35 — Live IPsec Monitoring

**Show:** Open **Live**, with capture already active on the configured interface. Show the connected badge and an arriving window with prediction, score and risk. Point to **Stop live capture**.

**Say:**

> “Live mode processes traffic from a configured interface in ten-second windows. As windows complete, the dashboard updates predictions and posture scores, allowing analysts to monitor changes while the VPN is running.”

## 2:35–3:00 — Passive Threat Alerts and Closing

**Show:** Open **Threat Alerts**. Upload a prepared threat-demo PCAP to start replay, then expand an actual alert to show severity, detector source, timestamp and evidence. Point to **Start mirror**; finish on Overview.

**Caption:** “Rule / heuristic signals: DDoS, scanning, outbound-volume exfiltration, beaconing, DGA, DNS tunnelling, suspicious TLS / QUIC sessions.”

**Say:**

> “Our separate passive threat workflow supports capture replay and live mirrored traffic. Alerts show severity, detector source and supporting evidence for suspicious patterns, including scanning and flooding. These are rule or heuristic signals. Together, CipherScore connects reproducible testing, encrypted-traffic analysis, security assessment and reporting in one analyst workflow.”

## Recording Preparation

- Use the local API setup in [RUN_SEQUENCE.md](RUN_SEQUENCE.md) when demonstrating the dashboard’s Lab-run button. Prepare completed p03 and p07 captures and generated reports before recording; cut capture-generation and processing waits.
- Confirm the registered traffic-model artifact loads before using the classification narration. Model binaries are distributed separately. If it is unavailable, replace that segment’s narration with: “The Traffic tab organizes encrypted-flow metadata, including packet-size distributions. With a trained model installed, it also shows application predictions and confidence.”
- Start live capture on an interface that actually carries the demo traffic. Configure `CS_LIVE_ENABLED`, `CS_LIVE_INTERFACE` and capture privileges as described in the run sequence. Have a completed live window ready when this segment begins.
- Use a known threat-demo capture that produces an alert. Threat replay and IPsec live analysis are separate workflows; point to mirror capture after configuring its input interface.
- Read the actual displayed results. The script deliberately leaves score values and percentages to the screen. The messaging lab generator is WhatsApp-like traffic, not verified real WhatsApp traffic.
- Speak at roughly **130 words per minute**, allowing brief pauses for clicks and screen transitions. Rehearse each segment against its timestamp and trim transitions to finish at **3:00**.
