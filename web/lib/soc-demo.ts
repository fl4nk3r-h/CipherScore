// Demo / fallback dataset for the SOC overview (mvp.md §10 demo behavior).
// When the API is live, the dashboard merges real lab sessions on top of this.
// Nothing here is presented as observed evidence — panels label it DEMO FEED
// until backed by an /analyses/{id} response.

export interface DemoAnalysis {
  id: string;
  profile: string;
  caption: string;
  score: number;
  grade: string;
  risk: number;
  confidence: number;
  saCount: number;
  severity: { critical: number; high: number; medium: number; low: number; info: number };
  top: string[];
  time: string;
  status: "completed" | "running";
}

export const DEMO_ANALYSES: DemoAnalysis[] = [
  {
    id: "an_p03_weak",
    profile: "p03 · tunnel/v4 · AES-256-CBC + SHA1-96 · DH2 · PFS off",
    caption: "p03-voip-0003.pcapng",
    score: 42, grade: "E", risk: 31.2, confidence: 0.91, saCount: 4,
    severity: { critical: 0, high: 2, medium: 3, low: 1, info: 1 },
    top: ["CRYPTO-001 Weak DH group 2", "PFS-001 PFS disabled", "INTEG-002 HMAC-SHA1-96"],
    time: "02:14 UTC", status: "completed",
  },
  {
    id: "an_p07_strong",
    profile: "p07 · tunnel/v6 · AES-256-GCM-16 · DH20 · PFS on",
    caption: "p07-web-0011.pcapng",
    score: 91, grade: "A", risk: 4.1, confidence: 0.96, saCount: 2,
    severity: { critical: 0, high: 0, medium: 0, low: 1, info: 2 },
    top: ["META-001 Traffic classifiable → TFC padding advised", "PQ-001 No PQ hybrid KE"],
    time: "01:47 UTC", status: "completed",
  },
  {
    id: "an_p10_nat",
    profile: "p10 · tunnel/v4 · AES-256-GCM · NAT-T UDP/4500",
    caption: "p10-video-0007.pcapng",
    score: 76, grade: "C", risk: 11.8, confidence: 0.88, saCount: 3,
    severity: { critical: 0, high: 1, medium: 1, low: 2, info: 1 },
    top: ["LIFE-001 No rekey in window", "META-001 Video burst pattern exposed"],
    time: "01:22 UTC", status: "completed",
  },
  {
    id: "an_p13_ikev1",
    profile: "p13 · IKEv1 main · AES-128-CBC · DH2 · PFS off",
    caption: "p13-email-0002.pcapng",
    score: 35, grade: "F", risk: 36.4, confidence: 0.93, saCount: 3,
    severity: { critical: 1, high: 2, medium: 2, low: 1, info: 0 },
    top: ["IKE-001 IKEv1 Aggressive/Main legacy", "CRYPTO-001 DH group 2", "PFS-001 PFS disabled"],
    time: "00:58 UTC", status: "completed",
  },
];

export const SCORE_TREND = [
  { t: "18:00", score: 58, risk: 21.4 }, { t: "19:00", score: 61, risk: 19.8 },
  { t: "20:00", score: 55, risk: 23.1 }, { t: "21:00", score: 49, risk: 27.5 },
  { t: "22:00", score: 42, risk: 31.2 }, { t: "23:00", score: 47, risk: 28.9 },
  { t: "00:00", score: 35, risk: 36.4 }, { t: "00:58", score: 35, risk: 36.4 },
  { t: "01:22", score: 76, risk: 11.8 }, { t: "01:47", score: 91, risk: 4.1 },
  { t: "02:14", score: 42, risk: 31.2 }, { t: "now", score: 58, risk: 21.4 },
];

export const SEVERITY_TOTALS = [
  { sev: "critical", count: 1 },
  { sev: "high", count: 5 },
  { sev: "medium", count: 6 },
  { sev: "low", count: 5 },
  { sev: "info", count: 4 },
];

export const TRAFFIC_MIX = [
  { name: "voip", value: 28 }, { name: "web", value: 24 },
  { name: "video", value: 19 }, { name: "email", value: 11 },
  { name: "messaging", value: 9 }, { name: "bulk", value: 6 },
  { name: "icmp", value: 3 },
];

export const THROUGHPUT = [
  { t: "-50s", esp: 410, ike: 4 }, { t: "-40s", esp: 620, ike: 2 },
  { t: "-30s", esp: 580, ike: 8 }, { t: "-20s", esp: 940, ike: 3 },
  { t: "-10s", esp: 720, ike: 12 }, { t: "now", esp: 810, ike: 5 },
];

export interface FeedEvent {
  ts: string;
  sev: "critical" | "high" | "medium" | "low" | "info";
  msg: string;
  src: string;
}

export const THREAT_FEED: FeedEvent[] = [
  { ts: "02:14:09", sev: "high", msg: "CRYPTO-001 — DH group 2 negotiated (p03-voip-0003)", src: "posture" },
  { ts: "02:13:52", sev: "medium", msg: "PFS-001 — CHILD_SA rekey without KE payload → PFS off", src: "infer" },
  { ts: "02:12:31", sev: "medium", msg: "META-001 — ESP flow classified voip @ 0.90 (conformal {voip, messaging})", src: "ml" },
  { ts: "01:47:20", sev: "low", msg: "p07-web-0011 scored 91 (A) — only hardening findings", src: "posture" },
  { ts: "01:22:05", sev: "high", msg: "LIFE-001 — no rekey in 60 min window (p10-video-0007)", src: "posture" },
  { ts: "00:58:44", sev: "critical", msg: "IKE-001 — IKEv1 Main Mode accepted (p13-email-0002)", src: "parse" },
  { ts: "00:41:12", sev: "info", msg: "ESN-001 — high-rate SA without ESN (tunnel/v4)", src: "parse" },
  { ts: "00:20:03", sev: "info", msg: "snapshot complete — 112 sessions indexed from lab bridge", src: "capture" },
];

export const TUNNELS = [
  { sa: "0xc3a1f00d", peers: "172.30.0.2 → 172.30.0.3", mode: "tunnel", cipher: "AES-CBC-256", dh: "g2", pfs: false, score: 42, tag: "inferred" },
  { sa: "0x9e77b201", peers: "fd30::2 → fd30::3", mode: "tunnel", cipher: "AES-GCM-256", dh: "g20", pfs: true, score: 91, tag: "observed" },
  { sa: "0x51ad44c9", peers: "172.30.0.2 → 172.30.0.3 :4500", mode: "tunnel·NAT-T", cipher: "AES-GCM-256", dh: "g14", pfs: true, score: 76, tag: "inferred" },
  { sa: "0x02ff90aa", peers: "172.30.0.2 → 172.30.0.3", mode: "transport", cipher: "AES-CBC-128", dh: "g2", pfs: false, score: 35, tag: "observed" },
];
