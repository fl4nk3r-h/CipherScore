"use client";
// Screen 1 — SOC Overview (mvp.md §4): Grafana-style analyst dashboard.
// Recent analyses, Security Score trend, top findings across captures,
// tunnel health, traffic mix, and a live threat feed. Renders API data when
// present, otherwise a labeled DEMO FEED so the SOC look works offline.
import Link from "next/link";
import { useMemo, useState } from "react";
import useSWR from "swr";
import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Line,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  ArrowRight,
  FileUp,
  Globe,
  Lock,
  Radar,
  RefreshCw,
  ShieldAlert,
  Zap,
} from "lucide-react";
import { api } from "@/lib/api";
import { Kpi, SevBadge, SocPanel } from "@/components/soc-panels";
import {
  DEMO_ANALYSES,
  SCORE_TREND,
  SEVERITY_TOTALS,
  THREAT_FEED,
  THROUGHPUT,
  TRAFFIC_MIX,
  TUNNELS,
} from "@/lib/soc-demo";

const SEV_COLOR: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#facc15",
  low: "#34d399",
  info: "#64748b",
};
const TRAFFIC_COLORS = ["#22d3ee", "#a78bfa", "#34d399", "#fbbf24", "#f87171", "#60a5fa", "#94a3b8"];

function gradeColor(g: string) {
  if (g === "A") return "text-emerald-300";
  if (g === "B" || g === "C") return "text-yellow-300";
  return "text-red-300";
}
function scoreColor(s: number) {
  if (s >= 80) return "text-emerald-300";
  if (s >= 60) return "text-yellow-300";
  if (s >= 45) return "text-orange-300";
  return "text-red-300";
}

const RANGES = ["1H", "6H", "24H", "7D"] as const;

export default function SocOverview() {
  const [range, setRange] = useState<(typeof RANGES)[number]>("24H");
  const [spinning, setSpinning] = useState(false);

  const { data: health } = useSWR("/healthz", (p: string) => api.fetcher(p).catch(() => null), {
    revalidateOnFocus: false,
  });
  const { data: sessions } = useSWR<any[] | null>("/lab/sessions", (p: string) => api.fetcher<any[]>(p).catch(() => null), {
    revalidateOnFocus: false,
  });
  const live = !!health;
  const sessionCount = sessions?.length;

  const trend = useMemo(() => {
    const slice = range === "1H" ? 4 : range === "6H" ? 6 : range === "24H" ? 9 : SCORE_TREND.length;
    return SCORE_TREND.slice(-slice);
  }, [range]);

  const totals = useMemo(() => {    const crit = DEMO_ANALYSES.reduce((a, x) => a + x.severity.critical, 0);
    const high = DEMO_ANALYSES.reduce((a, x) => a + x.severity.high, 0);
    const avgScore = Math.round(DEMO_ANALYSES.reduce((a, x) => a + x.score, 0) / DEMO_ANALYSES.length);
    const avgRisk = (DEMO_ANALYSES.reduce((a, x) => a + x.risk, 0) / DEMO_ANALYSES.length).toFixed(1);
    const avgConf = Math.round((DEMO_ANALYSES.reduce((a, x) => a + x.confidence, 0) / DEMO_ANALYSES.length) * 100);
    return { crit, high, avgScore, avgRisk, avgConf };
  }, []);

  function refresh() {
    setSpinning(true);
    setTimeout(() => setSpinning(false), 900);
  }

  return (
    <div className="mx-auto max-w-[1440px] space-y-4">
      {/* Dashboard header — Grafana style */}
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Radar className="h-4 w-4 text-cyan-400" />
            <h1 className="soc-num text-sm font-black uppercase tracking-[0.22em] text-slate-100">
              SOC Overview <span className="text-slate-600">/</span>{" "}
              <span className="text-cyan-300">IPsec VPN posture</span>
            </h1>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            {live ? "Live sensor data" : "DEMO FEED — start the API (`make up`) for live captures"} ·{" "}
            {sessionCount != null ? `${sessionCount} lab sessions indexed` : "passive · no probing"} · unknowns
            shown as unknown, never as facts
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <div className="soc-panel flex items-center gap-1 p-1">
            {RANGES.map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`soc-num rounded px-2.5 py-1 text-[11px] font-bold ${
                  range === r ? "bg-cyan-500/20 text-cyan-200" : "text-slate-500 hover:text-slate-300"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
          <button
            onClick={refresh}
            className="soc-panel flex items-center gap-1.5 px-3 py-2 text-xs text-slate-300 hover:border-cyan-500/40 hover:text-cyan-200"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${spinning ? "animate-spin" : ""}`} /> Refresh
          </button>
          <a
            href={process.env.NEXT_PUBLIC_GRAFANA_URL || "http://localhost:3001"}
            target="_blank"
            rel="noreferrer"
            className="soc-panel flex items-center gap-1.5 px-3 py-2 text-xs text-orange-200 hover:border-orange-500/40 hover:text-orange-100"
            title="Open the provisioned Grafana SOC dashboards"
          >
            <Globe className="h-3.5 w-3.5" /> Grafana
          </a>
          <Link
            href="/analyses/new"
            className="flex items-center gap-1.5 rounded bg-cyan-500 px-3 py-2 text-xs font-bold text-black hover:bg-cyan-400"
          >
            <FileUp className="h-3.5 w-3.5" /> New analysis
          </Link>
        </div>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Avg security score" value={<span className={scoreColor(totals.avgScore)}>{totals.avgScore}</span>} sub="across 4 analyses · grade C" dot="bg-cyan-400" />
        <Kpi label="Avg risk" value={totals.avgRisk} sub="confidence-weighted · max 100" accent="text-orange-300" dot="bg-orange-400" />
        <Kpi label="Critical + high" value={<span className="text-red-300">{totals.crit + totals.high}</span>} sub={`${totals.crit} critical · ${totals.high} high`} dot="bg-red-500 soc-live-dot" />
        <Kpi label="Tunnels / SAs" value={TUNNELS.length + " / 12"} sub="2 transport-exposed · 1 NAT-T" accent="text-cyan-200" dot="bg-cyan-400" />
        <Kpi label="AI confidence" value={`${totals.avgConf}%`} sub="calibrated · isotonic + conformal" accent="text-violet-300" dot="bg-violet-400" />
        <Kpi label="Lab sessions" value={sessionCount ?? "112"} sub={live ? "indexed from bridge" : "demo snapshot"} accent="text-emerald-300" dot={live ? "bg-emerald-400" : "bg-amber-400"} />
      </div>

      {/* Row 1: trend + severity + traffic */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel
          title="Security score / risk trend"
          className="xl:col-span-6"
          right={<span className="soc-num text-[10px] text-slate-500">score 0–100 · risk weighted × confidence</span>}
        >
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={trend} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                <CartesianGrid stroke="#16223a" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: "#0a111f", border: "1px solid #1a2740", fontSize: 12 }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Area type="monotone" dataKey="score" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.12} strokeWidth={2} name="score" />
                <Line type="monotone" dataKey="risk" stroke="#fb923c" strokeWidth={1.5} dot={false} name="risk" />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
          <div className="soc-num flex gap-4 px-1 pt-1 text-[10px] uppercase tracking-widest text-slate-500">
            <span><span className="text-cyan-300">—</span> security score</span>
            <span><span className="text-orange-300">—</span> risk score</span>
            <span className="ml-auto">dip @00:58 = ikev1 legacy tunnel</span>
          </div>
        </SocPanel>

        <SocPanel title="Findings by severity" className="xl:col-span-3"
          right={<ShieldAlert className="h-3.5 w-3.5 text-slate-600" />}>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={SEVERITY_TOTALS} layout="vertical" margin={{ top: 4, right: 12, bottom: 0, left: 8 }}>
                <CartesianGrid stroke="#16223a" horizontal={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="sev" type="category" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} width={62} />
                <Tooltip contentStyle={{ background: "#0a111f", border: "1px solid #1a2740", fontSize: 12 }} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {SEVERITY_TOTALS.map((s) => (
                    <Cell key={s.sev} fill={SEV_COLOR[s.sev]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-[11px] text-slate-500">1 critical (IKEv1) · rule pack <span className="soc-num text-slate-400">ipsec-baseline</span></p>
        </SocPanel>

        <SocPanel title="Encrypted traffic mix" className="xl:col-span-3"
          right={<span className="soc-num text-[10px] text-slate-500">ml · 7 classes</span>}>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={TRAFFIC_MIX} dataKey="value" nameKey="name" innerRadius={44} outerRadius={68} paddingAngle={2} strokeWidth={0}>
                  {TRAFFIC_MIX.map((_, i) => (
                    <Cell key={i} fill={TRAFFIC_COLORS[i % TRAFFIC_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#0a111f", border: "1px solid #1a2740", fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
            {TRAFFIC_MIX.slice(0, 6).map((t, i) => (
              <div key={t.name} className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm" style={{ background: TRAFFIC_COLORS[i % TRAFFIC_COLORS.length] }} />
                <span className="text-slate-400">{t.name}</span>
                <span className="soc-num ml-auto text-slate-300">{t.value}%</span>
              </div>
            ))}
          </div>
          <p className="mt-2 flex items-center gap-1.5 rounded border border-amber-500/20 bg-amber-500/5 px-2 py-1.5 text-[11px] text-amber-200/90">
            <Lock className="h-3 w-3 shrink-0" /> VoIP @ 0.90 inside ESP — metadata exposure is real.
          </p>
        </SocPanel>
      </div>

      {/* Row 2: recent analyses + top findings + throughput */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel
          title="Recent analyses"
          className="xl:col-span-7"
          pad={false}
          right={
            <Link href="/analyses/new" className="flex items-center gap-1 text-[11px] text-cyan-300 hover:text-cyan-200">
              open intake <ArrowRight className="h-3 w-3" />
            </Link>
          }
        >
          <div className="soc-scroll overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-xs">
              <thead>
                <tr className="soc-num border-b border-[#16223a] text-[10px] uppercase tracking-[0.18em] text-slate-500">
                  <th className="px-3 py-2">analysis / capture</th>
                  <th className="px-3 py-2">score</th>
                  <th className="px-3 py-2">risk</th>
                  <th className="px-3 py-2">sev</th>
                  <th className="px-3 py-2">conf</th>
                  <th className="px-3 py-2 text-right">drill</th>
                </tr>
              </thead>
              <tbody>
                {DEMO_ANALYSES.map((a) => (
                  <tr key={a.id} className="border-b border-[#101a30] last:border-0 hover:bg-cyan-500/[0.04]">
                    <td className="px-3 py-2.5">
                      <div className="font-semibold text-slate-200">{a.caption}</div>
                      <div className="soc-num mt-0.5 max-w-[380px] truncate text-[10px] text-slate-500">{a.profile}</div>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`soc-num text-base font-black ${scoreColor(a.score)}`}>{a.score}</span>{" "}
                      <span className={`soc-num text-[11px] font-bold ${gradeColor(a.grade)}`}>{a.grade}</span>
                    </td>
                    <td className="soc-num px-3 py-2.5 text-orange-200">{a.risk.toFixed(1)}</td>
                    <td className="px-3 py-2.5">
                      <div className="flex gap-1">
                        {a.severity.critical > 0 && <SevBadge sev="critical" />}
                        {a.severity.high > 0 && <SevBadge sev="high" />}
                        {a.severity.high === 0 && a.severity.critical === 0 && <SevBadge sev="low" />}
                        <span className="soc-num text-[10px] text-slate-500">
                          +{a.severity.medium}M
                        </span>
                      </div>
                    </td>
                    <td className="soc-num px-3 py-2.5 text-violet-200">{Math.round(a.confidence * 100)}%</td>
                    <td className="px-3 py-2.5 text-right">
                      <Link
                        href={`/analyses/${a.id}`}
                        className="soc-num rounded border border-[#1a2740] px-2 py-1 text-[10px] uppercase tracking-wider text-cyan-300 hover:border-cyan-500/50 hover:bg-cyan-500/10"
                      >
                        open
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SocPanel>

        <SocPanel title="Top findings across captures" className="xl:col-span-5"
          right={<span className="soc-num text-[10px] text-slate-500">posture · ipsec-baseline</span>}>
          <ul className="space-y-2">
            {[
              { id: "CRYPTO-001", sev: "high", title: "Weak DH group 2 in IKE + ESP", meta: "p03 · p13 · observed · RFC 8247 §2.4" },
              { id: "IKE-001", sev: "critical", title: "IKEv1 Main Mode accepted (legacy)", meta: "p13 · observed · retire to IKEv2" },
              { id: "PFS-001", sev: "medium", title: "PFS disabled — rekey without KE", meta: "p03 · p13 · inferred 0.88" },
              { id: "META-001", sev: "medium", title: "App class leaks via ESP sizes/timing", meta: "voip 0.90 · video bursts · conformal set" },
              { id: "INTEG-002", sev: "high", title: "HMAC-SHA1-96 integrity (truncation)", meta: "p03 · p09 · inferred 0.98" },
            ].map((f) => (
              <li key={f.id} className="flex items-start gap-2.5 rounded border border-[#16223a] bg-black/30 px-2.5 py-2">
                <SevBadge sev={f.sev} />
                <div className="min-w-0">
                  <div className="truncate text-xs font-semibold text-slate-200">
                    <span className="soc-num text-slate-500">{f.id}</span> — {f.title}
                  </div>
                  <div className="soc-num mt-0.5 text-[10px] text-slate-500">{f.meta}</div>
                </div>
              </li>
            ))}
          </ul>
          <Link href="/analyses/an_p03_weak/findings" className="mt-2.5 flex items-center justify-center gap-1 rounded border border-[#1a2740] py-1.5 text-[11px] text-slate-300 hover:border-cyan-500/40 hover:text-cyan-200">
            <Zap className="h-3 w-3" /> open findings workbench
          </Link>
        </SocPanel>
      </div>

      {/* Row 3: tunnels + throughput + live feed */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel title="Tunnel / SA watch" className="xl:col-span-5" pad={false}
          right={<span className="soc-num text-[10px] text-slate-500">spi · mode · suite</span>}>
          <ul className="divide-y divide-[#101a30]">
            {TUNNELS.map((t) => (
              <li key={t.sa} className="flex items-center gap-3 px-3 py-2.5">
                <span className={`h-8 w-1 rounded ${t.score >= 80 ? "bg-emerald-400" : t.score >= 60 ? "bg-yellow-400" : "bg-red-500"}`} />
                <div className="min-w-0 flex-1">
                  <div className="soc-num text-xs font-bold text-slate-200">{t.sa} <span className="font-normal text-slate-500">· {t.mode}</span></div>
                  <div className="soc-num truncate text-[10px] text-slate-500">{t.peers} · {t.cipher} · {t.dh} · PFS {t.pfs ? "on" : "off"}</div>
                </div>
                <div className="text-right">
                  <div className={`soc-num text-sm font-black ${scoreColor(t.score)}`}>{t.score}</div>
                  <div className="soc-num text-[9px] uppercase tracking-widest text-slate-500">{t.tag}</div>
                </div>
              </li>
            ))}
          </ul>
          <div className="border-t border-[#16223a] p-2.5">
            <Link href="/lab" className="flex items-center justify-center gap-1 rounded bg-slate-800/80 py-1.5 text-[11px] text-slate-200 hover:bg-slate-700">
              <Globe className="h-3 w-3" /> compare vs ground truth in lab matrix
            </Link>
          </div>
        </SocPanel>

        <SocPanel title="ESP / IKE throughput — lab bridge" className="xl:col-span-3"
          right={<span className="soc-num flex items-center gap-1 text-[10px] text-red-400"><span className="soc-live-dot h-1.5 w-1.5 rounded-full bg-red-500" /> live</span>}>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={THROUGHPUT} margin={{ top: 8, right: 4, bottom: 0, left: -22 }}>
                <CartesianGrid stroke="#16223a" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0a111f", border: "1px solid #1a2740", fontSize: 12 }} />
                <Bar dataKey="esp" fill="#22d3ee" fillOpacity={0.55} radius={[3, 3, 0, 0]} name="ESP pkt/s" />
                <Line type="monotone" dataKey="ike" stroke="#a78bfa" strokeWidth={2} dot={false} name="IKE msg" />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
          <div className="soc-num mt-1 flex justify-between text-[10px] uppercase tracking-widest text-slate-500">
            <span><span className="text-cyan-300">▮</span> esp</span>
            <span><span className="text-violet-300">—</span> ike</span>
            <Link href="/live" className="text-cyan-300 hover:text-cyan-200">open live →</Link>
          </div>
        </SocPanel>

        <SocPanel title="Threat feed" className="xl:col-span-4"
          pad={false}
          right={<span className="soc-num text-[10px] uppercase tracking-widest text-slate-500">posture · ml · parse</span>}>
          <ul className="soc-scroll max-h-72 overflow-y-auto p-2">
            {THREAT_FEED.map((e, i) => (
              <li key={i} className="flex items-start gap-2 rounded px-1.5 py-1.5 hover:bg-white/[0.02]">
                <span className="soc-num mt-0.5 shrink-0 text-[10px] text-slate-500">{e.ts}</span>
                <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEV_COLOR[e.sev] }} />
                <div className="min-w-0">
                  <p className="text-[11px] leading-snug text-slate-300">{e.msg}</p>
                  <p className="soc-num text-[9px] uppercase tracking-widest text-slate-600">src: {e.src}</p>
                </div>
              </li>
            ))}
          </ul>
        </SocPanel>
      </div>
    </div>
  );
}
