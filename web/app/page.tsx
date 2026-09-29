"use client";
// Screen 1 — Overview (mvp.md §4): recent analyses, Security Score trend,
// top findings across captures. Renders API data when present, otherwise
// labeled sample data so the dashboard works offline.
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
  ArrowUpRight,
  FileUp,
  Lock,
  RefreshCw,
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

const SEV_DOT: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#34d399",
  info: "#71717a",
};
const SEV_FILL: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#34d399",
  info: "#52525b",
};
const TRAFFIC_COLORS = ["#38bdf8", "#a78bfa", "#34d399", "#fbbf24", "#fb923c", "#f87171", "#71717a"];
const GRID = "rgba(255,255,255,0.06)";
const TICK = { fill: "#71717a", fontSize: 11 };
const TOOLTIP = { background: "#18181b", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12, color: "#e4e4e7" };

function scoreTone(s: number) {
  if (s >= 80) return "text-emerald-300";
  if (s >= 60) return "text-amber-200";
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

  const totals = useMemo(() => {
    const crit = DEMO_ANALYSES.reduce((a, x) => a + x.severity.critical, 0);
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
    <div className="mx-auto max-w-[1400px] space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-50">Overview</h1>
          <p className="mt-1 text-[13px] text-zinc-500">
            IPsec VPN posture across recent analyses
            {!live && " · showing sample data — connect the API for live results"}
            {sessionCount != null && ` · ${sessionCount} lab sessions indexed`}
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <div className="flex items-center gap-0.5 rounded-lg border border-white/[0.07] bg-white/[0.02] p-0.5">
            {RANGES.map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`soc-num rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                  range === r ? "bg-white/10 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
          <button
            onClick={refresh}
            className="flex items-center gap-1.5 rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-[7px] text-[13px] text-zinc-300 transition-colors hover:bg-white/[0.05]"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${spinning ? "animate-spin" : ""}`} /> Refresh
          </button>
          <a
            href={process.env.NEXT_PUBLIC_GRAFANA_URL || "http://localhost:3001"}
            target="_blank"
            rel="noreferrer"
            className="hidden items-center gap-1 rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-[7px] text-[13px] text-zinc-300 transition-colors hover:bg-white/[0.05] sm:flex"
          >
            Grafana <ArrowUpRight className="h-3.5 w-3.5 text-zinc-500" />
          </a>
          <Link
            href="/analyses/new"
            className="flex items-center gap-1.5 rounded-lg bg-zinc-50 px-3 py-[7px] text-[13px] font-medium text-zinc-950 transition-colors hover:bg-white"
          >
            <FileUp className="h-3.5 w-3.5" /> New analysis
          </Link>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Avg. security score" value={<span className={scoreTone(totals.avgScore)}>{totals.avgScore}</span>} sub="Across 4 analyses" />
        <Kpi label="Avg. risk" value={totals.avgRisk} sub="Confidence-weighted" />
        <Kpi label="Critical + high" value={totals.crit + totals.high} sub={`${totals.crit} critical · ${totals.high} high`} />
        <Kpi label="Tunnels / SAs" value="4 / 12" sub="2 transport-exposed · 1 NAT-T" />
        <Kpi label="AI confidence" value={`${totals.avgConf}%`} sub="Calibrated + conformal" />
        <Kpi label="Lab sessions" value={sessionCount ?? "112"} sub={live ? "Indexed from bridge" : "Sample snapshot"} />
      </div>

      {/* Trend + severity + traffic */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel
          title="Security score and risk trend"
          className="xl:col-span-6"
          right={<span className="text-xs">Score 0–100 · risk weighted by confidence</span>}
        >
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={trend} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
                <CartesianGrid stroke={GRID} vertical={false} />
                <XAxis dataKey="t" tick={TICK} axisLine={false} tickLine={false} />
                <YAxis tick={TICK} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={TOOLTIP} labelStyle={{ color: "#a1a1aa" }} />
                <Area type="monotone" dataKey="score" stroke="#e4e4e7" fill="#e4e4e7" fillOpacity={0.07} strokeWidth={1.75} name="Score" />
                <Line type="monotone" dataKey="risk" stroke="#71717a" strokeDasharray="4 3" strokeWidth={1.5} dot={false} name="Risk" />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
          <div className="flex gap-4 px-1 pt-2 text-xs text-zinc-500">
            <span><span className="text-zinc-200">—</span> Security score</span>
            <span><span className="text-zinc-500">- -</span> Risk score</span>
          </div>
        </SocPanel>

        <SocPanel title="Findings by severity" className="xl:col-span-3">
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={SEVERITY_TOTALS} layout="vertical" margin={{ top: 4, right: 12, bottom: 0, left: 0 }} barCategoryGap="28%">
                <CartesianGrid stroke={GRID} horizontal={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="sev" type="category" tick={{ fill: "#a1a1aa", fontSize: 12, textTransform: "capitalize" } as any} axisLine={false} tickLine={false} width={64} />
                <Tooltip contentStyle={TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                <Bar dataKey="count" radius={[4, 4, 4, 4]}>
                  {SEVERITY_TOTALS.map((s) => (
                    <Cell key={s.sev} fill={SEV_FILL[s.sev]} fillOpacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-xs text-zinc-500">Rule pack <span className="soc-num text-zinc-400">ipsec-baseline</span></p>
        </SocPanel>

        <SocPanel title="Encrypted traffic mix" className="xl:col-span-3" right={<span className="text-xs">ML · 7 classes</span>}>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={TRAFFIC_MIX} dataKey="value" nameKey="name" innerRadius={42} outerRadius={64} paddingAngle={3} strokeWidth={0} opacity={0.9}>
                  {TRAFFIC_MIX.map((_, i) => (
                    <Cell key={i} fill={TRAFFIC_COLORS[i % TRAFFIC_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
            {TRAFFIC_MIX.slice(0, 6).map((t, i) => (
              <div key={t.name} className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: TRAFFIC_COLORS[i % TRAFFIC_COLORS.length] }} />
                <span className="capitalize text-zinc-400">{t.name}</span>
                <span className="soc-num ml-auto text-zinc-300">{t.value}%</span>
              </div>
            ))}
          </div>
          <p className="mt-3 flex items-start gap-1.5 rounded-lg bg-white/[0.03] px-2.5 py-2 text-xs leading-relaxed text-zinc-400 ring-1 ring-inset ring-white/[0.06]">
            <Lock className="mt-0.5 h-3 w-3 shrink-0 text-zinc-500" />
            VoIP identified at 0.90 confidence inside ESP — packet sizes still leak application class.
          </p>
        </SocPanel>
      </div>

      {/* Recent analyses + top findings */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel
          title="Recent analyses"
          className="xl:col-span-7"
          pad={false}
          right={
            <Link href="/analyses/new" className="flex items-center gap-1 text-xs font-medium text-zinc-300 hover:text-zinc-100">
              Open intake <ArrowRight className="h-3 w-3" />
            </Link>
          }
        >
          <div className="soc-scroll overflow-x-auto">
            <table className="w-full min-w-[620px] text-left text-[13px]">
              <thead>
                <tr className="border-b border-white/[0.06] text-xs font-medium text-zinc-500">
                  <th className="px-4 py-2.5 font-medium">Capture</th>
                  <th className="px-3 py-2.5 font-medium">Score</th>
                  <th className="px-3 py-2.5 font-medium">Risk</th>
                  <th className="px-3 py-2.5 font-medium">Severity</th>
                  <th className="px-3 py-2.5 font-medium">Conf.</th>
                  <th className="px-4 py-2.5 text-right font-medium" />
                </tr>
              </thead>
              <tbody>
                {DEMO_ANALYSES.map((a) => (
                  <tr key={a.id} className="border-b border-white/[0.04] last:border-0 transition-colors hover:bg-white/[0.02]">
                    <td className="px-4 py-3">
                      <div className="font-medium text-zinc-100">{a.caption}</div>
                      <div className="soc-num mt-0.5 max-w-[360px] truncate text-[11px] text-zinc-500">{a.profile}</div>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3">
                      <span className={`soc-num text-[15px] font-semibold ${scoreTone(a.score)}`}>{a.score}</span>{" "}
                      <span className="soc-num text-xs text-zinc-500">{a.grade}</span>
                    </td>
                    <td className="soc-num px-3 py-3 text-zinc-300">{a.risk.toFixed(1)}</td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-1.5">
                        {a.severity.critical > 0 && <SevBadge sev="critical" />}
                        {a.severity.high > 0 && <SevBadge sev="high" />}
                        {a.severity.high === 0 && a.severity.critical === 0 && <SevBadge sev="low" />}
                        <span className="soc-num text-[11px] text-zinc-500">+{a.severity.medium} med</span>
                      </div>
                    </td>
                    <td className="soc-num px-3 py-3 text-zinc-300">{Math.round(a.confidence * 100)}%</td>
                    <td className="px-4 py-3 text-right">
                      <Link href={`/analyses/${a.id}`} className="rounded-md px-2 py-1 text-xs font-medium text-zinc-400 transition-colors hover:bg-white/[0.06] hover:text-zinc-100">
                        Open
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SocPanel>

        <SocPanel title="Top findings" className="xl:col-span-5" right={<span className="text-xs">ipsec-baseline</span>}>
          <ul className="space-y-2">
            {[
              { id: "CRYPTO-001", sev: "high", title: "Weak DH group 2 in IKE + ESP", meta: "p03 · p13 · observed · RFC 8247 §2.4" },
              { id: "IKE-001", sev: "critical", title: "IKEv1 Main Mode accepted (legacy)", meta: "p13 · observed · migrate to IKEv2" },
              { id: "PFS-001", sev: "medium", title: "PFS disabled — rekey without KE payload", meta: "p03 · p13 · inferred 0.88" },
              { id: "META-001", sev: "medium", title: "Application class leaks via ESP size and timing", meta: "VoIP 0.90 · video bursts" },
              { id: "INTEG-002", sev: "high", title: "HMAC-SHA1-96 integrity truncation", meta: "p03 · p09 · inferred 0.98" },
            ].map((f) => (
              <li key={f.id} className="flex items-start gap-2.5 rounded-lg border border-white/[0.05] bg-white/[0.015] px-3 py-2.5">
                <SevBadge sev={f.sev} />
                <div className="min-w-0">
                  <div className="truncate text-[13px] font-medium text-zinc-200">
                    <span className="soc-num font-normal text-zinc-500">{f.id}</span> · {f.title}
                  </div>
                  <div className="mt-0.5 truncate text-xs text-zinc-500">{f.meta}</div>
                </div>
              </li>
            ))}
          </ul>
          <Link href="/analyses/an_p03_weak/findings" className="mt-3 flex items-center justify-center rounded-lg border border-white/[0.07] py-2 text-[13px] font-medium text-zinc-300 transition-colors hover:bg-white/[0.04] hover:text-zinc-100">
            Open findings workbench
          </Link>
        </SocPanel>
      </div>

      {/* Tunnels + throughput + feed */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel title="Tunnels" className="xl:col-span-5" pad={false} right={<span className="text-xs">SPI · suite</span>}>
          <ul className="divide-y divide-white/[0.05]">
            {TUNNELS.map((t) => (
              <li key={t.sa} className="flex items-center gap-3 px-4 py-3">
                <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: t.score >= 80 ? "#34d399" : t.score >= 60 ? "#fbbf24" : "#f87171" }} />
                <div className="min-w-0 flex-1">
                  <div className="soc-num text-[13px] font-medium text-zinc-100">{t.sa} <span className="font-normal text-zinc-500">· {t.mode}</span></div>
                  <div className="soc-num mt-0.5 truncate text-[11px] text-zinc-500">{t.peers} · {t.cipher} · {t.dh} · PFS {t.pfs ? "on" : "off"}</div>
                </div>
                <div className="text-right">
                  <div className={`soc-num text-[15px] font-semibold ${scoreTone(t.score)}`}>{t.score}</div>
                  <div className="text-[10px] text-zinc-600">{t.tag}</div>
                </div>
              </li>
            ))}
          </ul>
          <div className="border-t border-white/[0.06] p-3">
            <Link href="/lab" className="flex items-center justify-center rounded-lg bg-white/[0.05] py-2 text-[13px] font-medium text-zinc-200 transition-colors hover:bg-white/[0.08]">
              Compare against ground truth in the lab
            </Link>
          </div>
        </SocPanel>

        <SocPanel title="Bridge throughput" className="xl:col-span-3"
          right={live && <span className="flex items-center gap-1.5 text-xs text-zinc-500"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Live</span>}>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={THROUGHPUT} margin={{ top: 8, right: 4, bottom: 0, left: -20 }}>
                <CartesianGrid stroke={GRID} vertical={false} />
                <XAxis dataKey="t" tick={TICK} axisLine={false} tickLine={false} />
                <YAxis tick={TICK} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                <Bar dataKey="esp" fill="#a1a1aa" fillOpacity={0.5} radius={[3, 3, 0, 0]} name="ESP pkt/s" />
                <Line type="monotone" dataKey="ike" stroke="#e4e4e7" strokeWidth={1.5} dot={false} name="IKE msg" />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-1 flex items-center justify-between text-xs text-zinc-500">
            <span>ESP packets/s · IKE messages</span>
            <Link href="/live" className="font-medium text-zinc-300 hover:text-zinc-100">Live view →</Link>
          </div>
        </SocPanel>

        <SocPanel title="Activity" className="xl:col-span-4" pad={false} right={<span className="text-xs">posture · ml · parse</span>}>
          <ul className="soc-scroll max-h-[290px] overflow-y-auto p-2">
            {THREAT_FEED.map((e, i) => (
              <li key={i} className="flex items-start gap-2.5 rounded-lg px-2 py-2 transition-colors hover:bg-white/[0.02]">
                <span className="soc-num mt-0.5 shrink-0 text-[11px] text-zinc-600">{e.ts}</span>
                <span className="mt-[5px] h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEV_DOT[e.sev] }} />
                <p className="min-w-0 text-xs leading-relaxed text-zinc-400">{e.msg}</p>
              </li>
            ))}
          </ul>
        </SocPanel>
      </div>
    </div>
  );
}
