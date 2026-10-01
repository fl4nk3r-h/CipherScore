"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import useSWR from "swr";
import {
  Area, Bar, BarChart, CartesianGrid, Cell, ComposedChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { ArrowRight, FileUp, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { Kpi, SevBadge, SocPanel } from "@/components/soc-panels";
import { CardSkeletons } from "@/components/states";
import type { AnalysisListItem, LabSession, SAEvidence, Severity, TopFinding } from "@/lib/types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const COLORS: Record<Severity, string> = {
  critical: "#f87171", high: "#fb923c", medium: "#fbbf24", low: "#34d399", info: "#71717a",
};
const TRAFFIC_COLORS = ["#38bdf8", "#a78bfa", "#34d399", "#fbbf24", "#fb923c", "#f87171", "#71717a"];
const TICK = { fill: "#71717a", fontSize: 11 };
const TOOLTIP = { background: "#18181b", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12, color: "#e4e4e7" };
const RANGES = ["24H", "7D", "30D", "Recent"] as const;

type Alert = { id: string; timestamp: number; threat_class: string; severity: Severity; confidence: number };

type FindingTotal = TopFinding & { analyses: number };

function timestamp(value: string): number {
  const normalized = value.includes("T") ? value : value.replace(" ", "T") + "Z";
  return Date.parse(normalized);
}

function scoreTone(score: number | null) {
  if (score == null) return "text-zinc-400";
  if (score >= 80) return "text-emerald-300";
  if (score >= 60) return "text-amber-200";
  return "text-red-300";
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="flex min-h-32 items-center justify-center px-4 text-center text-sm text-zinc-500">{children}</p>;
}

export default function SocOverview() {
  const [range, setRange] = useState<(typeof RANGES)[number]>("7D");
  const [refreshing, setRefreshing] = useState(false);
  const { data: analyses, error: analysesError, mutate: reloadAnalyses } = useSWR<AnalysisListItem[]>(
    "/analyses?limit=200", api.fetchArray, { refreshInterval: 10000 });
  const { data: sessions, error: sessionsError, mutate: reloadSessions } = useSWR<LabSession[]>(
    "/lab/sessions", api.fetchArray, { refreshInterval: 30000 });
  const { data: alerts, error: alertsError, mutate: reloadAlerts } = useSWR<Alert[]>(
    "/threats/alerts?limit=50", api.fetchArray, { refreshInterval: 10000 });

  const analysisList = Array.isArray(analyses) ? analyses : [];
  const sessionList = Array.isArray(sessions) ? sessions : [];
  const alertList = Array.isArray(alerts) ? alerts : [];
  const latestCompleted = analysisList.find((a) => a.status === "completed" && a.sa_count > 0);
  const saKey = latestCompleted ? `/analyses/${latestCompleted.analysis_id}/sas` : null;
  const { data: sas, error: sasError, mutate: reloadSas } = useSWR<SAEvidence[]>(saKey, api.fetchArray);
  const saList = Array.isArray(sas) ? sas : [];

  const visibleAnalyses = useMemo(() => {
    const hours = range === "24H" ? 24 : range === "7D" ? 168 : range === "30D" ? 720 : 0;
    const cutoff = Date.now() - hours * 3600000;
    return analysisList.filter((a) => !hours || timestamp(a.created) >= cutoff);
  }, [analysisList, range]);
  const scored = visibleAnalyses.filter((a) => a.security_score != null);
  const findingsSource = visibleAnalyses.find((a) => a.top_findings?.length);
  const totals = useMemo(() => {
    const severity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    const findings = new Map<string, FindingTotal>();
    for (const a of visibleAnalyses) {
      for (const s of SEVERITIES) severity[s] += a.findings?.[s] ?? 0;
      for (const f of a.top_findings ?? []) {
        const current = findings.get(f.rule_id);
        if (current) { current.count += f.count; current.analyses += 1; }
        else findings.set(f.rule_id, { ...f, analyses: 1 });
      }
    }
    const scoredItems = visibleAnalyses.filter((a) => a.security_score != null);
    const confident = visibleAnalyses.filter((a) => a.ai_confidence != null && a.ai_confidence > 0);
    const avg = (values: number[]) => values.length ? values.reduce((sum, n) => sum + n, 0) / values.length : null;
    return {
      severity,
      findings: [...findings.values()].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || b.count - a.count).slice(0, 6),
      score: avg(scoredItems.map((a) => a.security_score!)),
      risk: avg(visibleAnalyses.flatMap((a) => a.risk_score == null ? [] : [a.risk_score])),
      confidence: avg(confident.map((a) => a.ai_confidence!)),
      saCount: visibleAnalyses.reduce((sum, a) => sum + (a.sa_count ?? 0), 0),
    };
  }, [visibleAnalyses]);
  const trend = [...scored].sort((a, b) => timestamp(a.created) - timestamp(b.created)).slice(-20)
    .map((a) => ({ t: a.created.slice(5, 16).replace("T", " "), score: a.security_score, risk: a.risk_score }));
  const severityData = SEVERITIES.map((sev) => ({ sev, count: totals.severity[sev] }));
  const trafficCounts = new Map<string, number>();
  for (const sa of saList) {
    const type = sa.traffic?.top;
    if (type) trafficCounts.set(type, (trafficCounts.get(type) ?? 0) + 1);
  }
  const traffic = [...trafficCounts].map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  const trafficTotal = traffic.reduce((sum, t) => sum + t.value, 0);

  async function refresh() {
    setRefreshing(true);
    try { await Promise.all([reloadAnalyses(), reloadSessions(), reloadAlerts(), reloadSas()]); }
    finally { setRefreshing(false); }
  }

  if (!analyses && !analysesError) return <div className="mx-auto max-w-[1400px] space-y-5"><h1 className="text-xl font-semibold text-zinc-50">Overview</h1><CardSkeletons rows={3} /></div>;

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-50">Overview</h1>
          <p className="mt-1 text-[13px] text-zinc-500">IPsec VPN posture from analyzed captures</p>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-0.5 rounded-lg border border-white/[0.07] bg-white/[0.02] p-0.5" role="group" aria-label="Analysis time range">
            {RANGES.map((r) => <button key={r} onClick={() => setRange(r)} aria-pressed={range === r}
              className={`soc-num rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${range === r ? "bg-white/10 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"}`}>{r}</button>)}
          </div>
          <button onClick={refresh} disabled={refreshing} aria-label="Refresh overview"
            className="flex items-center gap-1.5 rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-[7px] text-[13px] text-zinc-300 hover:bg-white/[0.05] disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} /> Refresh
          </button>
          <Link href="/analyses/new" className="flex items-center gap-1.5 rounded-lg bg-cyan-700 px-3 py-[7px] text-[13px] font-medium text-white hover:bg-cyan-600">
            <FileUp className="h-3.5 w-3.5" /> New analysis
          </Link>
        </div>
      </div>

      {(analysesError || sessionsError || alertsError || sasError) &&
        <div role="alert" className="rounded-lg border border-red-400/20 bg-red-400/[0.06] px-3 py-2 text-[13px] text-red-200">
          Some overview data could not be loaded. Check the API connection and refresh.
        </div>}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Avg. security score" value={<span className={scoreTone(totals.score)}>{totals.score == null ? "—" : Math.round(totals.score)}</span>} sub={`Across ${scored.length} scored analyses`} />
        <Kpi label="Avg. risk" value={totals.risk == null ? "—" : totals.risk.toFixed(1)} sub="Across scored captures" />
        <Kpi label="Critical + high" value={totals.severity.critical + totals.severity.high} sub={`${totals.severity.critical} critical · ${totals.severity.high} high`} />
        <Kpi label="Security associations" value={totals.saCount} sub="Across selected analyses" />
        <Kpi label="AI confidence" value={totals.confidence == null ? "—" : `${Math.round(totals.confidence * 100)}%`} sub="Across classified analyses" />
        <Kpi label="Lab sessions" value={sessionsError ? "—" : sessionList.length} sub="Available for analysis" />
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel title="Security score and risk trend" className="xl:col-span-6" right={<span>Last {trend.length} scored analyses</span>}>
          {trend.length ? <div className="h-60"><ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={trend} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
              <XAxis dataKey="t" tick={TICK} axisLine={false} tickLine={false} /><YAxis tick={TICK} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP} labelStyle={{ color: "#a1a1aa" }} />
              <Area type="monotone" dataKey="score" stroke="#e4e4e7" fill="#e4e4e7" fillOpacity={0.07} strokeWidth={1.75} name="Score" />
              <Area type="monotone" dataKey="risk" stroke="#fbbf24" fill="#fbbf24" fillOpacity={0.03} strokeWidth={1.5} name="Risk" />
            </ComposedChart>
          </ResponsiveContainer></div> : <Empty>No scored analyses in this range.</Empty>}
        </SocPanel>
        <SocPanel title="Findings by severity" className="xl:col-span-3">
          {visibleAnalyses.length ? <div className="h-60"><ResponsiveContainer width="100%" height="100%">
            <BarChart data={severityData} layout="vertical" margin={{ top: 4, right: 12, bottom: 0, left: 0 }} barCategoryGap="28%">
              <CartesianGrid stroke="rgba(255,255,255,0.06)" horizontal={false} /><XAxis type="number" hide />
              <YAxis dataKey="sev" type="category" tick={TICK} axisLine={false} tickLine={false} width={64} />
              <Tooltip contentStyle={TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="count" radius={[4, 4, 4, 4]}>{severityData.map((s) => <Cell key={s.sev} fill={COLORS[s.sev]} />)}</Bar>
            </BarChart>
          </ResponsiveContainer></div> : <Empty>No findings in this range.</Empty>}
        </SocPanel>
        <SocPanel title="Encrypted traffic mix" className="xl:col-span-3" right={<span>Latest completed analysis</span>}>
          {traffic.length ? <>
            <div className="h-44"><ResponsiveContainer width="100%" height="100%"><PieChart>
              <Pie data={traffic} dataKey="value" nameKey="name" innerRadius={42} outerRadius={64} paddingAngle={3} strokeWidth={0}>
                {traffic.map((t, i) => <Cell key={t.name} fill={TRAFFIC_COLORS[i % TRAFFIC_COLORS.length]} />)}
              </Pie><Tooltip contentStyle={TOOLTIP} /></PieChart></ResponsiveContainer></div>
            <div className="space-y-1.5 text-xs">{traffic.map((t, i) => <div key={t.name} className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: TRAFFIC_COLORS[i % TRAFFIC_COLORS.length] }} />
              <span className="capitalize text-zinc-400">{t.name}</span><span className="soc-num ml-auto text-zinc-300">{Math.round(t.value / trafficTotal * 100)}%</span>
            </div>)}</div>
          </> : <Empty>No traffic predictions available yet.</Empty>}
        </SocPanel>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel title="Recent analyses" className="xl:col-span-7" pad={false} right={<Link href="/analyses/new" className="flex items-center gap-1 text-zinc-300 hover:text-zinc-100">Open intake <ArrowRight className="h-3 w-3" /></Link>}>
          {visibleAnalyses.length ? <div className="soc-scroll overflow-x-auto"><table className="w-full min-w-[600px] text-left text-[13px]">
            <thead><tr className="border-b border-white/[0.06] text-xs text-zinc-500">
              <th className="px-4 py-2.5 font-medium">Analysis</th><th className="px-3 py-2.5 font-medium">Status</th><th className="px-3 py-2.5 font-medium">Score</th>
              <th className="px-3 py-2.5 font-medium">Risk</th><th className="px-3 py-2.5 font-medium">SAs</th><th className="px-4 py-2.5 text-right font-medium">Details</th>
            </tr></thead><tbody>{visibleAnalyses.slice(0, 10).map((a) => <tr key={a.analysis_id} className="border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02]">
              <td className="px-4 py-3"><div className="font-medium text-zinc-100">{a.analysis_id}</div><div className="soc-num text-[11px] text-zinc-500">{a.created}</div></td>
              <td className="px-3 py-3 capitalize text-zinc-400">{a.status}</td>
              <td className={`soc-num px-3 py-3 font-semibold ${scoreTone(a.security_score)}`}>{a.security_score == null ? "—" : `${a.security_score} ${a.grade ?? ""}`}</td>
              <td className="soc-num px-3 py-3 text-zinc-300">{a.risk_score == null ? "—" : a.risk_score.toFixed(1)}</td>
              <td className="soc-num px-3 py-3 text-zinc-300">{a.sa_count}</td>
              <td className="px-4 py-3 text-right"><Link href={`/analyses/${a.analysis_id}`} className="rounded-md px-2 py-1 text-xs font-medium text-zinc-300 hover:bg-white/[0.06]">Open</Link></td>
            </tr>)}</tbody>
          </table></div> : <Empty>No analyses in this range. Start one to populate the overview.</Empty>}
        </SocPanel>
        <SocPanel title="Top findings" className="xl:col-span-5" right={<span>Across selected analyses</span>}>
          {totals.findings.length ? <ul className="space-y-2" data-testid="top-findings">{totals.findings.map((f) => <li key={f.rule_id} className="flex items-start gap-2.5 rounded-lg border border-white/[0.05] bg-white/[0.015] px-3 py-2.5">
            <SevBadge sev={f.severity} /><div className="min-w-0"><div className="text-[13px] font-medium text-zinc-200"><span className="soc-num font-normal text-zinc-500">{f.rule_id}</span> · {f.title}</div>
              <div className="mt-0.5 text-xs text-zinc-500">{f.count} finding{f.count === 1 ? "" : "s"} across {f.analyses} analysis{f.analyses === 1 ? "" : "es"}</div></div>
          </li>)}</ul> : <Empty>No findings in this range.</Empty>}
          {findingsSource && <Link href={`/analyses/${findingsSource.analysis_id}/findings`} className="mt-3 flex items-center justify-center rounded-lg border border-white/[0.07] py-2 text-[13px] font-medium text-zinc-300 hover:bg-white/[0.04]">Open findings workbench</Link>}
        </SocPanel>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <SocPanel title="Security associations" className="xl:col-span-7" pad={false} right={latestCompleted ? <Link href={`/analyses/${latestCompleted.analysis_id}/sas`} className="text-zinc-300 hover:text-zinc-100">View all</Link> : undefined}>
          {saList.length ? <ul className="divide-y divide-white/[0.05]">{saList.slice(0, 5).map((sa) => <li key={sa.spi} className="flex items-center gap-3 px-4 py-3">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
            <div className="min-w-0 flex-1"><div className="soc-num text-[13px] font-medium text-zinc-100">{sa.spi} <span className="font-normal text-zinc-500">· {String(sa.mode?.value ?? "mode unknown")}</span></div>
              <div className="soc-num mt-0.5 truncate text-[11px] text-zinc-500">{sa.peers?.join(" → ") || "Peers unknown"} · {String(sa.enc?.value ?? "cipher unknown")} · DH {String(sa.dh_group?.value ?? "unknown")}</div></div>
            <span className="text-xs capitalize text-zinc-400">{sa.traffic?.top ?? "—"}</span>
          </li>)}</ul> : <Empty>No security associations available yet.</Empty>}
        </SocPanel>
        <SocPanel title="Recent threat alerts" className="xl:col-span-5" pad={false} right={<Link href="/threats" className="text-zinc-300 hover:text-zinc-100">View alerts</Link>}>
          {alertList.length ? <ul className="soc-scroll max-h-[320px] overflow-y-auto p-2">{alertList.slice(0, 8).map((a) => <li key={a.id} className="flex items-start gap-2.5 rounded-lg px-2 py-2 hover:bg-white/[0.02]">
            <span className="mt-[5px] h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: COLORS[a.severity] ?? COLORS.info }} />
            <div className="min-w-0"><div className="text-xs capitalize text-zinc-300">{a.threat_class.replaceAll("_", " ")}</div>
              <div className="soc-num mt-0.5 text-[11px] text-zinc-500">{new Date(a.timestamp * 1000).toLocaleString()} · {Math.round(a.confidence * 100)}% confidence</div></div>
          </li>)}</ul> : <Empty>No threat alerts yet. Replay a capture on the Threats page.</Empty>}
        </SocPanel>
      </div>
    </div>
  );
}
