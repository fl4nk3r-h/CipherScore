"use client";
// Screen 8 — Lab (mvp.md §4): profile matrix, run a profile, session list with
// ground-truth vs predicted comparison (accuracy proof, §10 step 6).
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import { api } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ErrorState, EmptyState, CardSkeletons } from "@/components/states";
import type { LabProfile, LabRunStatus, LabSession, SessionAccuracy } from "@/lib/types";

const FIELD_LABELS: Record<string, string> = {
  ike_version: "IKE version",
  mode: "Mode",
  enc: "Encryption",
  key_bits: "Key size",
  integ: "Integrity",
  dh_group: "CHILD_SA DH group",
  ike_dh_group: "IKE DH group",
  pfs: "PFS",
  nat_t: "NAT-T",
  traffic: "Traffic",
};

const DEFAULT_PROFILES = ["p03", "p07"];
const DEFAULT_TRAFFIC = ["voip", "web"];

function formatDuration(seconds: number | null): string {
  if (seconds == null) return "Calculating…";
  if (seconds < 60) return "less than 1 min";
  const minutes = Math.ceil(seconds / 60);
  return minutes < 60 ? `${minutes} min` : `${Math.floor(minutes / 60)} hr ${minutes % 60} min`;
}

function fmt(value: string | number | boolean | null | undefined): string {
  if (value == null) return "—";
  return String(value);
}

function statusVariant(status: string): "success" | "default" | "secondary" | "destructive" {
  if (status === "completed") return "success";
  if (status === "running") return "default";
  if (status === "failed") return "destructive";
  return "secondary";
}

export default function Lab() {
  const { data: profiles, error: profilesError, mutate: reloadProfiles } = useSWR<LabProfile[]>(
    "/lab/profiles", api.fetchArray);
  const { data: sessions, error: sessionsError, mutate: reloadSessions } = useSWR<LabSession[]>(
    "/lab/sessions", api.fetchArray, { refreshInterval: 5000 });

  const { data: run, error: runStatusError, mutate: reloadRun } = useSWR<LabRunStatus | null>(
    "/lab/runs/current", api.fetcher, { refreshInterval: 2000 });

  const [selected, setSelected] = useState<string[]>(DEFAULT_PROFILES);
  const [starting, setStarting] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [analyzing, setAnalyzing] = useState<Set<string>>(new Set());
  const [analyzeError, setAnalyzeError] = useState<string | null>(null);

  const sessionList = Array.isArray(sessions) ? sessions : [];
  const profileList = Array.isArray(profiles) ? profiles : [];

  const runActive = run?.status === "queued" || run?.status === "running";
  useEffect(() => {
    if (run && !runActive) void reloadSessions();
  }, [run?.run_id, run?.status, runActive, reloadSessions]);

  const accuracy = useMemo(() => {
    const accs = sessionList.map((s) => s.accuracy).filter((a): a is SessionAccuracy => a?.status === "completed" && a.eligible > 0);
    const fields: Record<string, { hit: number; seen: number }> = {};
    let totalMatched = 0;
    let totalCompared = 0;
    let totalEligible = 0;
    for (const a of accs) {
      totalEligible += a.eligible;
      for (const [field, ok] of Object.entries(a.match)) {
        if (ok == null) continue;
        fields[field] ??= { hit: 0, seen: 0 };
        fields[field].seen += 1;
        if (ok) fields[field].hit += 1;
        totalCompared += 1;
        if (ok) totalMatched += 1;
      }
    }
    const rate = totalEligible ? totalMatched / totalEligible : null;
    return { analyzed: accs.length, totalMatched, totalCompared, totalEligible, rate, fields };
  }, [sessionList]);

  async function runSelected() {
    setRunError(null);
    setStarting(true);
    try {
      await api.post<LabRunStatus>("/lab/runs", {
        profile_ids: selected,
        traffic_types: DEFAULT_TRAFFIC,
      });
      await reloadRun();
    } catch (cause) {
      setRunError(cause instanceof Error ? cause.message : "could not start lab run");
    } finally {
      setStarting(false);
    }
  }

  async function analyzeSession(sessionId: string) {
    setAnalyzeError(null);
    setAnalyzing((prev) => new Set(prev).add(sessionId));
    try {
      await api.post<{ analysis_id: string }>("/analyses", { lab_session_id: sessionId });
      await reloadSessions();
    } catch (cause) {
      setAnalyzeError(cause instanceof Error ? cause.message : "could not analyze session");
    } finally {
      setAnalyzing((prev) => {
        const next = new Set(prev);
        next.delete(sessionId);
        return next;
      });
    }
  }

  const toggleExpand = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const sessionError = sessionsError ?? profilesError ?? runStatusError;
  const loading = (!sessions && !sessionsError) || (!profiles && !profilesError);

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <h1 className="text-xl font-semibold tracking-tight text-zinc-50">Lab</h1>

      {(sessionError || runError || analyzeError) && (
        <div role="alert" className="space-y-2">
          {sessionError && (
            <ErrorState message={`Could not load lab data: ${sessionError.message}`} onRetry={() => { reloadSessions(); reloadProfiles(); reloadRun(); }} />
          )}
          {runError && <ErrorState message={`Could not start Lab run: ${runError}`} />}
          {analyzeError && <ErrorState message={`Analysis failed: ${analyzeError}`} />}
        </div>
      )}

      <Card>
        <CardHeader className="flex-row items-start justify-between">
          <div>
            <CardTitle>Profile matrix (16 base profiles)</CardTitle>
            <CardDescription>
              Run VoIP + Web against the selected profiles; each produces a labelled session.
            </CardDescription>
          </div>
          <Button size="sm" variant="ghost" onClick={() => setSelected(profileList.map((p) => p.id))}>
            Select all
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setSelected([])}
            aria-label="Clear profile selection"
          >
            Clear
          </Button>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-2 md:grid-cols-4" role="group" aria-label="Profiles">
            {profileList.map((p) => (
              <label
                key={p.id}
                className="flex items-center gap-2 rounded border border-zinc-800 p-2 text-xs hover:border-zinc-600"
              >
                <input
                  type="checkbox"
                  checked={selected.includes(p.id)}
                  onChange={(e) =>
                    setSelected((prev) =>
                      e.target.checked ? [...prev, p.id] : prev.filter((x) => x !== p.id))}
                  aria-label={`Select profile ${p.id}`}
                  className="h-3.5 w-3.5 accent-cyan-500"
                />
                <span>
                  <b>{p.id}</b> {p.spec?.mode}/{p.spec?.ip_family}
                  <span className="text-zinc-500"> {p.spec?.esp_proposal}</span>
                </span>
              </label>
            ))}
          </div>
          <Button
            className="mt-3"
            disabled={starting || runActive || selected.length === 0}
            aria-busy={starting || runActive}
            onClick={runSelected}
          >
            {starting ? "Starting run…" : runActive ? "Lab run in progress" : `Run selected (${DEFAULT_TRAFFIC.join(" + ")})`}
          </Button>
        </CardContent>
      </Card>

      {run && (
        <Card role="status" aria-live="polite">
          <CardHeader className="flex-row items-center justify-between gap-3">
            <div>
              <CardTitle>Lab run</CardTitle>
              <CardDescription>{run.phase || "Preparing run"}</CardDescription>
            </div>
            <Badge variant={run.status === "completed" ? "success" : run.status === "failed" ? "destructive" : "secondary"}>
              {run.status}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span className="font-mono text-zinc-200">{run.current_session || run.run_id}</span>
              {runActive && <span className="text-cyan-300">ETA approx. {formatDuration(run.eta_seconds)}</span>}
            </div>
            {run.total > 0 && (
              <>
                <Progress value={(run.processed / run.total) * 100} aria-label="Lab run progress" tone="cyan" />
                <p className="text-xs text-zinc-400">
                  {run.processed} of {run.total} sessions processed · {run.completed} captured · {run.skipped} already valid
                  {run.failed > 0 ? ` · ${run.failed} failed` : ""}
                </p>
              </>
            )}
            {(run.error || run.last_error) && <p className="text-xs text-red-300">{run.error || run.last_error}</p>}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Passive matches across sessions</CardTitle>
          <CardDescription>PCAP analysis only. Missing predictions count against passive coverage; gateway evidence is reported separately.</CardDescription>
        </CardHeader>
        <CardContent>
          {accuracy.analyzed ? (
            <div className="space-y-1 text-xs text-zinc-400">
              <div className="flex justify-between">
                <span>{accuracy.analyzed} of {sessionList.length} analyzed sessions</span>
                <span>
                  {accuracy.totalMatched}/{accuracy.totalEligible} fields match · {accuracy.totalCompared} compared
                  ({accuracy.rate != null ? `${(accuracy.rate * 100).toFixed(1)}%` : "—"})
                </span>
              </div>
              <Progress
                value={accuracy.rate != null ? accuracy.rate * 100 : 0}
                aria-label="Overall field match and prediction coverage"
                className="mb-3"
                tone="emerald"
              />
              <table className="w-full max-w-lg">
                <tbody>
                  {Object.entries(accuracy.fields)
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([field, { hit, seen }]) => (
                      <tr key={field} className="border-t border-zinc-800">
                        <td className="py-1 capitalize">{FIELD_LABELS[field] ?? field}</td>
                        <td className="text-right">
                          <span className="text-emerald-300">{hit}</span>
                          <span className="text-zinc-500">/{seen}</span>
                        </td>
                        <td className="w-32">
                          <Progress
                            value={seen ? (hit / seen) * 100 : 0}
                            aria-label={`${FIELD_LABELS[field] ?? field} match rate`}
                            tone={seen && hit === seen ? "emerald" : "amber"}
                          />
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-zinc-500">
              {sessionList.length
                ? "No sessions have been analyzed yet."
                : "No lab sessions yet — run a profile above."}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sessions — passive analysis and gateway verification</CardTitle>
          <CardDescription>
            Saved captures can be analyzed again after training. A missing prediction counts as an unmatched field.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <CardSkeletons rows={3} />
          ) : sessionList.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8"><span className="sr-only">Expand</span></TableHead>
                  <TableHead>Session</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Ground truth traffic</TableHead>
                  <TableHead>Predicted traffic</TableHead>
                  <TableHead>Passive matches</TableHead>
                  <TableHead>Verified fields</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessionList.map((s) => {
                  const isOpen = expanded.has(s.session_id);
                  const runningNow = analyzing.has(s.session_id);
                  return (
                    <FragmentRow
                      key={s.session_id}
                      open={isOpen}
                      runningNow={runningNow}
                      session={s}
                      onToggle={() => toggleExpand(s.session_id)}
                      onAnalyze={() => analyzeSession(s.session_id)}
                    />
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <EmptyState
              title="No lab sessions"
              description="Run a profile above to generate sessions with ground-truth labels, then analyze one to compare predictions."
              action={
                <Button size="sm" variant="outline" onClick={() => reloadSessions()}>
                  Refresh
                </Button>
              }
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function FragmentRow({
  session,
  open,
  runningNow,
  onToggle,
  onAnalyze,
}: {
  session: LabSession;
  open: boolean;
  runningNow: boolean;
  onToggle: () => void;
  onAnalyze: () => void;
}) {
  const acc = session.accuracy;
  const predicted = acc?.predicted?.traffic;
  const rate = acc?.match_rate;
  const busy = runningNow ||
    (acc != null && (acc.status === "queued" || acc.status === "running"));
  return (
    <>
      <TableRow>
        <TableCell>
          <Button
            size="icon"
            variant="ghost"
            onClick={onToggle}
            aria-expanded={open}
            aria-controls={`detail-${session.session_id}`}
            aria-label={`Field comparison for ${session.session_id}`}
            className="h-6 w-6 text-zinc-400"
          >
            {open ? "▾" : "▸"}
          </Button>
        </TableCell>
        <TableCell className="font-mono text-xs">{session.session_id}</TableCell>
        <TableCell>{session.profile}</TableCell>
        <TableCell>{session.traffic_type}</TableCell>
        <TableCell>
          {predicted ? (
            <span className="capitalize">{predicted}</span>
          ) : session.capture_issue ? (
            <span className="text-red-300" title={session.capture_issue}>invalid capture</span>
          ) : acc ? (
            <span className="text-zinc-500" title="Traffic model is untrained or abstained">not predicted</span>
          ) : (
            "—"
          )}
        </TableCell>
        <TableCell>
          {rate != null ? (
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold">{(rate * 100).toFixed(0)}%</span>
              <Progress value={rate * 100} className="w-24" tone="emerald" />
              <span className="text-xs text-zinc-500">
                  {acc?.matched}/{acc?.eligible} · {acc?.compared} compared
              </span>
            </div>
          ) : session.capture_issue ? (
            <span className="text-xs text-red-300" title={session.capture_issue}>invalid capture</span>
          ) : acc?.status === "completed" ? (
            <span className="text-xs text-zinc-500">no comparable fields</span>
          ) : acc ? (
            <Badge variant={statusVariant(acc.status)}>{acc.status}</Badge>
          ) : (
            <span className="text-zinc-600">not analyzed</span>
          )}
        </TableCell>
        <TableCell className="text-xs">
          {session.verification?.compared
            ? `${session.verification.matched}/${session.verification.compared} match · ${session.verification.compared} verified`
            : <span className="text-zinc-500">unavailable</span>}
        </TableCell>
        <TableCell className="text-right">
          {busy ? (
            <Button size="xs" variant="outline" disabled aria-busy>
              {runningNow ? "Analyzing…" : acc?.status ?? "…"}
            </Button>
          ) : acc?.analysis_id ? (
            <div className="flex justify-end gap-2">
              <Button size="xs" variant="outline" onClick={onAnalyze}>Reanalyze</Button>
              <Button size="xs" variant="outline" asChild>
                <Link href={`/analyses/${acc.analysis_id}`}>View</Link>
              </Button>
            </div>
          ) : (
            <Button size="xs" onClick={onAnalyze}>
              Analyze session
            </Button>
          )}
        </TableCell>
      </TableRow>
      {open && (
        <TableRow id={`detail-${session.session_id}`}>
          <TableCell colSpan={8} className="bg-zinc-950/40 p-3">
            <FieldComparison session={session} />
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

const COMPARABLE = Object.keys(FIELD_LABELS);

function FieldComparison({ session }: { session: LabSession }) {
  const acc = session.accuracy;
  return (
    <div>
      <p className="mb-2 text-xs font-semibold text-zinc-300">Passive analysis from PCAP · {acc ? `${acc.matched}/${acc.eligible} matches` : "not analyzed"}</p>
      <div className="grid grid-cols-1 gap-x-6 sm:grid-cols-2">
      {COMPARABLE.map((field) => {
        const truth = session.labels[field];
        const expected = field === "traffic" ? session.traffic_type : truth;
        const predicted = acc?.predicted?.[field];
        const match = acc?.match?.[field];
        return (
          <div key={field} className="flex items-center justify-between gap-2 border-b border-zinc-800/60 py-1 text-xs">
            <span className="text-zinc-400">{FIELD_LABELS[field]}</span>
            <span className="flex items-center gap-2 font-mono">
              <span title="Ground truth">
                <span className="text-zinc-500">GT&nbsp;</span>{fmt(expected)}
              </span>
              <span className="text-zinc-600">→</span>
              <span title="Predicted">
                <span className="text-zinc-500">Analysis&nbsp;</span>
                <span className={match === false ? "text-red-300" : "text-zinc-100"}>
                  {fmt(predicted)}
                </span>
              </span>
              {match == null ? (
                <Badge variant="outline" className="text-zinc-500">n/a</Badge>
              ) : match ? (
                <Badge variant="success">match</Badge>
              ) : (
                <Badge variant="destructive">mismatch</Badge>
              )}
            </span>
          </div>
        );
      })}
      </div>
      <p className="mb-2 mt-4 text-xs font-semibold text-zinc-300">Gateway verification · {session.verification?.matched ?? 0}/{session.verification?.compared ?? 0} verified fields match</p>
      <div className="grid grid-cols-1 gap-x-6 sm:grid-cols-2">
        {["mode", "enc", "key_bits", "integ", "pfs", "dh_group"].map((field) => {
          const item = session.verification?.fields[field];
          const configured = item?.source === "configured";
          const source = item?.source === "legacy_sa_state" ? "saved SA state"
            : item?.source === "gateway_vici_rekey" ? "VICI rekey"
            : item?.source === "gateway_vici" ? "VICI SA state" : null;
          return <div key={field} className="flex items-center justify-between gap-2 border-b border-zinc-800/60 py-1 text-xs">
            <span className="text-zinc-400">{FIELD_LABELS[field]}</span>
            <span className="flex items-center gap-2 font-mono">
              <span className="text-zinc-500">GT</span>{fmt(session.labels[field])}
              <span className="text-zinc-600">→</span>{fmt(item?.value)}
              <Badge variant={configured ? "outline" : item?.match === true ? "success" : item?.match === false ? "destructive" : "outline"}>
                {configured ? "configured" : item?.source === "unavailable" || !item ? "unavailable" : item.match === true ? "verified match" : item.match === false ? "verified mismatch" : "gateway"}
              </Badge>
              {source && <span className="text-zinc-500" title="Gateway evidence source">{source}</span>}
            </span>
          </div>;
        })}
        <div className="flex items-center justify-between gap-2 border-b border-zinc-800/60 py-1 text-xs">
          <span className="text-zinc-400">IKE DH group</span>
          <span className="font-mono">{fmt(session.labels.ike_dh_group)} <Badge variant="outline">configured</Badge></span>
        </div>
      </div>
    </div>
  );
}
