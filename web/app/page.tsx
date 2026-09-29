"use client";
// Screen 1 — Overview (mvp.md §4): recent analyses, overall Security Score
// trend, top findings across captures.
import Link from "next/link";
import useSWR from "swr";
import { api } from "@/lib/api";
import { ScoreTrend, gradeColor } from "@/components/score-trend";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { ErrorState, EmptyState, CardSkeletons } from "@/components/states";
import type { AnalysisListItem, LabSession, TopFinding, Severity } from "@/lib/types";

const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function statusVariant(status: string): NonNullable<BadgeProps["variant"]> {
  switch (status) {
    case "completed": return "success";
    case "running": return "default";
    case "failed": return "destructive";
    default: return "secondary";
  }
}

function aggregateTopFindings(analyses: AnalysisListItem[]): TopFinding[] {
  const byId = new Map<string, TopFinding & { analyses: number }>();
  for (const a of analyses) {
    for (const t of a.top_findings) {
      const key = t.rule_id;
      const cur = byId.get(key);
      if (cur) {
        cur.count += t.count;
        cur.analyses += 1;
      } else {
        byId.set(key, { ...t, analyses: 1 });
      }
    }
  }
  return [...byId.values()]
    .sort((x, y) =>
      SEV_ORDER[x.severity] - SEV_ORDER[y.severity] || y.count - x.count || y.analyses - x.analyses)
    .slice(0, 6);
}

export default function Overview() {
  const { data: analyses, error, mutate } = useSWR<AnalysisListItem[]>("/analyses", api.fetcher);
  const { data: sessions } = useSWR<LabSession[]>("/lab/sessions", api.fetcher);
  const { data: health } = useSWR<unknown>("/healthz", api.fetcher);

  const items = analyses ?? [];
  const scored = items.filter((a) => a.security_score != null);
  const avgScore = scored.length
    ? Math.round(scored.reduce((s, a) => s + (a.security_score ?? 0), 0) / scored.length)
    : null;
  const topFindings = aggregateTopFindings(items);

  const stats = [
    {
      label: "API",
      value: health ? "online" : "offline",
      detail: health ? <span className="text-emerald-400">● online</span> : <span>● offline</span>,
    },
    { label: "Analyses", value: String(items.length), detail: `${scored.length} scored` },
    { label: "Lab sessions", value: String(sessions?.length ?? "…"), detail: "ground truth available" },
    { label: "Avg Security Score", value: avgScore == null ? "—" : String(avgScore), detail: "across captures" },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Overview</h1>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((s) => (
          <Card key={s.label}>
            <CardHeader className="pb-1">
              <CardDescription>{s.label}</CardDescription>
              <CardTitle className="text-2xl">{s.value}</CardTitle>
            </CardHeader>
            <CardContent className="pb-3 text-xs text-slate-500">{s.detail}</CardContent>
          </Card>
        ))}
      </div>

      {error && <ErrorState message={`Could not load overview: ${error.message}`} onRetry={mutate} />}

      <Card>
        <CardHeader>
          <CardTitle>Security Score trend</CardTitle>
          <CardDescription>Most recent analyses, oldest to newest</CardDescription>
        </CardHeader>
        <CardContent>
          {!analyses && !error ? (
            <CardSkeletons rows={1} />
          ) : scored.length ? (
            <ScoreTrend analyses={items} />
          ) : (
            <p className="text-sm text-slate-500">No scored analyses yet — run one under New Analysis.</p>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent analyses</CardTitle>
            <CardDescription>Latest results across all captures</CardDescription>
          </CardHeader>
          <CardContent>
            {!analyses && !error ? (
              <CardSkeletons rows={3} />
            ) : items.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Analysis</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((a) => (
                    <TableRow key={a.analysis_id}>
                      <TableCell>
                        <Link
                          href={`/analyses/${a.analysis_id}`}
                          className="font-mono text-xs text-cyan-300 hover:text-cyan-200 hover:underline"
                        >
                          {a.analysis_id}
                        </Link>
                        <Badge variant={statusVariant(a.status)} className="ml-2">
                          {a.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span style={{ color: gradeColor(a.grade) }} className="font-bold">
                          {a.security_score ?? "—"}
                        </span>{" "}
                        {a.grade && <span className="text-xs text-slate-400">({a.grade})</span>}
                      </TableCell>
                      <TableCell>{a.risk_score ?? "—"}</TableCell>
                      <TableCell>
                        {a.ai_confidence != null ? `${Math.round(a.ai_confidence * 100)}%` : "—"}
                      </TableCell>
                      <TableCell className="text-xs text-slate-400">{a.created.slice(0, 16)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                title="No analyses yet"
                description="Run make demo to seed three pre-analyzed captures, or upload a PCAP under New Analysis."
                action={
                  <Button asChild size="sm">
                    <Link href="/analyses/new">New Analysis</Link>
                  </Button>
                }
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top findings across captures</CardTitle>
            <CardDescription>Most frequent high-impact findings</CardDescription>
          </CardHeader>
          <CardContent>
            {!analyses && !error ? (
              <CardSkeletons rows={3} />
            ) : topFindings.length ? (
              <ul className="space-y-2" data-testid="top-findings">
                {topFindings.map((t) => (
                  <li key={t.rule_id} className="flex items-center justify-between gap-2 text-sm">
                    <div className="min-w-0">
                      <p className="truncate font-medium">
                        <span className="font-mono text-xs text-cyan-300">{t.rule_id}</span> · {t.title}
                      </p>
                      <p className="text-xs text-slate-500">
                        {t.count} finding{t.count === 1 ? "" : "s"} across {t.analyses} analysis
                        {t.analyses === 1 ? "" : "es"}
                      </p>
                    </div>
                    <SeverityBadge severity={t.severity} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-500">
                Nothing flagged yet — findings appear once analyses complete.
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}