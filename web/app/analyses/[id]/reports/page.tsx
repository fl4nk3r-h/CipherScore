"use client";
// Screen 7 — Reports (mvp.md §4): preview and download of the Executive and
// Technical PDFs + JSON export.
import { use, useState } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { CardSkeletons, ErrorState } from "@/components/states";
import type { ReportContext, Summary } from "@/lib/types";

const REPORTS = [
  { kind: "executive", label: "Executive Report", desc: "2 pages · management" },
  { kind: "technical", label: "Technical Report", desc: "8–20 pages · analysts" },
];

export default function Reports({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data: summary, error: summaryError, mutate: reloadSummary } = useSWR<Summary>(`/analyses/${id}`, api.fetcher, {
    refreshInterval: (current) =>
      current?.status === "completed" || current?.status === "failed" || current === undefined ? 0 : 2000,
  });
  const completed = summary?.status === "completed";

  const { data: report, error: reportError, mutate: reloadReport } = useSWR<ReportContext>(
    completed ? `/analyses/${id}/reports/report.json` : null, api.fetcher);
  const pdfsKey = completed ? `/analyses/${id}/reports/pdf-status` : null;
  const { data: pdfs } = useSWR<Record<string, boolean>>(
    pdfsKey,
    async () => {
      const [exe, tech] = await Promise.all([
        api.headExists(`/analyses/${id}/reports/executive.pdf`),
        api.headExists(`/analyses/${id}/reports/technical.pdf`),
      ]);
      return { executive: exe, technical: tech };
    },
  );
  const [preview, setPreview] = useState<string | null>(null);
  const [showJson, setShowJson] = useState(false);

  const base = api.url(`/analyses/${id}/reports`);

  if (summaryError)
    return <ErrorState message={`Could not load analysis: ${summaryError.message}`} onRetry={reloadSummary} />;
  if (!summary) return <CardSkeletons rows={2} />;
  if (!completed) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Reports</CardTitle>
          <CardDescription>
            Analysis is <span className="capitalize">{summary.status}</span> — reports are generated
            when it completes.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-zinc-100">Reports</h2>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {REPORTS.map((r) => {
          const available = pdfs?.[r.kind] ?? false;
          const show = preview === r.kind;
          return (
            <Card key={r.kind}>
              <CardHeader className="flex-row items-start justify-between gap-3">
                <div>
                  <CardTitle>{r.label}</CardTitle>
                  <CardDescription>{r.desc}</CardDescription>
                </div>
                <Badge variant={available ? "success" : "secondary"}>
                  {pdfs ? (available ? "ready" : "missing") : "checking"}
                </Badge>
              </CardHeader>
              <CardContent className="space-y-3">
                {available ? (
                  <>
                    <div className="flex gap-2">
                      <Button size="sm" variant={show ? "secondary" : "default"}
                        onClick={() => setPreview(show ? null : r.kind)}
                        aria-expanded={show}
                        aria-controls={`preview-${r.kind}`}
                      >
                        {show ? "Hide preview" : "Preview"}
                      </Button>
                      <Button size="sm" variant="outline" asChild>
                        <a href={`${base}/${r.kind}.pdf`} target="_blank" rel="noreferrer">
                          Open / download PDF
                        </a>
                      </Button>
                    </div>
                    {show && (
                      <iframe
                        id={`preview-${r.kind}`}
                        title={`${r.label} preview`}
                        src={`${base}/${r.kind}.pdf`}
                        className="h-[480px] w-full rounded border border-zinc-800 bg-white"
                      />
                    )}
                  </>
                ) : (
                  <p className="text-sm text-zinc-500">
                    {pdfs ? `The ${r.kind} report was not generated for this analysis.` : "Checking report availability…"}
                  </p>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Machine-readable exports</CardTitle>
          <CardDescription>
            report.json (full analysis result) and findings.csv (findings table)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label="Security Score" value={report?.security_score ?? "—"} />
            <Stat label="Grade" value={report?.grade ?? "—"} />
            <Stat label="Risk" value={report?.risk_score ?? "—"} />
            <Stat label="AI Confidence" value={report?.ai_confidence != null ? `${(report.ai_confidence * 100).toFixed(0)}%` : "—"} />
          </div>

          {reportError && (
            <ErrorState message={`report.json unavailable: ${reportError.message}`} onRetry={reloadReport} />
          )}

          {report && report.top_findings.length > 0 && (
            <div className="text-sm">
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-zinc-400">
                Top findings
              </h3>
              <ul className="space-y-1">
                {report.top_findings.map((f, index) => (
                  <li key={`${f.id}-${f.title}-${index}`}>
                    <span className="font-mono text-xs text-cyan-300">{f.id}</span> {f.title}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <Button size="sm" variant="outline" onClick={() => setShowJson((v) => !v)}
            aria-expanded={showJson} aria-controls="json-preview"
          >
            {showJson ? "Hide" : "Show"} raw JSON
          </Button>
          {showJson && report && (
            <pre id="json-preview" className="max-h-80 overflow-auto rounded bg-zinc-950 p-3 text-[11px] text-zinc-300">
              {JSON.stringify(report, null, 2)}
            </pre>
          )}

          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" asChild>
              <a href={`${base}/report.json`} download>Download report.json</a>
            </Button>
            <Button size="sm" variant="outline" asChild>
              <a href={`${base}/findings.csv`} download>Download findings.csv</a>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded border border-zinc-800 bg-zinc-950/40 p-2 text-center">
      <div className="text-xs text-zinc-500">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}