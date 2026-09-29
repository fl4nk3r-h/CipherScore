"use client";
// Screen 3 — Analysis Detail: Summary (mvp.md §4): Score gauge, Risk Score,
// AI Confidence meter, Threat Matrix heatmap.
import { use } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";
import { ScoreGauge } from "@/components/score-gauge";
import { ThreatMatrix } from "@/components/threat-matrix";
import { ProgressStream } from "@/components/progress-stream";
import type { MatrixCell, Summary } from "@/lib/types";

export default function Summary({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data } = useSWR<Summary>(`/analyses/${id}`, api.fetcher, {
    refreshInterval: (current) => current?.status === "completed" ? 0 : 1000,
  });
  const { data: matrix } = useSWR<MatrixCell[]>(
    `/analyses/${id}/threat-matrix`, api.fetcher);

  if (!data) return <p className="text-slate-500">loading…</p>;
  return (
    <div className="space-y-4">
      {data.status !== "completed" && (
        <div className="card">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-semibold">Analysis progress</h2>
            <span className="text-sm capitalize text-slate-400">{data.status}</span>
          </div>
          <ProgressStream url={api.url(`/analyses/${id}/events`)} />
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="card">
          <ScoreGauge score={data.security_score} grade={data.grade} />
        </div>
        <div className="card">
          <p className="text-sm text-slate-400">Risk Score</p>
          <p className="text-3xl">{data.risk_score ?? "—"}</p>
          <p className="mt-2 text-sm text-slate-400">AI Confidence</p>
          <p className="text-3xl">
            {data.ai_confidence != null
              ? `${Math.round(data.ai_confidence * 100)}%`
              : "—"}
          </p>
        </div>
        <div className="card md:col-span-1">
          <ThreatMatrix cells={matrix ?? []} />
        </div>
        <div className="card md:col-span-3">
          <h2 className="mb-2 font-semibold">Top findings</h2>
          <ul className="list-disc pl-6 text-sm">
            {(data.top_findings ?? []).map((f: string) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
