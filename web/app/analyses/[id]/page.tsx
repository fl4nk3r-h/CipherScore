"use client";
// Screen 3 — Analysis Detail: Summary (mvp.md §4): Score gauge, Risk Score,
// AI Confidence meter, Threat Matrix heatmap.
import useSWR from "swr";
import { api } from "@/lib/api";
import { ScoreGauge } from "@/components/score-gauge";
import { ThreatMatrix } from "@/components/threat-matrix";

export default function Summary({ params }: { params: { id: string } }) {
  const { data } = useSWR(`/analyses/${params.id}`, api.fetcher);
  const { data: matrix } = useSWR(`/analyses/${params.id}/threat-matrix`, api.fetcher);

  if (!data) return <p className="text-slate-500">loading…</p>;
  return (
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
  );
}
