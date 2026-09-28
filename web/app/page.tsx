"use client";
// Screen 1 — Overview (mvp.md §4): recent analyses, overall Security Score
// trend, top findings across captures.
import useSWR from "swr";
import { ScoreGauge } from "@/components/score-gauge";
import { api } from "@/lib/api";

export default function Overview() {
  const { data: health } = useSWR("/healthz", api.fetcher);
  const { data: sessions } = useSWR("/lab/sessions", api.fetcher);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Overview</h1>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="card">
          <h2 className="text-sm text-slate-400">API</h2>
          <p className="text-lg">{health ? "online" : "offline"}</p>
        </div>
        <div className="card">
          <h2 className="text-sm text-slate-400">Lab sessions</h2>
          <p className="text-lg">{sessions ? sessions.length : "…"}</p>
        </div>
        <div className="card">
          <h2 className="text-sm text-slate-400">Security Score trend</h2>
          <p className="text-sm text-slate-500">recent analyses appear here</p>
        </div>
      </div>
      <div className="card">
        <h2 className="mb-2 font-semibold">Recent analyses</h2>
        <p className="text-sm text-slate-500">
          Run <code className="text-cyan-300">make demo</code> to seed three
          pre-analyzed captures, or upload one under New Analysis.
        </p>
      </div>
      <ScoreGauge score={null} grade={null} />
    </div>
  );
}
