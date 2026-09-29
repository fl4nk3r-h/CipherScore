"use client";
// Screen 7 — Reports (mvp.md §4): preview and download of the Executive and
// Technical PDFs + JSON.
import { use } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";

export default function Reports({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const base = api.url(`/analyses/${id}/reports`);
  useSWR(`/analyses/${id}`, api.fetcher); // ensure analysis exists
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      {[
        { kind: "executive", label: "Executive Report", desc: "2 pages · management" },
        { kind: "technical", label: "Technical Report", desc: "8–20 pages · analysts" },
      ].map((r) => (
        <div key={r.kind} className="card space-y-2">
          <h2 className="font-semibold">{r.label}</h2>
          <p className="text-xs text-slate-400">{r.desc}</p>
          <a
            className="block rounded bg-cyan-700 px-3 py-1.5 text-center text-sm hover:bg-cyan-600"
            href={`${base}/${r.kind}.pdf`}
            target="_blank"
          >
            Download PDF
          </a>
        </div>
      ))}
      <div className="card space-y-2">
        <h2 className="font-semibold">Machine-readable</h2>
        <p className="text-xs text-slate-400">report.json · findings.csv</p>
      </div>
    </div>
  );
}
