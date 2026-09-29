"use client";
// Screen 6 — Analysis Detail: Findings (mvp.md §4): filterable findings list
// -> evidence drawer (packets, features, rule, references, fix).
import { use, useState } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";
import { FindingsList } from "@/components/findings-list";
import type { Finding } from "@/lib/types";

const SEVS = ["all", "critical", "high", "medium", "low", "info"];

export default function Findings({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data } = useSWR<Finding[]>(`/analyses/${id}/findings`, api.fetcher);
  const [sev, setSev] = useState("all");
  const [selected, setSelected] = useState<any>(null);
  if (!data) return <p className="text-slate-500">loading…</p>;

  const filtered = sev === "all" ? data : data.filter((f: any) => f.severity === sev);
  return (
    <div className="space-y-3">
      <div className="flex gap-2 text-xs">
        {SEVS.map((s) => (
          <button
            key={s}
            onClick={() => setSev(s)}
            className={`rounded px-3 py-1 ${
              sev === s ? "bg-cyan-700" : "bg-slate-800 hover:bg-slate-700"
            }`}
          >
            {s}
          </button>
        ))}
      </div>
      <FindingsList findings={filtered} onSelect={setSelected} />
      {selected && (
        <aside className="card fixed bottom-6 right-6 w-96">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold">{selected.rule_id}</h3>
            <button onClick={() => setSelected(null)} className="text-slate-400">×</button>
          </div>
          <pre className="mt-2 max-h-64 overflow-auto text-xs text-slate-300">
            {JSON.stringify(selected.evidence, null, 2)}
          </pre>
          <p className="mt-2 text-xs text-slate-400">refs: {selected.refs?.join("; ")}</p>
          <pre className="mt-2 rounded bg-slate-950 p-2 text-xs">{selected.fix}</pre>
        </aside>
      )}
    </div>
  );
}
