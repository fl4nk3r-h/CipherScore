"use client";
// Screen 8 — Lab (mvp.md §4): profile matrix, run a profile, session list with
// ground-truth vs predicted comparison (accuracy proof).
import { useState } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";

interface LabProfile {
  id: string;
  spec?: { mode?: string; ip_family?: string; esp_proposal?: string };
}
interface LabSession { session_id: string; traffic_type: string; labels?: unknown[] }

export default function Lab() {
  const { data: profiles } = useSWR<LabProfile[]>("/lab/profiles", api.fetcher);
  const { data: sessions } = useSWR<LabSession[]>("/lab/sessions", api.fetcher);
  const [selected, setSelected] = useState<string[]>(["p03", "p07"]);

  async function run() {
    await api.post("/lab/runs", { profile_ids: selected, traffic_types: ["voip", "web"] });
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Lab</h1>
      <div className="card">
        <h2 className="mb-2 font-semibold">Profile matrix (16 base profiles)</h2>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          {(profiles ?? []).map((p: any) => (
            <label key={p.id} className="flex items-center gap-2 rounded border border-slate-800 p-2 text-xs">
              <input
                type="checkbox"
                checked={selected.includes(p.id)}
                onChange={(e) =>
                  setSelected((prev) =>
                    e.target.checked ? [...prev, p.id] : prev.filter((x) => x !== p.id)
                  )
                }
              />
              <span>
                <b>{p.id}</b> {p.spec?.mode}/{p.spec?.ip_family}{" "}
                <span className="text-slate-500">{p.spec?.esp_proposal}</span>
              </span>
            </label>
          ))}
        </div>
        <button onClick={run} className="mt-3 rounded bg-cyan-700 px-4 py-1.5 text-sm hover:bg-cyan-600">
          Run selected (VoIP + Web)
        </button>
      </div>
      <div className="card">
        <h2 className="mb-2 font-semibold">Sessions — ground truth vs predicted</h2>
        <table className="w-full text-xs">
          <thead className="text-slate-400">
            <tr>
              <th className="text-left">session</th><th>traffic</th>
              <th>labels (ground truth)</th><th>match rate</th>
            </tr>
          </thead>
          <tbody>
            {(sessions ?? []).map((s: any) => (
              <tr key={s.session_id} className="border-t border-slate-800">
                <td>{s.session_id}</td>
                <td className="text-center">{s.traffic_type}</td>
                <td className="text-center font-mono">{JSON.stringify(s.labels)}</td>
                <td className="text-center text-slate-500">run analysis to compare</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
