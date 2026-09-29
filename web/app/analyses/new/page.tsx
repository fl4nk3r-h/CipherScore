"use client";
// Screen 2 — New Analysis (mvp.md §4): drag-and-drop PCAP upload, pick a lab
// session, or start live capture on an interface.
import { useState } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";
import { UploadDropzone } from "@/components/upload-dropzone";

export default function NewAnalysis() {
  const { data: sessions } = useSWR<{ session_id: string; traffic_type: string; labels?: unknown[] }[]>(
    "/lab/sessions", api.fetcher);
  const [analysisId, setAnalysisId] = useState<string | null>(null);

  async function analyzeCapture(captureId: string) {
    const res = await api.post<{ analysis_id: string }>("/analyses", { capture_id: captureId });
    setAnalysisId(res.analysis_id);
  }

  async function analyzeSession(sessionId: string) {
    const res = await api.post<{ analysis_id: string }>("/analyses", { lab_session_id: sessionId });
    setAnalysisId(res.analysis_id);
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">New Analysis</h1>
      <UploadDropzone onUploaded={analyzeCapture} />
      <div className="card">
        <h2 className="mb-2 font-semibold">…or analyze a lab session</h2>
        <ul className="space-y-1 text-sm">
          {(sessions ?? []).map((s: any) => (
            <li key={s.session_id} className="flex items-center justify-between">
              <span>
                {s.session_id} <span className="text-slate-500">({s.traffic_type})</span>
              </span>
              <button
                className="rounded bg-cyan-700 px-3 py-1 text-xs hover:bg-cyan-600"
                onClick={() => analyzeSession(s.session_id)}
              >
                analyze session
              </button>
            </li>
          ))}
        </ul>
      </div>
      {analysisId && (
        <p className="text-sm text-emerald-300">
          Started analysis {analysisId} — watch progress on the analysis page.
        </p>
      )}
    </div>
  );
}
