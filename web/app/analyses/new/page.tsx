"use client";
// Screen 2 — New Analysis (mvp.md §4): drag-and-drop PCAP upload, pick a lab
// session, or start live capture on an interface.
import { useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { api } from "@/lib/api";
import { UploadDropzone } from "@/components/upload-dropzone";
import { Card, CardContent, CardHeader, CardDescription, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CardSkeletons, ErrorState } from "@/components/states";
import type { LabSession } from "@/lib/types";

export default function NewAnalysis() {
  const { data: sessions, error: sessionsError, mutate } = useSWR<LabSession[]>("/lab/sessions", api.fetcher);
  const router = useRouter();
  const [actionError, setActionError] = useState<string | null>(null);

  function openAnalysis(analysisId: string) {
    router.push(`/analyses/${analysisId}`);
  }

  async function analyzeCapture(captureId: string) {
    setActionError(null);
    const res = await api.post<{ analysis_id: string }>("/analyses", { capture_id: captureId });
    openAnalysis(res.analysis_id);
  }

  async function analyzeSession(sessionId: string) {
    setActionError(null);
    try {
      const res = await api.post<{ analysis_id: string }>("/analyses", { lab_session_id: sessionId });
      openAnalysis(res.analysis_id);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "could not start analysis");
    }
  }

  const sessionsList = sessions ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">New Analysis</h1>
      <UploadDropzone onUploaded={analyzeCapture} />
      {actionError && (
        <div role="alert" className="card">
          <p className="text-sm text-red-400">Could not start analysis: {actionError}</p>
        </div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>…or analyze a lab session</CardTitle>
          <CardDescription>Sessions produced by the lab carry ground-truth labels</CardDescription>
        </CardHeader>
        <CardContent>
          {!sessions && !sessionsError ? (
            <CardSkeletons rows={2} />
          ) : sessionsError ? (
            <ErrorState message={`Could not load lab sessions: ${sessionsError.message}`} onRetry={mutate} />
          ) : sessionsList.length ? (
            <ul className="space-y-1 text-sm">
              {sessionsList.map((s) => (
                <li key={s.session_id} className="flex items-center justify-between">
                  <span>
                    {s.session_id} <span className="text-slate-500">({s.traffic_type})</span>
                  </span>
                  <Button size="xs" onClick={() => analyzeSession(s.session_id)}>
                    Analyze session
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-500">
              No lab sessions yet — generate them on the Lab screen first.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}