"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { ArrowRight, Beaker, FileUp, Radio, RefreshCw, Search } from "lucide-react";
import { api } from "@/lib/api";
import { UploadDropzone } from "@/components/upload-dropzone";
import { Button } from "@/components/ui/button";
import { CardSkeletons, ErrorState } from "@/components/states";
import type { LabSession } from "@/lib/types";

export default function NewAnalysis() {
  const { data: sessions, error: sessionsError, mutate: reloadSessions, isValidating } = useSWR<LabSession[]>(
    "/lab/sessions", api.fetchArray, { refreshInterval: 10000 });
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [pendingSession, setPendingSession] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const sessionList = Array.isArray(sessions) ? sessions : [];
  const filteredSessions = useMemo(() => {
    const term = query.trim().toLowerCase();
    return [...sessionList].reverse().filter((session) =>
      !term || [session.session_id, session.profile, session.traffic_type]
        .some((value) => value.toLowerCase().includes(term)));
  }, [sessionList, query]);

  async function startSession(sessionId: string) {
    if (pendingSession) return;
    setActionError(null);
    setPendingSession(sessionId);
    try {
      const result = await api.post<{ analysis_id: string }>("/analyses", { lab_session_id: sessionId });
      router.push(`/analyses/${result.analysis_id}`);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Could not start analysis");
      setPendingSession(null);
    }
  }

  async function startUpload(captureId: string) {
    setActionError(null);
    const result = await api.post<{ analysis_id: string }>("/analyses", { capture_id: captureId });
    router.push(`/analyses/${result.analysis_id}`);
  }

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <header>
        <h1 className="text-xl font-semibold tracking-tight text-zinc-50">New analysis</h1>
        <p className="mt-1 text-[13px] text-zinc-500">Choose a capture source to inspect its IPsec posture and evidence.</p>
      </header>

      {actionError && <ErrorState message={`Could not start analysis: ${actionError}`} />}

      <div className="grid items-start gap-4 xl:grid-cols-12">
        <section className="soc-panel overflow-hidden xl:col-span-7" aria-labelledby="upload-heading">
          <div className="soc-panel-header">
            <div className="flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-300 ring-1 ring-inset ring-cyan-500/20"><FileUp className="h-4 w-4" /></span>
              <div>
                <h2 id="upload-heading" className="soc-panel-title text-sm">Upload a capture</h2>
                <p className="mt-0.5 text-xs text-zinc-500">Start from a PCAP or PCAPNG file</p>
              </div>
            </div>
            <span className="hidden text-xs text-zinc-500 sm:inline">Recommended</span>
          </div>
          <div className="p-5">
            <UploadDropzone onUploaded={startUpload} />
            <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-zinc-500">
              <span>1. Upload capture</span><span>2. Analyze traffic</span><span>3. Review findings</span>
            </div>
          </div>
        </section>

        <section className="soc-panel overflow-hidden xl:col-span-5" aria-labelledby="lab-heading">
          <div className="soc-panel-header">
            <div className="flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.05] text-zinc-300 ring-1 ring-inset ring-white/[0.07]"><Beaker className="h-4 w-4" /></span>
              <div>
                <h2 id="lab-heading" className="soc-panel-title text-sm">Lab sessions</h2>
                <p className="mt-0.5 text-xs text-zinc-500">Compare predictions with ground truth</p>
              </div>
            </div>
            <Button size="icon" variant="ghost" onClick={() => reloadSessions()} disabled={isValidating} aria-label="Refresh lab sessions" className="h-8 w-8">
              <RefreshCw className={`h-4 w-4 ${isValidating ? "animate-spin" : ""}`} />
            </Button>
          </div>
          <div className="p-4">
            <label className="relative block">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
              <span className="sr-only">Search lab sessions</span>
              <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search session, profile, or traffic"
                className="h-10 w-full rounded-lg border border-white/[0.08] bg-black/20 pl-9 pr-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-cyan-500/60 focus:outline-none focus:ring-2 focus:ring-cyan-500/20" />
            </label>
            <div className="mt-3 flex items-center justify-between text-xs text-zinc-500">
              <span>{sessionsError ? "Sessions unavailable" : `${filteredSessions.length} of ${sessionList.length} sessions`}</span>
              <Link href="/lab" className="inline-flex items-center gap-1 text-zinc-300 hover:text-zinc-100">Open Lab <ArrowRight className="h-3 w-3" /></Link>
            </div>
            <div className="soc-scroll mt-3 max-h-[355px] overflow-y-auto" aria-live="polite">
              {!sessions && !sessionsError ? <CardSkeletons rows={2} /> : sessionsError ? (
                <ErrorState message={`Could not load lab sessions: ${sessionsError.message}`} onRetry={() => reloadSessions()} />
              ) : filteredSessions.length ? (
                <ul className="space-y-2">
                  {filteredSessions.map((session) => (
                    <li key={session.session_id} className="flex min-w-0 items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.015] p-3 transition-colors hover:border-white/[0.12] hover:bg-white/[0.03]">
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-mono text-xs font-medium text-zinc-200" title={session.session_id}>{session.session_id}</p>
                        <p className="mt-1 text-xs text-zinc-500"><span className="font-medium text-zinc-400">{session.profile}</span> · <span className="capitalize">{session.traffic_type}</span></p>
                      </div>
                      <Button size="sm" variant="outline" disabled={pendingSession !== null} aria-busy={pendingSession === session.session_id}
                        onClick={() => startSession(session.session_id)}>
                        {pendingSession === session.session_id ? "Starting…" : "Analyze"}
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : query ? (
                <p className="rounded-lg border border-dashed border-white/[0.08] px-4 py-10 text-center text-sm text-zinc-500">No sessions match “{query}”.</p>
              ) : (
                <div className="rounded-lg border border-dashed border-white/[0.08] px-4 py-10 text-center">
                  <p className="text-sm font-medium text-zinc-300">No Lab sessions yet</p>
                  <p className="mt-1 text-xs text-zinc-500">Generate labelled sessions in the Lab to analyze them here.</p>
                  <Link href="/lab" className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-cyan-300 hover:text-cyan-200">Go to Lab <ArrowRight className="h-3 w-3" /></Link>
                </div>
              )}
            </div>
          </div>
        </section>
      </div>

      <section className="soc-panel flex flex-wrap items-center gap-4 p-4 sm:p-5" aria-labelledby="live-heading">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.05] text-zinc-300 ring-1 ring-inset ring-white/[0.07]"><Radio className="h-4 w-4" /></span>
        <div className="min-w-0 flex-1">
          <h2 id="live-heading" className="text-[13px] font-semibold text-zinc-200">Capture live traffic</h2>
          <p className="mt-0.5 text-xs text-zinc-500">Monitor rolling windows on the configured interface when live capture is enabled.</p>
        </div>
        <Button size="sm" variant="outline" asChild><Link href="/live">Open live capture <ArrowRight className="h-3.5 w-3.5" /></Link></Button>
      </section>
    </div>
  );
}
