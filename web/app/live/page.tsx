"use client";
// Screen 9 — Live (mvp.md §4): rolling 10 s windows streamed over SSE with
// evolving predictions and alerts.
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useSSE, type SSEStatus } from "@/lib/use-sse";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/states";
import type { LiveWindow } from "@/lib/types";

const MAX_WINDOWS = 30;

function parseWindow(raw: string): LiveWindow | null {
  try {
    const data = JSON.parse(raw);
    if (data && typeof data === "object" && data.analysis_id) return data as LiveWindow;
    return null;
  } catch {
    return null;
  }
}

function ConnectionBadge({ status }: { status: SSEStatus }) {
  if (status === "open") return <Badge variant="success">connected</Badge>;
  if (status === "connecting") return <Badge variant="secondary">connecting…</Badge>;
  if (status === "reconnecting") return <Badge variant="warning">reconnecting…</Badge>;
  if (status === "closed") return <Badge variant="secondary">stream ended</Badge>;
  return <Badge variant="outline">idle</Badge>;
}

export default function Live() {
  const [running, setRunning] = useState(false);
  const [windows, setWindows] = useState<LiveWindow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [startError, setStartError] = useState<string | null>(null);

  const { lastEvent, status } = useSSE(running ? api.url("/live/events") : null);

  useEffect(() => {
    if (lastEvent?.event === "window") {
      const window = parseWindow(lastEvent.data);
      if (window) setWindows((prev) => [window, ...prev].slice(0, MAX_WINDOWS));
    }
  }, [lastEvent]);

  useEffect(() => {
    setError(null);
    const timeout = setTimeout(() => {
      if (running && status === "reconnecting") {
        setError("Live stream is reconnecting to the API…");
      }
    }, 15_000);
    return () => clearTimeout(timeout);
  }, [status, running]);

  async function toggle() {
    setError(null);
    setStartError(null);
    try {
      if (!running) {
        await api.post("/live/start", {});
        setError(null);
      } else {
        await api.post("/live/stop", {});
      }
      setRunning(!running);
    } catch (cause) {
      setStartError(cause instanceof Error ? cause.message : "live capture request failed");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Live</h1>
        <div className="flex items-center gap-3">
          <ConnectionBadge status={running ? status : "idle"} />
          <Button
            onClick={toggle}
            variant={running ? "destructive" : "default"}
            aria-pressed={running}
            aria-busy={status === "connecting" || status === "reconnecting"}
          >
            {running ? "Stop" : "Start"} live capture
          </Button>
        </div>
      </div>
      <p className="text-xs text-slate-400">
        Rolling 10 s windows on one interface; predictions update every 10 s.
        Requires the API to run with CS_LIVE_ENABLED=true.
      </p>
      {(startError || error) && (
        <div role="alert" className="card flex items-center justify-between gap-3">
          <p className="text-sm text-red-400">
            {startError ? `Live capture could not start: ${startError}` : error}
          </p>
          {error && (
            <Button size="sm" variant="outline" onClick={() => setError(null)}>
              Dismiss
            </Button>
          )}
        </div>
      )}
      <div className="space-y-2" aria-live="polite">
        {windows.map((w, i) => (
          <div key={`${w.analysis_id}-${w.t0 ?? i}`} className="card flex items-center justify-between text-sm">
            <span className="font-mono text-xs">{w.analysis_id}</span>
            <span className="flex items-center gap-4">
              {w.pred && (
                <Badge variant="secondary" className="capitalize">pred: {w.pred}</Badge>
              )}
              <span>
                score {w.posture?.security_score ?? "—"} · risk {w.posture?.risk_score ?? "—"}
              </span>
            </span>
          </div>
        ))}
        {running && windows.length === 0 && (
          <EmptyState
            title="Waiting for the first window"
            description="Traffic on the configured interface is sampled into 10 s windows as they close."
          />
        )}
        {!running && windows.length === 0 && (
          <EmptyState
            title="Not capturing"
            description="Start a live capture to stream rolling traffic predictions."
            action={
              <Button onClick={toggle}>Start live capture</Button>
            }
          />
        )}
      </div>
    </div>
  );
}