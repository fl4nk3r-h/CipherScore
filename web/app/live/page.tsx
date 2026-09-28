"use client";
// Screen 9 — Live (mvp.md §4): rolling 10 s windows streamed over SSE with
// evolving predictions and alerts.
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useSSE } from "@/lib/use-sse";

export default function Live() {
  const [running, setRunning] = useState(false);
  const [windows, setWindows] = useState<any[]>([]);

  const { lastEvent } = useSSE(running ? api.url("/live/events") : null);

  useEffect(() => {
    if (lastEvent?.event === "window") {
      try {
        const data = JSON.parse(lastEvent.data);
        setWindows((prev) => [data, ...prev].slice(0, 30));
      } catch {}
    }
  }, [lastEvent]);

  async function toggle() {
    if (!running) {
      await api.post("/live/start", {});
    } else {
      await api.post("/live/stop", {});
    }
    setRunning(!running);
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Live</h1>
        <button
          onClick={toggle}
          className={`rounded px-4 py-1.5 text-sm ${
            running ? "bg-red-700 hover:bg-red-600" : "bg-emerald-700 hover:bg-emerald-600"
          }`}
        >
          {running ? "Stop" : "Start"} live capture
        </button>
      </div>
      <p className="text-xs text-slate-400">
        Rolling 10 s windows on one interface; predictions update every 10 s.
        Requires the API to run with CS_LIVE_ENABLED=true.
      </p>
      <div className="space-y-2">
        {windows.map((w, i) => (
          <div key={i} className="card flex items-center justify-between text-sm">
            <span>{w.analysis_id}</span>
            <span>
              score {w.posture?.security_score ?? "—"} · risk {w.posture?.risk_score ?? "—"}
            </span>
          </div>
        ))}
        {running && windows.length === 0 && (
          <p className="text-slate-500">waiting for the first 10 s window…</p>
        )}
      </div>
    </div>
  );
}
