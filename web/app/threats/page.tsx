"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { UploadDropzone } from "@/components/upload-dropzone";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

type ThreatAlert = {
  id: string;
  timestamp: number;
  flow_id: string;
  threat_class: string;
  severity: string;
  confidence: number;
  evidence: Record<string, unknown>;
  source: string;
  model_version: string;
};

export default function Threats() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState("Connecting to alert stream");
  const [error, setError] = useState("");

  useEffect(() => {
    api.fetcher<ThreatAlert[]>("/threats/alerts").then(setAlerts).catch((e) => setError(String(e)));
    const es = new EventSource(api.url("/threats/events"));
    es.onopen = () => setStatus("Connected");
    es.onerror = () => setStatus("Reconnecting");
    es.addEventListener("alert", (event) => {
      const item = JSON.parse((event as MessageEvent).data).alert as ThreatAlert;
      setAlerts((prev) => [item, ...prev.filter((x) => x.id !== item.id)].slice(0, 200));
    });
    es.addEventListener("completed", (event) => {
      const data = JSON.parse((event as MessageEvent).data);
      setStatus(`Replay complete · ${data.packets} packets`);
    });
    es.addEventListener("failed", (event) => {
      setError(JSON.parse((event as MessageEvent).data).error || "Detection failed");
    });
    return () => es.close();
  }, []);

  async function replay(captureId: string) {
    setError("");
    try {
      const result = await api.post<{ run_id: string }>("/threats/replay", { capture_id: captureId });
      setStatus(`Replay ${result.run_id} queued`);
    } catch (cause) { setError(String(cause)); }
  }

  async function toggleLive() {
    setError("");
    try {
      await api.post(`/threats/live/${running ? "stop" : "start"}`, {});
      setRunning(!running);
    } catch (cause) { setError(String(cause)); }
  }

  return <div className="space-y-5">
    <div className="flex items-center justify-between">
      <div><h1 className="text-2xl font-bold">Passive threat alerts</h1><p className="text-sm text-slate-400">{status}</p></div>
      <Button onClick={toggleLive} variant={running ? "destructive" : "default"}>
        {running ? "Stop mirror" : "Start mirror"}
      </Button>
    </div>
    <UploadDropzone onUploaded={replay} />
    {error && <div role="alert" className="card text-red-400">{error}</div>}
    <div className="space-y-3" aria-live="polite">
      {alerts.map((alert) => <details key={alert.id} className="card">
        <summary className="flex cursor-pointer flex-wrap items-center gap-3">
          <Badge variant={alert.severity === "high" || alert.severity === "critical" ? "destructive" : "warning"}>{alert.severity}</Badge>
          <span className="font-semibold capitalize">{alert.threat_class.replaceAll("_", " ")}</span>
          <span>{Math.round(alert.confidence * 100)}% confidence</span>
          <span className="text-xs text-slate-400">{new Date(alert.timestamp * 1000).toLocaleString()}</span>
          <span className="font-mono text-xs text-slate-500">{alert.flow_id}</span>
        </summary>
        <div className="mt-3 text-xs text-slate-400">Source: {alert.source} · Detector: {alert.model_version}</div>
        <pre className="mt-2 overflow-x-auto text-xs">{JSON.stringify(alert.evidence, null, 2)}</pre>
      </details>)}
      {!alerts.length && <p className="card text-sm text-slate-400">No alerts yet. Replay a PCAP or start passive mirror capture.</p>}
    </div>
  </div>;
}
