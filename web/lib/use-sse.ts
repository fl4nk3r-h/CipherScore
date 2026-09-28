// EventSource hook (repo.md §8 lib/use-sse.ts).
"use client";
import { useEffect, useRef, useState } from "react";

export function useSSE(url: string | null) {
  const [lastEvent, setLastEvent] = useState<{ event: string; data: string } | null>(null);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!url) return;
    const es = new EventSource(url);
    sourceRef.current = es;
    const onAny = (e: MessageEvent) =>
      setLastEvent({ event: e.type || "message", data: e.data });
    for (const t of ["progress", "completed", "failed", "window", "ping"]) {
      es.addEventListener(t, onAny as EventListener);
    }
    es.onmessage = onAny as EventListener;
    return () => {
      es.close();
      sourceRef.current = null;
    };
  }, [url]);

  return { lastEvent, source: sourceRef.current };
}
