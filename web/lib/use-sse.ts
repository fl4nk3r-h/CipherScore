// EventSource hook with exponential-backoff reconnection (repo.md §8
// lib/use-sse.ts; gap: SSE resilience).
"use client";
import { useEffect, useRef, useState } from "react";

export interface SSEEvent {
  event: string;
  data: string;
}

export type SSEStatus = "idle" | "connecting" | "open" | "reconnecting" | "closed";

const EVENT_TYPES = ["progress", "completed", "failed", "window", "ping", "alert", "closed"];

export const MAX_BACKOFF_MS = 30_000;
export const BASE_BACKOFF_MS = 1_000;

export function useSSE(url: string | null) {
  const [lastEvent, setLastEvent] = useState<SSEEvent | null>(null);
  const [status, setStatus] = useState<SSEStatus>("idle");
  const sourceRef = useRef<EventSource | null>(null);
  const doneRef = useRef(false);

  useEffect(() => {
    if (!url) {
      doneRef.current = false;
      setStatus("idle");
      sourceRef.current?.close();
      sourceRef.current = null;
      return;
    }

    let disposed = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let es: EventSource | null = null;

    const scheduleReconnect = () => {
      if (disposed) return;
      es?.close();
      sourceRef.current = null;
      if (doneRef.current) {
        setStatus("closed");
        return;
      }
      attempt = Math.min(attempt + 1, 20);
      const delay = Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2 ** (attempt - 1));
      setStatus("reconnecting");
      retryTimer = setTimeout(connect, delay);
    };

    const connect = () => {
      if (disposed || doneRef.current) return;
      setStatus(attempt === 0 ? "connecting" : "reconnecting");
      const source = new EventSource(url);
      es = source;
      sourceRef.current = source;

      const onAny = (e: MessageEvent) => {
        const type = e.type || "message";
        if (type === "completed" || type === "failed" || type === "closed") doneRef.current = true;
        setLastEvent({ event: type, data: e.data });
      };
      for (const t of EVENT_TYPES) {
        source.addEventListener(t, onAny as EventListener);
      }
      source.onmessage = onAny as EventListener;
      source.onopen = () => {
        attempt = 0;
        setStatus("open");
      };
      // Fired on network errors and when the server ends the stream. We
      // close the native EventSource and take over reconnection with backoff
      // so terminal events (completed/failed) stop the loop.
      source.onerror = scheduleReconnect;
    };

    connect();

    return () => {
      disposed = true;
      if (retryTimer) clearTimeout(retryTimer);
      es?.close();
      sourceRef.current = null;
    };
  }, [url]);

  return { lastEvent, status, source: sourceRef.current };
}