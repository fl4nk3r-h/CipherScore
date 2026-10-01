// Progress stream (mvp.md §8): parsed 0.30 → features 0.50 → inferred 0.70 →
// assessed 0.85 → completed 1.0 over SSE.
"use client";
import { useSSE } from "@/lib/use-sse";

const STAGES = [
  ["parsed", 0.3],
  ["features", 0.5],
  ["inferred", 0.7],
  ["assessed", 0.85],
  ["completed", 1.0],
] as const;

export function ProgressStream({ url }: { url: string }) {
  const { lastEvent } = useSSE(url);
  const frac = lastEvent ? parseFloat(
    (() => { try { return String(JSON.parse(lastEvent.data).frac ?? 0); } catch { return "0"; } })()
  ) : 0;
  return (
    <div>
      <div className="h-2 w-full rounded bg-zinc-800">
        <div className="h-2 rounded bg-cyan-600 transition-all" style={{ width: `${frac * 100}%` }} />
      </div>
      <ul className="mt-2 flex gap-3 text-xs">
        {STAGES.map(([stage, f]) => (
          <li key={stage} className={frac >= f ? "text-emerald-300" : "text-zinc-500"}>
            {stage} {frac >= f ? "✓" : ""}
          </li>
        ))}
      </ul>
      {lastEvent?.event === "failed" && (
        <p className="mt-2 text-xs text-red-400">
          Analysis failed: {(() => { try { return JSON.parse(lastEvent.data).error; } catch { return "unknown"; } })()}
        </p>
      )}
    </div>
  );
}
