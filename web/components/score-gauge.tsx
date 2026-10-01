// Security Score gauge (mvp.md §3: score 0-100 with grade).
export function ScoreGauge({ score, grade }: { score: number | null; grade: string | null }) {
  const color =
    score == null ? "#475569"
    : score >= 90 ? "#059669"
    : score >= 80 ? "#65a30d"
    : score >= 70 ? "#ca8a04"
    : score >= 55 ? "#ea580c"
    : "#dc2626";
  return (
    <div className="card text-center">
      <div className="text-5xl font-black" style={{ color }}>
        {score ?? "—"}
      </div>
      <div className="mt-1 text-sm text-zinc-400">
        Security Score {grade ? `· grade ${grade}` : ""}
      </div>
      <div className="mt-3 h-2 w-full rounded bg-zinc-800">
        <div
          className="h-2 rounded transition-all"
          style={{ width: `${score ?? 0}%`, background: color }}
        />
      </div>
    </div>
  );
}
