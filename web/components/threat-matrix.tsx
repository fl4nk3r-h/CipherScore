// 5 x 5 Threat Matrix heatmap (mvp.md §3.5): likelihood bucket x impact.
import type { MatrixCell, Severity } from "@/lib/types";

const SEVS: Severity[] = ["info", "low", "medium", "high", "critical"];
const HEAT: Record<string, string> = {
  info: "bg-zinc-800",
  low: "bg-lime-900/60",
  medium: "bg-yellow-800/60",
  high: "bg-orange-800/70",
  critical: "bg-red-900/70",
};

export function ThreatMatrix({ cells }: { cells: MatrixCell[] }) {
  const grid: MatrixCell[][] = [];
  for (let b = 1; b <= 5; b++) {
    grid.push(SEVS.map((s) =>
      cells.find((c) => c.likelihood_bucket === b && c.impact === s) ??
      { likelihood_bucket: b, impact: s, findings: [] }));
  }
  return (
    <div>
      <h2 className="mb-2 text-sm font-semibold text-zinc-300">Threat Matrix</h2>
      <table className="w-full text-center text-xs">
        <tbody>
          {grid.map((row, i) => (
            <tr key={i}>
              {row.map((cell) => (
                <td
                  key={cell.impact}
                  className={`m-0.5 h-8 rounded ${HEAT[cell.impact]} ${
                    cell.findings.length ? "font-bold" : "opacity-50"
                  }`}
                  title={`${cell.likelihood_bucket} × ${cell.impact}: ${cell.findings.length} finding(s)`}
                >
                  {cell.findings.length || ""}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-1 flex justify-between text-[10px] text-zinc-500">
        <span>← lower likelihood</span>
        <span>impact: info → critical →</span>
      </div>
    </div>
  );
}
