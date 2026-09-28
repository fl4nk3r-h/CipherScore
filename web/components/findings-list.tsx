// Findings list (mvp.md §4 screen 6).
import type { Finding } from "@/lib/types";

const SEV_COLOR: Record<string, string> = {
  critical: "border-red-600",
  high: "border-orange-500",
  medium: "border-yellow-500",
  low: "border-lime-500",
  info: "border-slate-600",
};

export function FindingsList({ findings, onSelect }: {
  findings: Finding[];
  onSelect: (f: Finding) => void;
}) {
  if (!findings.length) return <p className="text-sm text-slate-500">No findings.</p>;
  return (
    <ul className="space-y-2">
      {findings.map((f) => (
        <li
          key={`${f.rule_id}-${f.evidence?.spi ?? ""}`}
          onClick={() => onSelect(f)}
          className={`card cursor-pointer border-l-4 ${SEV_COLOR[f.severity]} hover:bg-slate-800/70`}
        >
          <div className="flex items-center justify-between">
            <span className="font-semibold">{f.rule_id} · {f.title}</span>
            <span className="text-xs text-slate-400">
              {f.severity} · conf {(f.confidence * 100).toFixed(0)}%
            </span>
          </div>
          <p className="text-xs text-slate-400">{f.fix}</p>
        </li>
      ))}
    </ul>
  );
}
