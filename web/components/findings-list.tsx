// Findings list (mvp.md §4 screen 6). Rows are focusable buttons so the whole
// list is operable by keyboard (gap: keyboard navigation).
import type { Finding } from "@/lib/types";
import { severityBadgeVariant } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";

const SEV_BORDER: Record<string, string> = {
  critical: "border-l-red-600",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-lime-500",
  info: "border-l-slate-600",
};

export function FindingsList({
  findings,
  onSelect,
}: {
  findings: Finding[];
  onSelect: (f: Finding) => void;
}) {
  if (!findings.length) return <p className="text-sm text-slate-500">No findings.</p>;
  return (
    <ul className="space-y-2">
      {findings.map((f) => (
        <li key={`${f.rule_id}-${(f.evidence?.spi as string) ?? ""}`} className="list-none">
          <button
            type="button"
            onClick={() => onSelect(f)}
            aria-label={`Show evidence for ${f.rule_id} ${f.title}`}
            className={`block w-full rounded-lg border border-slate-800 border-l-4 ${SEV_BORDER[f.severity] ?? "border-l-slate-600"} bg-slate-900 p-4 text-left transition-colors hover:bg-slate-800/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold">
                {f.rule_id} · {f.title}
              </span>
              <span className="flex shrink-0 items-center gap-2">
                <Badge variant={severityBadgeVariant(f.severity)}>{f.severity}</Badge>
                <span className="text-xs text-slate-400">conf {(f.confidence * 100).toFixed(0)}%</span>
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-400">{f.fix}</p>
          </button>
        </li>
      ))}
    </ul>
  );
}