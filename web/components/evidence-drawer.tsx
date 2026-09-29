// Evidence drawer (mvp.md §4 screen 6): packets, features, rule, references,
// fix. Rendered as an accessible modal dialog (gap: drawer dialog semantics,
// responsive width).
import { useId } from "react";
import type { Finding } from "@/lib/types";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";

export function EvidenceDrawer({
  finding,
  onClose,
}: {
  finding: Finding | null;
  onClose: () => void;
}) {
  const titleId = useId();
  if (!finding) return null;
  return (
    <Dialog open={finding != null} onClose={onClose} labelledBy={titleId} className="max-w-lg">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 id={titleId} className="font-semibold">{finding.rule_id}</h3>
          <p className="text-xs text-slate-400">{finding.category}</p>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <Button size="icon" variant="ghost" onClick={onClose} aria-label="Close evidence">
            ×
          </Button>
        </div>
      </div>
      <h4 className="mt-3 text-sm font-medium text-slate-200">{finding.title}</h4>
      <div className="mt-1 text-xs text-slate-400">
        likelihood {Math.round(finding.likelihood * 100)}% · confidence{" "}
        {Math.round(finding.confidence * 100)}%
      </div>
      <pre className="mt-2 max-h-56 overflow-auto rounded bg-slate-950 p-2 text-[11px] text-slate-300">
        {JSON.stringify(finding.evidence, null, 2)}
      </pre>
      {finding.refs.length > 0 && (
        <p className="mt-2 text-[11px] text-slate-400">refs: {finding.refs.join("; ")}</p>
      )}
      <pre className="mt-2 rounded bg-slate-950 p-2 text-xs text-emerald-200/80">{finding.fix}</pre>
    </Dialog>
  );
}