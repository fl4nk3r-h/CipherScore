// Evidence drawer (mvp.md §4 screen 6): packets, features, rule, references, fix.
import type { Finding } from "@/lib/types";

export function EvidenceDrawer({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  if (!finding) return null;
  return (
    <aside className="card fixed bottom-6 right-6 w-[28rem]">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold">{finding.rule_id}</h3>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-200">×</button>
      </div>
      <p className="text-xs text-slate-400">{finding.category} · {finding.severity}</p>
      <pre className="mt-2 max-h-56 overflow-auto rounded bg-slate-950 p-2 text-[11px]">
        {JSON.stringify(finding.evidence, null, 2)}
      </pre>
      <p className="mt-2 text-[11px] text-slate-400">refs: {finding.refs.join("; ")}</p>
      <pre className="mt-2 rounded bg-slate-950 p-2 text-[11px]">{finding.fix}</pre>
    </aside>
  );
}
