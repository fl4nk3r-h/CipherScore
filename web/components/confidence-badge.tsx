// Observed / Inferred / Unknown + % (mvp.md §3.4 credibility contract).
import type { TaggedValue } from "@/lib/types";

export function ConfidenceBadge({ value }: { value: TaggedValue | undefined }) {
  if (!value) return <span className="tag-unknown">unknown</span>;
  const pct = `${Math.round(value.confidence * 100)}%`;
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`tag-${value.tag}`}>{value.tag}</span>
      <span className="text-xs text-zinc-400">{pct}</span>
    </span>
  );
}
