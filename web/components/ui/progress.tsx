// shadcn/ui-style Progress (repo.md §8 components/ui).
import * as React from "react";
import { cn } from "@/lib/utils";

export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number | null;
  max?: number;
  /** Colour of the filled bar from a fixed palette. */
  tone?: "cyan" | "emerald" | "red" | "amber";
}

const TONES = {
  cyan: "bg-cyan-600",
  emerald: "bg-emerald-600",
  red: "bg-red-600",
  amber: "bg-amber-600",
};

export function Progress({ value, max = 100, tone = "cyan", className, ...props }: ProgressProps) {
  const clamped = value == null ? 0 : Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(clamped)}
      aria-label={props["aria-label"] ?? undefined}
      className={cn("h-2 w-full overflow-hidden rounded bg-zinc-800", className)}
      {...props}
    >
      <div
        className={cn("h-full rounded transition-all", TONES[tone])}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}