"use client";
import React from "react";
import { MoreHorizontal } from "lucide-react";

export function SocPanel({
  title,
  right,
  children,
  className = "",
  pad = true,
}: {
  title: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  pad?: boolean;
}) {
  return (
    <section className={`soc-panel min-w-0 ${className}`}>
      <header className="soc-panel-header">
        <h2 className="soc-panel-title">{title}</h2>
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          {right}
          <MoreHorizontal className="h-4 w-4 text-zinc-600" />
        </div>
      </header>
      <div className={pad ? "p-4" : ""}>{children}</div>
    </section>
  );
}

const SEV_STYLE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-300 ring-red-500/20",
  high: "bg-orange-500/10 text-orange-300 ring-orange-500/20",
  medium: "bg-amber-500/10 text-amber-300 ring-amber-500/20",
  low: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/20",
  info: "bg-white/[0.06] text-zinc-300 ring-white/10",
};

export function SevBadge({ sev }: { sev: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${SEV_STYLE[sev] ?? SEV_STYLE.info}`}
    >
      {sev}
    </span>
  );
}

export function Kpi({
  label,
  value,
  sub,
}: {
  label: string;
  value: React.ReactNode;
  sub: string;
}) {
  return (
    <div className="soc-panel p-4">
      <div className="text-xs text-zinc-500">{label}</div>
      <div className="soc-num mt-1.5 text-[26px] font-semibold leading-none tracking-tight text-zinc-50">
        {value}
      </div>
      <div className="mt-1.5 text-xs text-zinc-500">{sub}</div>
    </div>
  );
}
