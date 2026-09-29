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
        <div className="flex items-center gap-2">
          {right}
          <MoreHorizontal className="h-3.5 w-3.5 text-slate-600" />
        </div>
      </header>
      <div className={pad ? "p-3" : ""}>{children}</div>
    </section>
  );
}

export function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "bg-red-500/15 text-red-300 ring-red-500/40",
    high: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
    medium: "bg-yellow-500/15 text-yellow-300 ring-yellow-500/40",
    low: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
    info: "bg-slate-500/15 text-slate-300 ring-slate-500/40",
  };
  return (
    <span className={`soc-num inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 ${map[sev] ?? map.info}`}>
      {sev}
    </span>
  );
}

export function Kpi({
  label,
  value,
  sub,
  accent = "text-slate-100",
  dot,
}: {
  label: string;
  value: React.ReactNode;
  sub: string;
  accent?: string;
  dot?: string;
}) {
  return (
    <div className="soc-panel p-3">
      <div className="flex items-center gap-1.5">
        {dot && <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />}
        <span className="soc-num text-[10px] uppercase tracking-[0.2em] text-slate-500">{label}</span>
      </div>
      <div className={`soc-num mt-1 text-2xl font-black ${accent}`}>{value}</div>
      <div className="mt-0.5 text-[11px] text-slate-500">{sub}</div>
    </div>
  );
}
