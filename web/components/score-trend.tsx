// Security Score trend (mvp.md §4 screen 1: "overall Security Score trend").
"use client";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { AnalysisListItem } from "@/lib/types";

const GRADE_COLOR: Record<string, string> = {
  A: "#059669",
  B: "#65a30d",
  C: "#ca8a04",
  D: "#ea580c",
  E: "#dc2626",
};

export function ScoreTrend({ analyses }: { analyses: AnalysisListItem[] }) {
  // API returns newest-first; chart plots oldest -> newest left to right.
  const data = analyses
    .filter((a) => a.security_score != null)
    .slice()
    .reverse()
    .map((a) => ({
      label: a.created.slice(5, 16), // "MM-DD HH:MM"
      score: a.security_score as number,
      id: a.analysis_id,
    }));

  if (!data.length) return <p className="text-sm text-zinc-500">No scored analyses yet.</p>;
  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
        <defs>
          <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.5} />
            <stop offset="100%" stopColor="#06b6d4" stopOpacity={0.05} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
        <XAxis dataKey="label" tick={{ fontSize: 10, fill: "#64748b" }} />
        <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#64748b" }} />
        <Tooltip
          contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }}
          labelStyle={{ color: "#cbd5e1" }}
        />
        <Area
          type="monotone"
          dataKey="score"
          name="Security Score"
          stroke="#06b6d4"
          strokeWidth={2}
          fill="url(#scoreFill)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function gradeColor(grade: string | null): string {
  return (grade && GRADE_COLOR[grade]) || "#64748b";
}