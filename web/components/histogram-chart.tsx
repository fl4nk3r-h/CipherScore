// Packet-size / IAT histogram (mvp.md §4 screen 5).
"use client";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export function HistogramChart({ values, bins = 20 }: { values: number[]; bins?: number }) {
  if (!values.length) return <p className="text-sm text-zinc-500">No numeric data.</p>;
  const min = Math.min(...values), max = Math.max(...values);
  const width = (max - min) / bins || 1;
  const counts = new Array(bins).fill(0);
  for (const v of values) {
    const idx = Math.min(bins - 1, Math.floor((v - min) / width));
    counts[idx] += 1;
  }
  const data = counts.map((c, i) => ({
    bin: `${Math.round(min + i * width)}`,
    count: c,
  }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data}>
        <XAxis dataKey="bin" tick={{ fontSize: 10 }} />
        <YAxis tick={{ fontSize: 10 }} />
        <Tooltip />
        <Bar dataKey="count" fill="#06b6d4" />
      </BarChart>
    </ResponsiveContainer>
  );
}
