// Traffic-type donut (mvp.md §4 screen 5).
"use client";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

const COLORS = ["#06b6d4", "#a78bfa", "#34d399", "#fbbf24", "#f87171", "#60a5fa", "#94a3b8"];

export function TrafficDonut({ windows }: { windows: { pred: string | null; p: number | null }[] }) {
  const counts = new Map<string, number>();
  for (const w of windows) {
    if (w.pred) counts.set(w.pred, (counts.get(w.pred) ?? 0) + 1);
  }
  const data = [...counts.entries()].map(([name, value]) => ({ name, value }));
  if (!data.length) return <p className="text-sm text-zinc-500">No classified windows.</p>;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
          {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
        </Pie>
        <Tooltip />
      </PieChart>
    </ResponsiveContainer>
  );
}
