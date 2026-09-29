"use client";
// Screen 5 — Analysis Detail: Traffic (mvp.md §4): traffic-type donut,
// per-window timeline, packet-size and IAT histograms, metadata exposure panel.
import { use } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";
import { TrafficDonut } from "@/components/traffic-donut";
import { HistogramChart } from "@/components/histogram-chart";
import { ExposurePanel } from "@/components/exposure-panel";
import type { SAEvidence } from "@/lib/types";

export default function Traffic({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data } = useSWR<{ pred: string | null; p: number | null; t0: number }[]>(
    `/analyses/${id}/traffic`, api.fetcher);
  const { data: sas } = useSWR<SAEvidence[]>(`/analyses/${id}/sas`, api.fetcher);
  if (!data) return <p className="text-slate-500">loading…</p>;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="card">
          <h2 className="mb-2 font-semibold">Traffic types (in ESP)</h2>
          <TrafficDonut windows={data} />
        </div>
        <div className="card">
          <h2 className="mb-2 font-semibold">Packet-size histogram</h2>
          <HistogramChart
            values={(data ?? []).flatMap((w: any) =>
              Object.values(w.features ?? {}).filter((v: any) => typeof v === "number")
            )}
            bins={20}
          />
        </div>
      </div>
      <ExposurePanel sas={sas ?? []} />
    </div>
  );
}
