"use client";
// Screen 5 — Analysis Detail: Traffic (mvp.md §4): traffic-type donut,
// per-window timeline, packet-size and IAT histograms, metadata exposure panel.
import { use } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";
import { TrafficDonut } from "@/components/traffic-donut";
import { HistogramChart } from "@/components/histogram-chart";
import { ExposurePanel } from "@/components/exposure-panel";
import { CardSkeletons, ErrorState } from "@/components/states";
import type { SAEvidence, TrafficWindow } from "@/lib/types";

export default function Traffic({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, error, mutate } = useSWR<TrafficWindow[]>(
    `/analyses/${id}/traffic`, api.fetcher);
  const { data: sas, error: sasError } = useSWR<SAEvidence[]>(`/analyses/${id}/sas`, api.fetcher);

  if (error || sasError)
    return <ErrorState message="Could not load traffic data." onRetry={mutate} />;
  if (!data) return <CardSkeletons rows={2} />;

  const windows = data.filter((w): w is TrafficWindow => w != null);
  const featureValues = windows.flatMap((w) =>
    Object.values(w.features ?? {}).filter(
      (v): v is number => typeof v === "number" && Number.isFinite(v)));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="card">
          <h2 className="mb-2 font-semibold">Traffic types (in ESP)</h2>
          <TrafficDonut windows={windows} />
        </div>
        <div className="card">
          <h2 className="mb-2 font-semibold">Window features histogram</h2>
          <p className="mb-2 text-xs text-slate-500">
            Combined distribution of per-window packet-size and IAT statistics
          </p>
          <HistogramChart
            values={featureValues}
            bins={20}
          />
        </div>
      </div>
      <ExposurePanel sas={sas ?? []} />
    </div>
  );
}