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
    `/analyses/${id}/traffic`, api.fetchArray);
  const { data: sas, error: sasError } = useSWR<SAEvidence[]>(`/analyses/${id}/sas`, api.fetchArray);

  if (error || sasError)
    return <ErrorState message="Could not load traffic data." onRetry={mutate} />;
  if (!data) return <CardSkeletons rows={2} />;

  const windows = data.filter((w): w is TrafficWindow => w != null);
  const featureValues = windows.flatMap((w) => {
    const value = w.features?.len_mean;
    return typeof value === "number" && Number.isFinite(value) ? [value] : [];
  });

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="card">
          <h2 className="mb-2 font-semibold">Traffic types (in ESP)</h2>
          <TrafficDonut windows={windows} />
        </div>
        <div className="card">
          <h2 className="mb-2 font-semibold">Window features histogram</h2>
          <p className="mb-2 text-xs text-zinc-500">
            Distribution of mean packet size per window (bytes)
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