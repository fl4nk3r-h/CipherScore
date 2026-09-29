"use client";
// Screen 4 — Analysis Detail: Tunnels/SAs (mvp.md §4): table of SAs (SPI,
// peers, mode, cipher, integrity, DH, PFS, lifetime), each value tagged
// Observed / Inferred / Unknown with confidence.
import { use } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";
import { SaTable } from "@/components/sa-table";
import { CardSkeletons, ErrorState } from "@/components/states";
import type { SAEvidence } from "@/lib/types";

export default function SAs({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, error, mutate } = useSWR<SAEvidence[]>(`/analyses/${id}/sas`, api.fetcher);
  if (error) return <ErrorState message={`Could not load SAs: ${error.message}`} onRetry={mutate} />;
  if (!data) return <CardSkeletons rows={2} />;
  return <SaTable sas={data} />;
}
