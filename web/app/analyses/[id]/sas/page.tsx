"use client";
// Screen 4 — Analysis Detail: Tunnels/SAs (mvp.md §4): table of SAs (SPI,
// peers, mode, cipher, integrity, DH, PFS, lifetime), each value tagged
// Observed / Inferred / Unknown with confidence.
import useSWR from "swr";
import { api } from "@/lib/api";
import { ConfidenceBadge } from "@/components/confidence-badge";
import { SaTable } from "@/components/sa-table";

export default function SAs({ params }: { params: { id: string } }) {
  const { data } = useSWR(`/analyses/${params.id}/sas`, api.fetcher);
  if (!data) return <p className="text-slate-500">loading…</p>;
  return <SaTable sas={data} />;
  _ = ConfidenceBadge;
}
