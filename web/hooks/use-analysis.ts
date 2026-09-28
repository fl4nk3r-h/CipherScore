// SWR hooks per resource (repo.md §8 hooks/use-analysis.ts).
"use client";
import useSWR from "swr";
import { api } from "@/lib/api";
import type { Finding, SAEvidence, Summary } from "@/lib/types";

export function useAnalysis(id: string) {
  return useSWR<Summary>(`/analyses/${id}`, api.fetcher);
}

export function useAnalysisSAs(id: string) {
  return useSWR<SAEvidence[]>(`/analyses/${id}/sas`, api.fetcher);
}

export function useAnalysisTraffic(id: string) {
  return useSWR<{ pred: string | null; p: number | null; t0: number }[]>(
    `/analyses/${id}/traffic`, api.fetcher);
}

export function useAnalysisFindings(id: string) {
  return useSWR<Finding[]>(`/analyses/${id}/findings`, api.fetcher);
}

export function useThreatMatrix(id: string) {
  return useSWR(`/analyses/${id}/threat-matrix`, api.fetcher);
}
