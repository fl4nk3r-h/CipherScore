// SWR hooks per resource (repo.md §8 hooks/use-analysis.ts).
"use client";
import useSWR from "swr";
import { api } from "@/lib/api";
import type { Finding, SAEvidence, Summary, TrafficWindow } from "@/lib/types";

export function useAnalysis(id: string) {
  return useSWR<Summary>(`/analyses/${id}`, api.fetcher);
}

export function useAnalysisSAs(id: string) {
  return useSWR<SAEvidence[]>(`/analyses/${id}/sas`, api.fetchArray);
}

export function useAnalysisTraffic(id: string) {
  return useSWR<TrafficWindow[]>(`/analyses/${id}/traffic`, api.fetchArray);
}

export function useAnalysisFindings(id: string) {
  return useSWR<Finding[]>(`/analyses/${id}/findings`, api.fetchArray);
}

export function useThreatMatrix(id: string) {
  return useSWR(`/analyses/${id}/threat-matrix`, api.fetchArray);
}
