"use client";
// Screen 6 — Analysis Detail: Findings (mvp.md §4): filterable findings list
// -> evidence drawer (packets, features, rule, references, fix).
import { use, useState } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";
import { FindingsList } from "@/components/findings-list";
import { EvidenceDrawer } from "@/components/evidence-drawer";
import { Tabs, TabsList, TabsTrigger, TabsPanel } from "@/components/ui/tabs";
import { CardSkeletons, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import type { Finding } from "@/lib/types";

const SEVS = ["all", "critical", "high", "medium", "low", "info"] as const;

export default function Findings({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, error, mutate } = useSWR<Finding[]>(`/analyses/${id}/findings`, api.fetchArray);
  const [sev, setSev] = useState<(typeof SEVS)[number]>("all");
  const [selected, setSelected] = useState<Finding | null>(null);
  if (error) return <ErrorState message={`Could not load findings: ${error.message}`} onRetry={mutate} />;
  if (!data) return <CardSkeletons rows={5} />;

  const filtered = sev === "all" ? data : data.filter((f) => f.severity === sev);

  return (
    <div className="space-y-3">
      <Tabs value={sev} onValueChange={(v) => setSev(v as (typeof SEVS)[number])}>
        <div className="flex flex-wrap items-center gap-3">
          <TabsList aria-label="Filter findings by severity">
            {SEVS.map((s) => (
              <TabsTrigger key={s} value={s}>
                {s}
              </TabsTrigger>
            ))}
          </TabsList>
          <Badge variant="secondary" aria-live="polite">
            {filtered.length} of {data.length}
          </Badge>
        </div>
        <TabsPanel className="mt-2">
          <FindingsList findings={filtered} onSelect={setSelected} />
        </TabsPanel>
      </Tabs>
      <EvidenceDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}