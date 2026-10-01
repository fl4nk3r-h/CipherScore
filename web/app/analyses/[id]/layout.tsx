import { AnalysisTabs } from "@/components/analysis-tabs";

export default async function AnalysisLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <header>
        <h1 className="text-xl font-semibold tracking-tight text-zinc-50">Analysis <span className="font-mono text-cyan-300">{id}</span></h1>
        <p className="mt-1 text-[13px] text-zinc-500">Inspect posture, traffic, findings, and reports for this capture.</p>
      </header>
      <AnalysisTabs id={id} />
      {children}
    </div>
  );
}
