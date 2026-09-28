import Link from "next/link";

const TABS = [
  { seg: "", label: "Summary" },
  { seg: "sas", label: "SAs" },
  { seg: "traffic", label: "Traffic" },
  { seg: "findings", label: "Findings" },
  { seg: "reports", label: "Reports" },
];

export default function AnalysisLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: { id: string };
}) {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Analysis {params.id}</h1>
      <div className="flex gap-3 text-sm">
        {TABS.map((t) => (
          <Link
            key={t.seg}
            href={`/analyses/${params.id}${t.seg ? `/${t.seg}` : ""}`}
            className="rounded border border-slate-700 px-3 py-1 hover:border-cyan-500 hover:text-cyan-300"
          >
            {t.label}
          </Link>
        ))}
      </div>
      {children}
    </div>
  );
}
