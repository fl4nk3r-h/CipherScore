// Metadata exposure panel (mvp.md §3.5 "Metadata exposure" category):
// transport mode exposes real endpoints · IKEv1 Aggressive identity leak ·
// no TFC padding so sizes reveal the application (classifier confidence = exposure).
import type { SAEvidence } from "@/lib/types";

export function ExposurePanel({ sas }: { sas: SAEvidence[] }) {
  const rows = sas.map((sa) => {
    const val = (f: keyof SAEvidence) => (sa[f] as any)?.value;
    const items: string[] = [];
    if (val("mode") === "transport") items.push("Real endpoints exposed (transport mode)");
    if (val("ike_version") === 1) items.push("IKEv1 Aggressive Mode identity leak possible");
    if (sa.traffic) {
      items.push(
        `No TFC padding: application fingerprintable as "${sa.traffic.top}" ` +
        `at ${(sa.traffic.p * 100).toFixed(0)}% confidence`,
      );
    }
    return { spi: sa.spi, items };
  }).filter((r) => r.items.length);

  if (!rows.length) return <p className="text-sm text-slate-500">No metadata exposure detected.</p>;
  return (
    <div className="card">
      <h2 className="mb-2 font-semibold">Metadata exposure</h2>
      <ul className="space-y-2 text-sm">
        {rows.map((r) => (
          <li key={r.spi}>
            <span className="font-mono text-xs text-cyan-300">{r.spi}</span>
            <ul className="ml-4 list-disc text-slate-300">
              {r.items.map((it) => <li key={it}>{it}</li>)}
            </ul>
          </li>
        ))}
      </ul>
    </div>
  );
}
