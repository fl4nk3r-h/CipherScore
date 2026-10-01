// SA table (mvp.md §4 screen 4; §5 sample SA record shape).
import type { SAEvidence } from "@/lib/types";
import { ConfidenceBadge } from "./confidence-badge";

const FIELDS: { key: keyof SAEvidence; label: string }[] = [
  { key: "ike_version", label: "IKE" },
  { key: "mode", label: "Mode" },
  { key: "enc", label: "Encryption" },
  { key: "key_bits", label: "Key size" },
  { key: "integ", label: "Integrity" },
  { key: "dh_group", label: "DH group" },
  { key: "pfs", label: "PFS" },
  { key: "nat_t", label: "NAT-T" },
  { key: "rekey_interval_s", label: "Rekey interval" },
  { key: "replay_window", label: "Replay window" },
];

export function SaTable({ sas }: { sas: SAEvidence[] }) {
  if (!sas.length) return <p className="text-zinc-500">No SAs in this capture.</p>;
  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-left text-zinc-400">
          <tr>
            <th className="py-1">SPI</th><th>Peers</th>
            {FIELDS.map((f) => <th key={f.key} className="text-center">{f.label}</th>)}
            <th className="text-center">Traffic</th>
          </tr>
        </thead>
        <tbody>
          {sas.map((sa) => (
            <tr key={sa.spi} className="border-t border-zinc-800">
              <td className="py-2 font-mono text-xs">{sa.spi}</td>
              <td className="text-xs">{sa.peers.join(" ↔ ")}</td>
              {FIELDS.map((f) => (
                <td key={f.key} className="text-center text-xs">
                  <ConfidenceBadge value={sa[f.key] as any} />
                </td>
              ))}
              <td className="text-center text-xs">
                {sa.traffic ? (
                  <>
                    <b>{sa.traffic.top}</b>{" "}
                    <span className="text-zinc-400">
                      {(sa.traffic.p * 100).toFixed(0)}% [{sa.traffic.conformal_set.join(", ")}]
                    </span>
                  </>
                ) : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
