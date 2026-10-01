"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const TABS = [
  { segment: "", label: "Summary" },
  { segment: "sas", label: "SAs" },
  { segment: "traffic", label: "Traffic" },
  { segment: "findings", label: "Findings" },
  { segment: "reports", label: "Reports" },
];

export function AnalysisTabs({ id }: { id: string }) {
  const pathname = usePathname();
  return (
    <nav aria-label="Analysis sections" className="soc-scroll flex gap-1 overflow-x-auto border-b border-white/[0.07] pb-2">
      {TABS.map((tab) => {
        const href = `/analyses/${id}${tab.segment ? `/${tab.segment}` : ""}`;
        const active = pathname === href;
        return (
          <Link key={tab.segment} href={href} aria-current={active ? "page" : undefined}
            className={`shrink-0 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors ${active ? "bg-white/[0.08] text-zinc-50" : "text-zinc-500 hover:bg-white/[0.04] hover:text-zinc-200"}`}>
            {tab.label}
          </Link>
        );
      })}
    </nav>
  );
}
