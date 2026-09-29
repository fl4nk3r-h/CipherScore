"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  Activity,
  Beaker,
  FileUp,
  LayoutDashboard,
  Radio,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import useSWR from "swr";
import { api } from "@/lib/api";

const NAV = [
  {
    section: "Operations",
    items: [
      { href: "/", label: "SOC Overview", icon: LayoutDashboard, match: (p: string) => p === "/" },
      { href: "/analyses/new", label: "New Analysis", icon: FileUp, match: (p: string) => p.startsWith("/analyses") },
      { href: "/live", label: "Live Intercept", icon: Radio, match: (p: string) => p.startsWith("/live") },
    ],
  },
  {
    section: "Intel & Proof",
    items: [
      { href: "/lab", label: "Lab Matrix", icon: Beaker, match: (p: string) => p.startsWith("/lab") },
    ],
  },
];

function UtcClock() {
  const [now, setNow] = useState("--:--:--");
  useEffect(() => {
    const f = () =>
      setNow(
        new Date().toISOString().slice(11, 19) + " UTC"
      );
    f();
    const t = setInterval(f, 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="soc-num text-[11px] text-slate-400">{now}</span>;
}

export function SocChrome({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: health, error } = useSWR("/healthz", (p: string) => api.fetcher(p).catch(() => null), {
    refreshInterval: 15000,
    revalidateOnFocus: false,
  });
  const online = !!health && !error;

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-[#16223a] bg-[#060c17] lg:flex">
        <div className="border-b border-[#16223a] px-4 py-4">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded bg-cyan-500/15 ring-1 ring-cyan-500/40">
              <ShieldCheck className="h-5 w-5 text-cyan-300" />
            </div>
            <div>
              <div className="soc-num text-sm font-black tracking-widest text-slate-100">
                CIPHER<span className="text-cyan-400">SCOPE</span>
              </div>
              <div className="soc-num text-[10px] uppercase tracking-[0.25em] text-slate-500">
                SOC // IPsec Ops
              </div>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2 rounded border border-[#1a2740] bg-black/40 px-2 py-1.5">
            <span className={`h-2 w-2 rounded-full ${online ? "bg-emerald-400" : "bg-amber-400 soc-live-dot"}`} />
            <span className="soc-num text-[10px] uppercase tracking-widest text-slate-400">
              {online ? "sensor: online" : "sensor: demo feed"}
            </span>
          </div>
        </div>

        <nav className="soc-scroll flex-1 overflow-y-auto px-3 py-3">
          {NAV.map((g) => (
            <div key={g.section} className="mb-4">
              <div className="soc-num px-2 pb-1.5 text-[10px] uppercase tracking-[0.22em] text-slate-600">
                {g.section}
              </div>
              <div className="space-y-1">
                {g.items.map((it) => {
                  const active = it.match(pathname);
                  const Icon = it.icon;
                  return (
                    <Link
                      key={it.href}
                      href={it.href}
                      className={`flex items-center gap-2.5 rounded px-2.5 py-2 text-[13px] transition-colors ${
                        active
                          ? "border border-cyan-500/30 bg-cyan-500/10 text-cyan-200"
                          : "border border-transparent text-slate-400 hover:border-slate-700 hover:bg-slate-800/50 hover:text-slate-200"
                      }`}
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      {it.label}
                      {it.href === "/live" && (
                        <span className="ml-auto flex items-center gap-1 text-[10px] text-red-400">
                          <span className="soc-live-dot h-1.5 w-1.5 rounded-full bg-red-500" /> REC
                        </span>
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}

          <div className="soc-panel mt-2 p-3">
            <div className="flex items-center gap-1.5 text-amber-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              <span className="soc-num text-[10px] font-bold uppercase tracking-widest">Analyst note</span>
            </div>
            <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">
              Encrypted ≠ opaque. ESP length + timing still leaks app class. Check the exposure panel
              before closing a tunnel as “safe”.
            </p>
          </div>
        </nav>

        <div className="border-t border-[#16223a] px-4 py-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-700 text-[11px] font-bold text-slate-200">
              A1
            </div>
            <div>
              <div className="text-xs font-semibold text-slate-200">Analyst-01</div>
              <div className="soc-num text-[10px] text-slate-500">shift: night · tier-2</div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-60">
        <header className="sticky top-0 z-20 border-b border-[#16223a] bg-[#04070e]/90 backdrop-blur">
          <div className="flex items-center gap-3 px-4 py-2.5 lg:px-6">
            <span className="font-black tracking-widest text-cyan-400 lg:hidden">CIPHERSCOPE</span>
            <nav className="ml-auto flex items-center gap-3">
              <span className="soc-num hidden rounded border border-[#1a2740] bg-black/40 px-2 py-1 text-[10px] uppercase tracking-widest text-slate-400 md:inline">
                env: lab-only · passive
              </span>
              <UtcClock />
              <span className="flex items-center gap-1.5 rounded border border-[#1a2740] px-2 py-1 text-[11px]">
                <Activity className={`h-3.5 w-3.5 ${online ? "text-emerald-400" : "text-amber-400"}`} />
                <span className={online ? "text-emerald-300" : "text-amber-300"}>
                  API {online ? "ONLINE" : "DEMO"}
                </span>
              </span>
            </nav>
          </div>
          {/* mobile nav */}
          <div className="flex gap-2 overflow-x-auto px-4 pb-2 lg:hidden">
            {[{ href: "/", label: "Overview" }, { href: "/analyses/new", label: "New" }, { href: "/lab", label: "Lab" }, { href: "/live", label: "Live" }].map((n) => (
              <Link key={n.href} href={n.href} className="rounded border border-slate-700 px-3 py-1 text-xs text-slate-300">
                {n.label}
              </Link>
            ))}
          </div>
        </header>

        <main className="soc-grid-bg min-w-0 flex-1 px-4 py-5 lg:px-6">{children}</main>

        <footer className="border-t border-[#16223a] px-6 py-2.5">
          <p className="soc-num text-[10px] uppercase tracking-[0.2em] text-slate-600">
            cipherscope soc · observed / inferred / unknown — never render unknowns as facts · rfc 8221 · rfc 8247 · nist 800-77r1 · cnsa 2.0
          </p>
        </footer>
      </div>
    </div>
  );
}
