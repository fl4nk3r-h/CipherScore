"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  Beaker,
  FileUp,
  LayoutDashboard,
  Radio,
  ShieldAlert,
} from "lucide-react";
import useSWR from "swr";
import { api } from "@/lib/api";

const NAV = [
  {
    section: "Operations",
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard, match: (p: string) => p === "/" },
      { href: "/analyses/new", label: "New analysis", icon: FileUp, match: (p: string) => p.startsWith("/analyses") },
      { href: "/live", label: "Live intercept", icon: Radio, match: (p: string) => p.startsWith("/live") },
      { href: "/threats", label: "Threat alerts", icon: ShieldAlert, match: (p: string) => p.startsWith("/threats") },
    ],
  },
  {
    section: "Workspace",
    items: [
      { href: "/lab", label: "Lab matrix", icon: Beaker, match: (p: string) => p.startsWith("/lab") },
    ],
  },
];

function UtcClock() {
  const [now, setNow] = useState("--:--");
  useEffect(() => {
    const f = () => setNow(new Date().toISOString().slice(11, 16) + " UTC");
    f();
    const t = setInterval(f, 10000);
    return () => clearInterval(t);
  }, []);
  return <span className="soc-num text-xs text-zinc-500">{now}</span>;
}

export function SocChrome({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: health, error } = useSWR("/healthz", (p: string) => api.fetcher(p).catch(() => null), {
    refreshInterval: 30000,
    revalidateOnFocus: false,
  });
  const online = !!health && !error;

  return (
    <div className="flex min-h-screen bg-zinc-950">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-white/[0.06] bg-zinc-950 lg:flex">
        <div className="px-5 pb-5 pt-6 text-center">
          <div className="text-xl font-semibold tracking-tight text-zinc-50">CipherScope</div>
          <div className="mt-0.5 text-[11px] text-zinc-500">IPsec security operations</div>
        </div>

        <nav className="soc-scroll flex-1 overflow-y-auto px-3">
          {NAV.map((g) => (
            <div key={g.section} className="mb-5">
              <div className="px-2 pb-1.5 text-[11px] font-medium text-zinc-600">{g.section}</div>
              <div className="space-y-0.5">
                {g.items.map((it) => {
                  const active = it.match(pathname);
                  const Icon = it.icon;
                  return (
                    <Link
                      key={it.href}
                      href={it.href}
                      aria-current={active ? "page" : undefined}
                      className={`flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13.5px] transition-colors ${
                        active
                          ? "bg-white/[0.07] font-medium text-zinc-50"
                          : "text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-200"
                      }`}
                    >
                      <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                      {it.label}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-white/[0.06] p-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-white/10 text-[11px] font-semibold text-zinc-200">
              A
            </div>
            <div className="min-w-0">
              <div className="truncate text-[13px] font-medium text-zinc-200">Analyst</div>
              <div className="flex items-center gap-1.5 text-[11px] text-zinc-500">
                <span className={`h-1.5 w-1.5 rounded-full ${online ? "bg-emerald-400" : "bg-amber-400"}`} />
                {online ? "API connected" : "API offline"}
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-60">
        <header className="sticky top-0 z-20 border-b border-white/[0.06] bg-zinc-950/80 backdrop-blur">
          <div className="flex items-center gap-3 px-4 py-3 lg:px-8">
            <span className="text-[15px] font-semibold tracking-tight lg:hidden">CipherScope</span>
            <div className="ml-auto flex items-center gap-4">
              <UtcClock />
              <span
                className={`hidden items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium ring-1 ring-inset sm:flex ${
                  online
                    ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/20"
                    : "bg-white/[0.05] text-zinc-400 ring-white/10"
                }`}
              >
                <span className={`h-1.5 w-1.5 rounded-full ${online ? "bg-emerald-400" : "bg-zinc-500"}`} />
                {online ? "API connected" : "API offline"}
              </span>
            </div>
          </div>
          <div className="flex gap-1 overflow-x-auto px-4 pb-2.5 lg:hidden">
            {[{ href: "/", label: "Overview" }, { href: "/analyses/new", label: "New" }, { href: "/lab", label: "Lab" }, { href: "/live", label: "Live" }, { href: "/threats", label: "Threats" }].map((n) => (
              <Link key={n.href} href={n.href} aria-current={pathname === n.href ? "page" : undefined} className={`rounded-lg px-3 py-1.5 text-[13px] hover:bg-white/5 hover:text-zinc-200 ${pathname === n.href ? "bg-white/[0.07] text-zinc-100" : "text-zinc-400"}`}>
                {n.label}
              </Link>
            ))}
          </div>
        </header>

        <main className="min-w-0 flex-1 px-4 py-6 lg:px-8">{children}</main>

        <footer className="border-t border-white/[0.06] px-8 py-3">
          <p className="text-[11px] text-zinc-600">
            Observed / inferred / unknown — unknowns are never rendered as facts.
          </p>
        </footer>
      </div>
    </div>
  );
}
