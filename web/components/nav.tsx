"use client";
// Primary navigation with active-link highlighting (a11y: aria-current).
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/analyses/new", label: "New Analysis" },
  { href: "/lab", label: "Lab" },
  { href: "/live", label: "Live" },
];

export function Nav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Primary" className="flex gap-4 border-b border-slate-800 px-6 py-3 text-sm">
      <span className="font-bold text-cyan-400">CipherScope</span>
      {NAV.map((n) => {
        const isActive = n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
        return (
          <Link
            key={n.href}
            href={n.href}
            aria-current={isActive ? "page" : undefined}
            className={cn(
              "rounded px-1 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500",
              isActive ? "text-cyan-300" : "text-slate-200 hover:text-cyan-300",
            )}
          >
            {n.label}
          </Link>
        );
      })}
    </nav>
  );
}