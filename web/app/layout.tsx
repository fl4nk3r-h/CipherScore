import Link from "next/link";
import "./globals.css";

export const metadata = { title: "CipherScope MVP" };

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/analyses/new", label: "New Analysis" },
  { href: "/lab", label: "Lab" },
  { href: "/live", label: "Live" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100">
        <nav className="flex gap-4 border-b border-slate-800 px-6 py-3 text-sm">
          <span className="font-bold text-cyan-400">CipherScope</span>
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} className="hover:text-cyan-300">
              {n.label}
            </Link>
          ))}
        </nav>
        <main className="mx-auto max-w-7xl p-6">{children}</main>
      </body>
    </html>
  );
}
