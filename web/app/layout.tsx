import Link from "next/link";
import "./globals.css";
import { SocChrome } from "@/components/soc-chrome";

export const metadata = { title: "CipherScope SOC — IPsec VPN Security Operations" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-zinc-950 text-zinc-200 antialiased">
        <SocChrome>{children}</SocChrome>
      </body>
    </html>
  );
}
