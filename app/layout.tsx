import type { Metadata } from "next";
import { JetBrains_Mono, Plus_Jakarta_Sans } from "next/font/google";
import "./globals.css";

const plusJakarta = Plus_Jakarta_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-plus-jakarta",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Vector Network Explorer",
  description:
    "Vector Network Explorer connecting to the authoritative Rust node runtime, BFT consensus ledger, and Vector Language verifier.",
  openGraph: {
    title: "Vector Network Explorer",
    description:
      "Vector Network Explorer connecting to the authoritative Rust node runtime, BFT consensus ledger, and Vector Language verifier.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${plusJakarta.variable} ${jetbrainsMono.variable}`}>
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased selection:bg-blue-100 selection:text-slate-900">
        {children}
      </body>
    </html>
  );
}
