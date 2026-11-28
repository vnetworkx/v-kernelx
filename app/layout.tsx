import type { Metadata } from "next";
import "./globals.css";

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
    <html lang="en">
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased selection:bg-blue-100 selection:text-slate-900">
        {children}
      </body>
    </html>
  );
}
