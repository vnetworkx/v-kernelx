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
  title: "v-kernelx — ATLAS VECTOR NETWORK",
  description:
    "Vector Network prototype kernel, protocol state machine, opcode interpreter, and TypeScript SDK workbench.",
  openGraph: {
    title: "v-kernelx — ATLAS VECTOR NETWORK",
    description:
      "Vector Network prototype kernel, protocol state machine, opcode interpreter, and TypeScript SDK workbench.",
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
