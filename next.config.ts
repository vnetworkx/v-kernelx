import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  serverExternalPackages: ["node:sqlite", "@noble/hashes"],
  allowedDevOrigins: [
    "**.run.app",
    "*.run.app",
    "**.google.com",
    "*.google.com",
    "localhost",
    "**.localhost",
    "127.0.0.1",
  ],
};

export default nextConfig;
