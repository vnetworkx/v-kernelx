import "server-only";
import fs from "node:fs";
import path from "node:path";
import { AtlasKernel, VectorKernelX } from "@/ts/src/index.ts";

declare global {
  var __atlasKernel: AtlasKernel | undefined;
  var __atlasSandboxKernel: VectorKernelX | undefined;
}

function readCleanEnv(name: string): string | null {
  const raw = process.env[name]?.trim();
  if (!raw || raw === "null" || raw === "undefined") {
    return null;
  }
  return raw;
}

export function getDataDir(): string {
  const configured = readCleanEnv("ATLAS_DATA_DIR");
  if (configured) {
    return path.resolve(configured);
  }
  return path.join(process.cwd(), "data");
}

export function getKernel(): AtlasKernel {
  if (!globalThis.__atlasKernel) {
    globalThis.__atlasKernel = new AtlasKernel(getDataDir());
  }
  return globalThis.__atlasKernel;
}

export function getSandboxKernel(): VectorKernelX {
  if (!globalThis.__atlasSandboxKernel) {
    globalThis.__atlasSandboxKernel = new VectorKernelX();
  }
  return globalThis.__atlasSandboxKernel;
}

export function resetSandboxKernel(): VectorKernelX {
  globalThis.__atlasSandboxKernel = new VectorKernelX();
  return globalThis.__atlasSandboxKernel;
}

export function getCoreTriggerEventHash(kernel = getKernel()): string {
  return kernel.ensureCoreTriggerEventHash(kernel.nodePubkey, kernel.nodeId);
}

export function logServerEvent(
  level: "info" | "warn" | "error",
  event: string,
  details: Record<string, unknown> = {},
): void {
  let nodeId = "uninitialized";
  try {
    nodeId = getKernel().nodeId;
  } catch {
    // ignore during early startup error logging
  }
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      level,
      event,
      node_id: nodeId,
      ...details,
    }),
  );
}

export function resolveSafeBackupPath(rawFilename?: string): string {
  const backupDir = path.resolve(getDataDir(), "backups");
  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const candidate = path.basename((rawFilename ?? "").trim() || `atlas-backup-${stamp}.db`);
  const sanitized = candidate.replace(/[^a-zA-Z0-9._-]/g, "_");
  const withExt = sanitized.endsWith(".db") ? sanitized : `${sanitized}.db`;
  if (!withExt || withExt === ".db" || withExt.startsWith(".")) {
    throw new Error("Invalid backup filename");
  }
  const dest = path.resolve(backupDir, withExt);
  if (!dest.startsWith(`${backupDir}${path.sep}`)) {
    throw new Error("Backup path escapes permitted backup directory");
  }
  return dest;
}
