import "server-only";
import { timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getNetworkApiUrl } from "./network-proxy";

export {
  fetchNetworkApiJson,
  fetchNetworkExplorerSnapshot,
  getNetworkApiUrl,
  mapNetworkSnapshotToWorkbenchProps,
  postNetworkApiJson,
} from "./network-proxy";

function readCleanEnv(name: string): string | null {
  const raw = process.env[name]?.trim();
  if (!raw || raw === "null" || raw === "undefined") {
    return null;
  }
  return raw;
}

export function getConfiguredAdminToken(): string | null {
  return readCleanEnv("ATLAS_ADMIN_TOKEN") ?? readCleanEnv("NETWORK_ADMIN_TOKEN");
}

function extractBearerOrAdminToken(request: Request): string | null {
  const xAdmin = request.headers.get("x-admin-token")?.trim();
  if (xAdmin) return xAdmin;
  const auth = request.headers.get("authorization")?.trim();
  if (auth) {
    const match = /^bearer\s+(.+)$/i.exec(auth);
    if (match?.[1]) return match[1].trim();
  }
  return null;
}

export function requireAdminToken(
  request: Request,
): { ok: true } | { ok: false; status: number; error: string } {
  const expected = getConfiguredAdminToken();
  if (!expected) {
    return {
      ok: false,
      status: 503,
      error: "Administrative endpoint requires ATLAS_ADMIN_TOKEN or NETWORK_ADMIN_TOKEN",
    };
  }
  const provided = extractBearerOrAdminToken(request);
  if (!provided) {
    return {
      ok: false,
      status: 401,
      error: "Missing X-Admin-Token or Authorization: Bearer <token> header",
    };
  }
  const expectedBuf = Buffer.from(expected, "utf8");
  const providedBuf = Buffer.from(provided, "utf8");
  if (expectedBuf.length !== providedBuf.length || !timingSafeEqual(expectedBuf, providedBuf)) {
    return {
      ok: false,
      status: 403,
      error: "Invalid administrative token",
    };
  }
  return { ok: true };
}

export function getDataDir(): string {
  const configured = readCleanEnv("ATLAS_DATA_DIR");
  if (configured) {
    return path.resolve(configured);
  }
  return path.join(process.cwd(), "data");
}

export function logServerEvent(
  level: "info" | "warn" | "error",
  event: string,
  details: Record<string, unknown> = {},
): void {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      level,
      event,
      upstream_api: getNetworkApiUrl(),
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
