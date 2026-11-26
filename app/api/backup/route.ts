import { NextResponse } from "next/server";
import {
  fetchNetworkApiJson,
  requireAdminToken,
  resolveSafeBackupPath,
} from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const auth = requireAdminToken(request);
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status });
  }
  const body = (await request.json().catch(() => ({}))) as { filename?: unknown };
  try {
    const dest = resolveSafeBackupPath(
      typeof body.filename === "string" ? body.filename : undefined,
    );
    const upstream = await fetchNetworkApiJson("/v1/ledger/proofs");
    if (!upstream.ok) {
      return NextResponse.json(
        { error: upstream.error ?? "Rust node unreachable" },
        { status: upstream.status },
      );
    }
    return NextResponse.json(
      {
        error:
          "Use scripts/backup.sh on the host holding Vector Network WAL+checkpoint storage to capture a consistent backup",
        suggested_backup_path: dest,
      },
      { status: 501 },
    );
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
