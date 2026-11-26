import { NextResponse } from "next/server";
import { getKernel, resolveSafeBackupPath } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as { filename?: unknown };
    const dest = resolveSafeBackupPath(
      typeof body.filename === "string" ? body.filename : undefined,
    );
    getKernel().store.backupTo(dest);
    return NextResponse.json({ ok: true, backup_path: dest });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
