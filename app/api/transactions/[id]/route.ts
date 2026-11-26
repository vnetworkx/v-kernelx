import { NextResponse } from "next/server";
import { getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const kernel = getKernel();
    const record =
      kernel.store.getRecord(id) ??
      kernel.store.listRecords().find((r) => (r.parameters as Record<string, unknown>)?.request_id === id) ??
      null;
    const event = kernel.store.getEventByHash(id) ?? kernel.store.getEventById(id);
    if (!record && !event) {
      return NextResponse.json({ error: `Transaction record or event not found: ${id}` }, { status: 404 });
    }
    return NextResponse.json({ record, event });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
