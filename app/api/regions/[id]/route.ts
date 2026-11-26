import { NextResponse } from "next/server";
import { getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const { searchParams } = new URL(request.url);
    const accessKey = searchParams.get("access_key");

    const kernel = getKernel();
    const region = kernel.getRegion(id);
    if (!region) {
      return NextResponse.json({ error: `Region not found: ${id}` }, { status: 404 });
    }

    const authorized = region.visibility === "public" || region.access_key_hash === accessKey;
    return NextResponse.json({ region, authorized });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
