import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST() {
  return NextResponse.json(
    {
      error:
        "Supply transport is governed by the authoritative Rust kernel CreateToken/TransferToken/DrainToken protocol",
    },
    { status: 410 },
  );
}
