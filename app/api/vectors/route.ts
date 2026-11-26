import { NextResponse } from "next/server";
import { getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const kernel = getKernel();
  return NextResponse.json({
    vectors: kernel.store.listVectors(),
    rewards: kernel.store.listDrainRewards(500),
  });
}
