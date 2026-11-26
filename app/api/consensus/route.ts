import { NextResponse } from "next/server";
import { getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const kernel = getKernel();
  return NextResponse.json({
    validators: kernel.listValidators(),
    rounds: kernel.listConsensusRounds(),
  });
}

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const kernel = getKernel();
    const action = String(body.action ?? "attest_local");

    if (action === "register_validator") {
      const v = kernel.registerValidator({
        node_id: String(body.node_id ?? ""),
        public_key_hex: String(body.public_key_hex ?? ""),
        label: String(body.label ?? "Validator Node"),
        weight: Number(body.weight ?? 100),
        active: Boolean(body.active ?? true),
      });
      return NextResponse.json({ validator: v });
    }

    if (action === "attest_event") {
      const eventHash = String(body.event_hash ?? "");
      const voteAccept = body.vote_accept !== false;
      const round = kernel.attestEventWithLocalNode(eventHash, voteAccept);
      return NextResponse.json({ round });
    }

    if (action === "sync_bundle") {
      const bundle = kernel.exportSyncBundle();
      return NextResponse.json({ bundle });
    }

    if (action === "import_bundle") {
      const bundle = body.bundle as {
        validators?: any[];
        events?: any[];
        attestations?: any[];
      };
      if (!bundle) {
        return NextResponse.json({ error: "Sync bundle is required" }, { status: 400 });
      }
      const res = kernel.importPeerSyncBundle(bundle);
      return NextResponse.json(res);
    }

    return NextResponse.json({ error: `Unknown consensus action: ${action}` }, { status: 400 });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
