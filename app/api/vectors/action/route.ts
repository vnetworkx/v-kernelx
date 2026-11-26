import { NextResponse } from "next/server";
import { getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const kernel = getKernel();
    const action = String(body.action ?? "origin");

    if (action === "origin") {
      const state = kernel.createSignedOriginVector({
        request_id: String(body.request_id ?? `orig_${Date.now()}`),
        vector_id: String(body.vector_id ?? ""),
        space_id: String(body.space_id ?? ""),
        components: (body.components as number[]) ?? [0],
        dimension_labels: (body.dimension_labels as string[]) ?? undefined,
        seed: String(body.seed ?? ""),
        nonce: Number(body.nonce ?? 0),
        difficulty: Number(body.difficulty ?? 1),
        drain_bps: body.drain_bps !== undefined ? Number(body.drain_bps) : undefined,
        actor_public_key: String(body.actor_public_key ?? ""),
        signature: String(body.signature ?? ""),
      });
      return NextResponse.json({ vector: state });
    }

    if (action === "transport") {
      const res = kernel.transportMultidimensionalVector({
        request_id: String(body.request_id ?? `vtr_${Date.now()}`),
        from_reserve_id: String(body.from_reserve_id ?? ""),
        to_vector_id: String(body.to_vector_id ?? ""),
        amount: (body.amount as number[]) ?? [],
        actor_public_key: String(body.actor_public_key ?? ""),
        signature: String(body.signature ?? ""),
      });
      return NextResponse.json(res);
    }

    if (action === "transfer") {
      const res = kernel.transferMultidimensionalVector({
        request_id: String(body.request_id ?? `vtx_${Date.now()}`),
        from_vector_id: String(body.from_vector_id ?? ""),
        to_vector_id: String(body.to_vector_id ?? ""),
        amount: (body.amount as number[]) ?? [],
        drain_bps: body.drain_bps !== undefined ? Number(body.drain_bps) : undefined,
        actor_public_key: String(body.actor_public_key ?? ""),
        signature: String(body.signature ?? ""),
      });
      return NextResponse.json(res);
    }

    if (action === "project") {
      const state = kernel.projectMultidimensionalVector({
        request_id: String(body.request_id ?? `prj_${Date.now()}`),
        vector_id: String(body.vector_id ?? ""),
        projected_components: (body.projected_components as number[]) ?? [],
        escrow_id: String(body.escrow_id ?? ""),
        actor_public_key: String(body.actor_public_key ?? ""),
        signature: String(body.signature ?? ""),
      });
      return NextResponse.json({ vector: state });
    }

    if (action === "reconstruct") {
      const state = kernel.reconstructMultidimensionalVector({
        request_id: String(body.request_id ?? `rec_${Date.now()}`),
        vector_id: String(body.vector_id ?? ""),
        gains: (body.gains as number[]) ?? [],
        losses: (body.losses as number[]) ?? [],
        outcome_tag: String(body.outcome_tag ?? "settled"),
        actor_public_key: String(body.actor_public_key ?? ""),
        signature: String(body.signature ?? ""),
      });
      return NextResponse.json({ vector: state });
    }

    if (action === "certify") {
      const state = kernel.certifyMultidimensionalVector({
        request_id: String(body.request_id ?? `crt_${Date.now()}`),
        vector_id: String(body.vector_id ?? ""),
        actor_public_key: String(body.actor_public_key ?? ""),
        signature: String(body.signature ?? ""),
      });
      return NextResponse.json({ vector: state });
    }

    if (action === "drain") {
      const res = kernel.drainMultidimensionalVector({
        request_id: String(body.request_id ?? `drn_${Date.now()}`),
        vector_id: String(body.vector_id ?? ""),
        basis_points: Number(body.basis_points ?? 200),
        actor_public_key: String(body.actor_public_key ?? ""),
        signature: String(body.signature ?? ""),
      });
      return NextResponse.json(res);
    }

    return NextResponse.json({ error: `Unknown vector action: ${action}` }, { status: 400 });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
