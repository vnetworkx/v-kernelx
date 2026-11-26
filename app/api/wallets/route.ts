import { NextResponse } from "next/server";
import { getKernel, logServerEvent } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const kernel = getKernel();
  const wallets = kernel.listWallets().map((w) => ({
    ...w,
    auth_ratio: kernel.computeWalletAuthRatio(w),
    balances: kernel.store.listTokenBalancesForWallet(w.wallet_id),
    rewards: kernel.store.listDrainRewardsForWallet(w.wallet_id),
  }));
  return NextResponse.json({ wallets });
}

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => ({}))) as {
      mode?: unknown;
      label?: unknown;
      region_id?: unknown;
      creator_wallet_id?: unknown;
      public_key_hex?: unknown;
    };
    const kernel = getKernel();
    const label = String(body.label ?? "").trim();
    const regionId = body.region_id ? String(body.region_id).trim() : null;
    const creatorWalletId = body.creator_wallet_id ? String(body.creator_wallet_id).trim() : null;

    if (body.mode === "register_pubkey") {
      const publicKeyHex = String(body.public_key_hex ?? "").trim();
      const wallet = kernel.registerExternalWallet({
        public_key_hex: publicKeyHex,
        label,
        region_id: regionId,
        creator_wallet_id: creatorWalletId,
      });
      logServerEvent("info", "wallet_registered_external", {
        wallet_id: wallet.wallet_id,
        region_id: wallet.region_id,
        creator_wallet_id: wallet.creator_wallet_id,
      });
      return NextResponse.json({
        wallet: {
          ...wallet,
          auth_ratio: kernel.computeWalletAuthRatio(wallet),
          balances: [],
          rewards: [],
        },
      });
    }

    const created = kernel.createOpenWallet(label, regionId, creatorWalletId);
    logServerEvent("info", "wallet_created_open", {
      wallet_id: created.wallet.wallet_id,
      region_id: created.wallet.region_id,
      creator_wallet_id: created.wallet.creator_wallet_id,
    });
    return NextResponse.json({
      wallet: {
        ...created.wallet,
        auth_ratio: kernel.computeWalletAuthRatio(created.wallet),
        balances: [],
        rewards: [],
      },
      private_key_hex: created.private_key_hex,
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
}
