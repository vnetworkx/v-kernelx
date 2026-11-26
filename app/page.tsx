import { AtlasWorkbench } from "@/components/AtlasWorkbench";
import { getCoreTriggerEventHash, getKernel } from "@/lib/server/kernel";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export default function HomePage() {
  const kernel = getKernel();
  const initialStatus = kernel.status();
  const initialRegions = kernel.listRegions();
  const initialWallets = kernel.listWallets().map((w) => ({
    ...w,
    auth_ratio: kernel.computeWalletAuthRatio(w),
    balances: kernel.store.listTokenBalancesForWallet(w.wallet_id),
    rewards: kernel.store.listDrainRewardsForWallet(w.wallet_id),
  }));
  const initialTokens = kernel.store.listTokens().map((t) => ({
    ...t,
    balances: kernel.store.listTokenBalancesForToken(t.token_id),
    conservation: kernel.verifySupplyConservation(t.token_id),
  }));
  const initialVectors = kernel.store.listVectors();
  const initialRewards = kernel.store.listDrainRewards(500);
  const initialValidators = kernel.listValidators();
  const initialRounds = kernel.listConsensusRounds();
  const initialEvents = kernel.store.listEvents();
  const initialRecords = kernel.store.listRecords();
  const initialSnapshots = kernel.store.listSnapshots().map((s) => ({
    snapshot_id: s.snapshot_id,
    state_root: s.state_root,
    event_root: s.event_root,
    replay_hash: s.replay_hash,
    event_count: s.event_count,
    logical_clock: s.logical_clock,
    dag_heads: s.dag_heads,
    created_at: s.created_at,
  }));
  const coreEventHash = getCoreTriggerEventHash(kernel);

  return (
    <AtlasWorkbench
      initialStatus={initialStatus}
      initialRegions={initialRegions}
      initialWallets={initialWallets}
      initialTokens={initialTokens}
      initialVectors={initialVectors}
      initialRewards={initialRewards}
      initialValidators={initialValidators}
      initialRounds={initialRounds}
      initialEvents={initialEvents}
      initialRecords={initialRecords}
      initialSnapshots={initialSnapshots}
      coreEventHash={coreEventHash}
    />
  );
}
