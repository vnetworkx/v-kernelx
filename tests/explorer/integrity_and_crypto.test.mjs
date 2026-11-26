import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const {
  canonicalJsonBytes,
  canonicalTransferApprovalObject,
  blake3Hex,
  signEd25519,
  verifyEd25519,
  ClientIdentity,
} = await import(path.join(ROOT, "sdks/javascript/index.js"));

const { mapNetworkSnapshotToWorkbenchProps } = await import(
  path.join(ROOT, "lib/server/snapshot-mapper.ts")
);

function buildValidExplorerSnapshot(overrides = {}) {
  const rootHash = "a".repeat(64);
  const replayHash = "b".repeat(64);
  const eventHistoryRoot = "c".repeat(64);
  const proposalDigest = "d".repeat(64);
  const evRegionHash = "e".repeat(64);
  const certId = "cert_0001";

  const base = {
    kernel_version: "vnetwork-node/0.2.0",
    protocol_version: "1.0.0",
    storage_engine: "redb+wal",
    state_root: rootHash,
    replay_hash: replayHash,
    event_history_root: eventHistoryRoot,
    status: {
      network_id: "vector-mainnet-1",
      profile: "PRODUCTION",
      node_id: "nod_alpha",
      kernel_version: "vnetwork-node/0.2.0",
      protocol_version: "1.0.0",
      storage_engine: "redb+wal",
      storage_ok: true,
      wal_consistency_ok: true,
      equivocation_store_ok: true,
      committed_events: 1,
      logical_clock: 1,
      state_root: rootHash,
      replay_hash: replayHash,
      event_history_root: eventHistoryRoot,
      active_validators: 4,
    },
    health: {
      healthy: true,
      ready: true,
      kernel_version: "vnetwork-node/0.2.0",
      protocol_version: "1.0.0",
      node_pubkey: "11".repeat(32),
      storage_ok: true,
      wal_consistency_ok: true,
      equivocation_store_ok: true,
      equivocation_count: 0,
      verification_status: "VERIFIED",
      key_storage_mode: "encrypted-file",
    },
    network_info: {
      kernel_version: "vnetwork-node/0.2.0",
      protocol_version: "1.0.0",
    },
    proofs: {
      network_id: "vector-mainnet-1",
      protocol_version: "1.0.0",
      chain_valid: true,
      certified_event_count: 1,
      event_history_root: eventHistoryRoot,
      verification_status: "VERIFIED",
      certificate_verifications: [
        {
          certificate_id: certId,
          verification_status: "VERIFIED",
          event_hashes: [evRegionHash],
          ordered_event_ids: ["evt_reg_1"],
        },
      ],
    },
    replay: {
      valid: true,
      replayed_state_root: rootHash,
      live_state_root: rootHash,
      replayed_replay_hash: replayHash,
      live_replay_hash: replayHash,
      events_replayed: 1,
    },
    regions: [
      {
        region_id: "reg_atlas",
        space_id: "spc_atlas",
        name: "ATLAS",
        prefix: "ATL",
        title: "Atlas Region",
        visibility: "PUBLIC",
        section: 1,
        auth_ratio_bps: 900,
        creator_pubkey: "22".repeat(32),
        created_at_ms: 1_700_000_000_000,
        version: 1,
      },
    ],
    wallets: [
      {
        wallet_id: "wal_1",
        owner_pubkey: "22".repeat(32),
        name: "Alice",
        region_id: "reg_atlas",
        auth_ratio: 950,
        created_at_ms: 1_700_000_000_000,
      },
    ],
    tokens: [
      {
        token_id: "tok_vec",
        name: "Vector",
        symbol: "VEC",
        region_id: "reg_atlas",
        decimals: 8,
        max_supply: "10000",
        total_supply: "900",
        minted_supply: "1000",
        drain_bps: 100,
        creator_pubkey: "22".repeat(32),
        purpose: "Network utility",
        created_at_ms: 1_700_000_000_000,
        version: 1,
      },
    ],
    balances: [
      {
        token_id: "tok_vec",
        wallet_id: "wal_1",
        vector: { token: "700", auth_ratio_au: 950, energy: "100" },
        updated_at_ms: 1_700_000_000_000,
        version: 1,
      },
      {
        token_id: "tok_vec",
        wallet_id: "escrow::loan_1",
        vector: { token: "200", auth_ratio_au: 1000, energy: "0" },
        updated_at_ms: 1_700_000_000_000,
        version: 1,
      },
    ],
    supply_breakdowns: {
      tok_vec: {
        conserved: true,
        verification_status: "VERIFIED",
        verification_reason: null,
        circulating_and_escrow_total: "900",
        wallet_balances_total: "700",
        escrow_balances_total: "0",
        locked_collateral_total: "200",
        reserve_balances_total: "0",
        unknown_account_balances_total: "0",
        burned_supply: "100",
        drained_fees_total: "25",
      },
    },
    events: [
      {
        event_id: "evt_reg_1",
        parent_hashes: [],
        entity_kind: "region",
        entity_id: "reg_atlas",
        operation: "REGION_CREATE",
        actor_pubkey: "22".repeat(32),
        logical_clock: 1,
        timestamp_ms: 1_700_000_000_000,
        payload_hash: "f".repeat(64),
        event_hash: evRegionHash,
        auth_ratio: 900,
        signature: "33".repeat(64),
      },
    ],
    certificates: [
      {
        certificate_id: certId,
        height: 1,
        post_state_root: rootHash,
        proposal_digest: proposalDigest,
        event_hashes: [evRegionHash],
        finalized_at_ms: 1_700_000_000_001,
        votes: [],
      },
    ],
    consensus: {
      validators: [
        {
          validator_id: "val_1",
          validator_pubkey_hex: "44".repeat(32),
          weight: 100,
          active: true,
        },
      ],
      equivocation_count: 0,
    },
    equivocations: [],
  };

  return {
    reachable: true,
    endpoint: "http://127.0.0.1:8080",
    data: { ...base, ...overrides },
  };
}

test("JavaScript SDK canonicalTransferApprovalObject includes domain and omits drain_bps", () => {
  const obj = canonicalTransferApprovalObject({
    networkId: "vector-devnet-1",
    tokenId: "tok_demo",
    fromWalletId: "wal_a",
    toWalletId: "wal_b",
    amount: 1000,
  });
  assert.equal(obj.domain, "vnetwork/transfer-approval/v1");
  assert.equal("drain_bps" in obj, false);
  assert.equal(obj.amount, "1000");
});

test("JavaScript SDK rejects weak all-zero and identity Ed25519 public keys", () => {
  const msg = canonicalJsonBytes({ hello: "world" });
  assert.equal(verifyEd25519("00".repeat(32), msg, "00".repeat(64)), false);
  assert.equal(verifyEd25519("01" + "00".repeat(31), msg, "00".repeat(64)), false);
});

test("ClientIdentity produces distinct deterministic node_id and participant_id", () => {
  const seedA = "11".repeat(32);
  const seedB = "22".repeat(32);
  const id = ClientIdentity.fromKeys("parity-test", seedA, seedB);
  assert.ok(id.participant_id.startsWith("prt_"));
  assert.ok(id.node_id.startsWith("nod_"));
  assert.notEqual(id.participant_id, id.node_id);

  const payload = canonicalJsonBytes({ action: "test", count: 42 });
  const sig = signEd25519(seedA, payload);
  assert.equal(verifyEd25519(id.participant_key.public_key_hex, payload, sig), true);
  assert.equal(blake3Hex("").length, 64);
});

test("lib/client-crypto.ts uses vnetwork/transfer-approval/v1, omits drain_bps, and avoids broken randomSecretKey", () => {
  const src = readFileSync(path.join(ROOT, "lib/client-crypto.ts"), "utf8");
  assert.match(src, /DOM_TRANSFER_APPROVAL_V1\s*=\s*"vnetwork\/transfer-approval\/v1"/);
  assert.doesNotMatch(src, /drain_bps/);
  assert.doesNotMatch(src, /randomSecretKey/);
  assert.match(src, /ed\.utils\.randomPrivateKey\(\)/);
});

test("Explorer proxy & components contain zero fabricated verification claims or 200 bps fallbacks", () => {
  const proxySrc = readFileSync(path.join(ROOT, "lib/server/snapshot-mapper.ts"), "utf8");
  const formatSrc = readFileSync(path.join(ROOT, "lib/format.ts"), "utf8");
  const healthRouteSrc = readFileSync(path.join(ROOT, "app/api/health/route.ts"), "utf8");
  const replayRouteSrc = readFileSync(path.join(ROOT, "app/api/replay/route.ts"), "utf8");
  const tokensPanelSrc = readFileSync(path.join(ROOT, "components/TokensPanel.tsx"), "utf8");

  assert.doesNotMatch(proxySrc, /rust-wal-sqlite/);
  assert.doesNotMatch(proxySrc, /vector-network\/1\.0\.0/);
  assert.doesNotMatch(proxySrc, /db_integrity_ok:\s*true/);
  assert.doesNotMatch(proxySrc, /replay_verified:\s*Boolean\(replayHash\)/);

  assert.doesNotMatch(formatSrc, /baseBps\s*=\s*200/);
  assert.doesNotMatch(formatSrc, /authRatio\s*=\s*1000/);
  assert.doesNotMatch(tokensPanelSrc, /\?\?\s*200/);
  assert.doesNotMatch(tokensPanelSrc, /\?\?\s*1000/);

  assert.match(healthRouteSrc, /wal_consistency_ok/);
  assert.match(healthRouteSrc, /equivocation_store_ok/);
  assert.match(replayRouteSrc, /\/v1\/ledger\/replay/);
});

test("Explorer mapper: 1. valid certified snapshot returns VERIFIED and keeps burned_supply distinct from drained_fees", () => {
  const props = mapNetworkSnapshotToWorkbenchProps(buildValidExplorerSnapshot());
  assert.equal(props.initialStatus.verification_status, "VERIFIED");
  assert.equal(props.initialStatus.replay_status, "VERIFIED");
  assert.equal(props.initialStatus.replay_verified, true);
  assert.equal(props.initialStatus.kernel_version, "vnetwork-node/0.2.0");
  assert.equal(props.initialStatus.protocol_version, "1.0.0");
  assert.equal(props.initialEvents[0].certified, true);
  assert.equal(props.initialEvents[0].verification_status, "VERIFIED");
  assert.equal(props.initialSnapshots[0].verification_status, "VERIFIED");
  assert.equal(props.initialSnapshots[0].event_root, "c".repeat(64));
  assert.equal(props.initialSnapshots[0].proposal_digest, "d".repeat(64));
  assert.equal(props.initialTokens[0].burned_supply, "100");
  assert.equal(props.initialTokens[0].drained_fees_collected, "25");
  assert.equal(props.initialTokens[0].conservation.verification_status, "VERIFIED");
});

test("Explorer mapper: 2. invalid certificate marks snapshot & node status INVALID", () => {
  const snap = buildValidExplorerSnapshot();
  snap.data.proofs.chain_valid = false;
  snap.data.proofs.certificate_verifications[0].verification_status = "INVALID";
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialStatus.verification_status, "INVALID");
  assert.equal(props.initialSnapshots[0].verification_status, "INVALID");
  assert.equal(props.initialEvents[0].certified, false);
  assert.equal(props.initialEvents[0].verification_status, "INVALID");
});

test("Explorer mapper: 3. missing certificate verification yields UNVERIFIED (never VERIFIED)", () => {
  const snap = buildValidExplorerSnapshot();
  snap.data.proofs.certificate_verifications = [];
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialStatus.verification_status, "UNVERIFIED");
  assert.equal(props.initialSnapshots[0].verification_status, "UNVERIFIED");
  assert.equal(props.initialEvents[0].certified, false);
  assert.equal(props.initialEvents[0].verification_status, "UNVERIFIED");
});

test("Explorer mapper: 4. invalid validator signature (marked INVALID in certificate_verifications) rejects verification", () => {
  const snap = buildValidExplorerSnapshot();
  snap.data.proofs.certificate_verifications = [
    {
      certificate_id: "cert_0001",
      verification_status: "INVALID",
      verification_reason: "Invalid validator signature",
      event_hashes: ["e".repeat(64)],
      ordered_event_ids: ["evt_reg_1"],
    },
  ];
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialStatus.verification_status, "INVALID");
  assert.equal(props.initialSnapshots[0].verification_status, "INVALID");
  assert.equal(props.initialEvents[0].certified, false);
});

test("Explorer mapper: 5. insufficient quorum cannot be spoofed by non-empty votes array", () => {
  const snap = buildValidExplorerSnapshot();
  snap.data.certificates[0].votes = [
    { validator_id: "v1" },
    { validator_id: "v2" },
    { validator_id: "v3" },
  ];
  snap.data.proofs.chain_valid = false;
  snap.data.proofs.certificate_verifications = [
    {
      certificate_id: "cert_0001",
      verification_status: "INVALID",
      verification_reason: "Insufficient quorum weight",
      event_hashes: ["e".repeat(64)],
      ordered_event_ids: ["evt_reg_1"],
    },
  ];
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialStatus.verification_status, "INVALID");
  assert.equal(props.initialEvents[0].certified, false);
});

test("Explorer mapper: 6. incorrect network_id in proofs marks node status and replay INVALID", () => {
  const snap = buildValidExplorerSnapshot();
  snap.data.proofs.network_id = "rogue-testnet-99";
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialStatus.replay_status, "INVALID");
  assert.equal(props.initialStatus.replay_verified, false);
  assert.equal(props.initialStatus.verification_status, "INVALID");
});

test("Explorer mapper: 7. mismatched state root rejects replay and overall status", () => {
  const snap = buildValidExplorerSnapshot();
  snap.data.replay.replayed_state_root = "9".repeat(64);
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialStatus.replay_status, "INVALID");
  assert.equal(props.initialStatus.replay_verified, false);
  assert.equal(props.initialStatus.verification_status, "INVALID");
});

test("Explorer mapper: 8. missing replay or proof report stays UNVERIFIED (never defaults verified)", () => {
  const noReplay = buildValidExplorerSnapshot({ replay: null });
  const propsNoReplay = mapNetworkSnapshotToWorkbenchProps(noReplay);
  assert.equal(propsNoReplay.initialStatus.replay_status, "UNVERIFIED");
  assert.equal(propsNoReplay.initialStatus.replay_verified, false);
  assert.equal(propsNoReplay.initialStatus.verification_status, "UNVERIFIED");

  const noProofs = buildValidExplorerSnapshot({ proofs: null });
  const propsNoProofs = mapNetworkSnapshotToWorkbenchProps(noProofs);
  assert.equal(propsNoProofs.initialStatus.replay_status, "UNVERIFIED");
  assert.equal(propsNoProofs.initialStatus.replay_verified, false);
  assert.equal(propsNoProofs.initialStatus.verification_status, "UNVERIFIED");
});

test("Explorer mapper: 9. partial balance dataset keeps token conservation UNVERIFIED", () => {
  const snap = buildValidExplorerSnapshot({ balances: null });
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialTokens[0].conservation.conserved, false);
  assert.equal(props.initialTokens[0].conservation.verification_status, "UNVERIFIED");
  assert.equal(props.initialStatus.verification_status, "UNVERIFIED");
});

test("Explorer mapper: 10. unknown account category prevents VERIFIED supply conservation", () => {
  const snap = buildValidExplorerSnapshot();
  snap.data.balances.push({
    token_id: "tok_vec",
    wallet_id: "shadow::unknown_bucket",
    vector: { token: "50", auth_ratio_au: 1000, energy: "0" },
    updated_at_ms: 1_700_000_000_000,
    version: 1,
  });
  snap.data.tokens[0].total_supply = "950";
  snap.data.supply_breakdowns.tok_vec.circulating_and_escrow_total = "950";
  snap.data.supply_breakdowns.tok_vec.unknown_account_balances_total = "50";
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialTokens[0].conservation.unknown_account_balances_total, "50");
  assert.equal(props.initialTokens[0].conservation.verification_status, "UNVERIFIED");
  assert.equal(props.initialStatus.verification_status, "UNVERIFIED");
});

test("Explorer mapper: 11. invalid event ancestry / failed chain marks status INVALID", () => {
  const snap = buildValidExplorerSnapshot();
  snap.data.proofs.chain_valid = false;
  snap.data.proofs_error = "Broken parent hash linkage at height 1";
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialStatus.verification_status, "INVALID");
  assert.equal(props.initialStatus.replay_status, "INVALID");
});

test("Explorer mapper: 12. missing region creation event yields null hashes & preserves honest null metadata", () => {
  const snap = buildValidExplorerSnapshot();
  delete snap.data.kernel_version;
  delete snap.data.status.kernel_version;
  delete snap.data.health.kernel_version;
  delete snap.data.network_info.kernel_version;
  delete snap.data.regions[0].section;
  delete snap.data.wallets[0].auth_ratio;
  delete snap.data.balances[0].vector.auth_ratio_au;
  snap.data.events = [
    {
      event_id: "evt_unrelated",
      parent_hashes: [],
      entity_kind: "token",
      entity_id: "tok_vec",
      operation: "TOKEN_CREATE",
      actor_pubkey: "22".repeat(32),
      logical_clock: 1,
      timestamp_ms: 1_700_000_000_000,
      payload_hash: "f".repeat(64),
      event_hash: "7".repeat(64),
    },
  ];
  const props = mapNetworkSnapshotToWorkbenchProps(snap);
  assert.equal(props.initialStatus.kernel_version, "unknown");
  assert.equal(props.initialRegions[0].section, null);
  assert.equal(props.initialRegions[0].trigger_event_hash, null);
  assert.equal(props.initialRegions[0].creation_proof_hash, null);
  assert.equal(props.initialWallets[0].auth_ratio, null);
  assert.equal(props.initialEvents[0].auth_ratio, null);
  assert.equal(props.initialEvents[0].signature, null);
});
