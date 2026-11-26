import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  AtlasKernel,
  authorizeRegionAccess,
  canonicalRegionId,
  canonicalRegionRequestSignatureBytes,
  checkedAddU128,
  generateEd25519Keypair,
  signEd25519,
  U128_MAX,
  validateDag,
  validateEventIntegrity,
  verifyEd25519,
} from "../src/index.ts";

function makeTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("wallet generation, signing, invalid signature rejection, and no private key exposure", () => {
  const dir = makeTempDir("atlas-wallet-");
  try {
    const kernel = new AtlasKernel(dir);
    const wallet = kernel.createWallet("primary");
    assert.ok(wallet.wallet_id.startsWith("wlt_"));
    assert.equal(wallet.public_key_hex.length, 64);
    assert.equal("privateKey" in wallet, false);
    assert.equal("privateSeedHex" in wallet, false);

    const payload = Buffer.from("atlas-test-message", "utf8");
    const sig = kernel.signWithWallet(wallet.wallet_id, payload);
    assert.equal(sig.length, 128);
    assert.equal(verifyEd25519(wallet.public_key_hex, payload, sig), true);
    assert.equal(verifyEd25519(wallet.public_key_hex, Buffer.from("tampered"), sig), false);

    const otherKp = generateEd25519Keypair();
    const badSig = signEd25519(otherKp.privateSeedHex, payload);
    assert.equal(verifyEd25519(wallet.public_key_hex, payload, badSig), false);
    kernel.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("canonical ATLAS region creation, duplicate rejection, private access control, and persistence across restart", () => {
  const dir = makeTempDir("atlas-region-");
  try {
    let kernel = new AtlasKernel(dir);
    const creator = kernel.createWallet("atlas-creator");

    const { region, event, request } = kernel.createSignedRegionWithWallet({
      creatorWalletId: creator.wallet_id,
      regionName: "ATLAS",
      regionPrefix: "ATL",
      suggestedTitle: "Atlas Vector Region",
      visibility: "public",
      section: 1,
    });

    assert.equal(region.region_name, "ATLAS");
    assert.equal(region.region_prefix, "ATL");
    assert.equal(region.suggested_title, "Atlas Vector Region");
    assert.equal(region.visibility, "public");
    assert.equal(region.section, 1);
    assert.equal(region.creator_public_key, creator.public_key_hex);
    assert.equal(region.region_id, canonicalRegionId(request, creator.public_key_hex, 1));
    assert.ok(region.region_id.startsWith("ATL::rgn_"));
    assert.equal(authorizeRegionAccess(region, null), true);

    // Duplicate region creation must be rejected
    assert.throws(() =>
      kernel.createSignedRegionWithWallet({
        creatorWalletId: creator.wallet_id,
        regionName: "atlas",
        regionPrefix: "atl",
        suggestedTitle: "Duplicate",
        visibility: "public",
        section: 1,
      }),
    );

    // Invalid trigger_event_hash must be rejected
    const badReq = {
      ...request,
      region_name: "OTHER",
      region_prefix: "OTH",
      trigger_event_hash: "nonexistent-trigger-hash",
      request_signature: "",
    };
    const kp = generateEd25519Keypair();
    badReq.request_signature = signEd25519(kp.privateSeedHex, canonicalRegionRequestSignatureBytes(badReq));
    assert.throws(() => kernel.createRegion(badReq, kp.publicKeyHex), /trigger_event_hash not found/);

    // Private region access key check
    const priv = kernel.createSignedRegionWithWallet({
      creatorWalletId: creator.wallet_id,
      regionName: "VAULT",
      regionPrefix: "VLT",
      suggestedTitle: "Private Vault",
      visibility: "private",
      section: 2,
      accessKey: "secret-atlas-key",
    });
    assert.equal(authorizeRegionAccess(priv.region, null), false);
    assert.equal(authorizeRegionAccess(priv.region, "wrong"), false);
    assert.equal(authorizeRegionAccess(priv.region, "secret-atlas-key"), true);

    const savedRegionId = region.region_id;
    const savedEventHash = event.event_hash;
    kernel.close();

    // Restart from persistent SQLite store
    kernel = new AtlasKernel(dir);
    const reloaded = kernel.getRegion(savedRegionId);
    assert.ok(reloaded);
    assert.equal(reloaded.region_id, savedRegionId);
    assert.equal(reloaded.region_root, savedEventHash);
    const replay = kernel.replayCanonicalHistory();
    assert.equal(replay.matches_stored_state, true);
    kernel.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("ATLAS TOKEN lifecycle, supply conservation, authorization, overflow, duplicate protection, restart & replay", () => {
  const dir = makeTempDir("atlas-token-");
  try {
    let kernel = new AtlasKernel(dir);
    const primary = kernel.createWallet("primary-atlas-wallet");
    const secondary = kernel.createWallet("secondary-test-wallet");
    const attacker = kernel.createWallet("attacker");

    const { region } = kernel.createSignedRegionWithWallet({
      creatorWalletId: primary.wallet_id,
      regionName: "ATLAS",
      regionPrefix: "ATL",
      suggestedTitle: "Atlas Vector Region",
      visibility: "public",
      section: 1,
    });

    const { token } = kernel.createTokenWithWallet({
      authorityWalletId: primary.wallet_id,
      requestId: "req-create-atlas-1",
      name: "ATLAS TOKEN",
      symbol: "ATLAS",
      regionId: region.region_id,
      decimals: 8,
      maxSupply: "100000000000000000", // 1B ATLAS
      supplyPolicy: "development-test-supply-no-external-value",
    });

    // Duplicate token registration rejected
    assert.throws(() =>
      kernel.createTokenWithWallet({
        authorityWalletId: primary.wallet_id,
        requestId: "req-create-atlas-2",
        name: "ATLAS TOKEN",
        symbol: "ATLAS",
        regionId: region.region_id,
        decimals: 8,
        maxSupply: "100000000000000000",
        supplyPolicy: "dev",
      }),
    );

    // Unauthorized transport rejected
    assert.throws(() =>
      kernel.transportTokenWithWallet({
        authorityWalletId: attacker.wallet_id,
        requestId: "req-transport-unauth",
        tokenId: token.token_id,
        toWalletId: attacker.wallet_id,
        amount: "1000",
      }),
      /unauthorized transport/,
    );

    // Authorized transport: 1,000,000 ATLAS (1000000 * 10^8)
    kernel.transportTokenWithWallet({
      authorityWalletId: primary.wallet_id,
      requestId: "req-transport-1",
      tokenId: token.token_id,
      toWalletId: primary.wallet_id,
      amount: "100000000000000",
    });

    // Duplicate request_id rejected
    assert.throws(() =>
      kernel.transportTokenWithWallet({
        authorityWalletId: primary.wallet_id,
        requestId: "req-transport-1",
        tokenId: token.token_id,
        toWalletId: primary.wallet_id,
        amount: "1000",
      }),
      /duplicate request_id/,
    );

    // Transfer 250,000 ATLAS to secondary with drain fee
    const tx = kernel.transferTokenWithWallet({
      senderWalletId: primary.wallet_id,
      requestId: "req-tx-1",
      tokenId: token.token_id,
      toWalletId: secondary.wallet_id,
      amount: "25000000000000",
    });

    assert.ok(BigInt(tx.fromBalance.balance) < "100000000000000");
    assert.ok(BigInt(tx.toBalance.balance) > 0n);

    // Insufficient balance rejected
    assert.throws(() =>
      kernel.transferTokenWithWallet({
        senderWalletId: secondary.wallet_id,
        requestId: "req-tx-over",
        tokenId: token.token_id,
        toWalletId: primary.wallet_id,
        amount: "999999999999999",
      }),
      /insufficient balance/,
    );

    // Burn 10,000 ATLAS from secondary
    const burned = kernel.burnTokenWithWallet({
      ownerWalletId: secondary.wallet_id,
      requestId: "req-burn-1",
      tokenId: token.token_id,
      amount: "1000000000000",
    });
    assert.ok(BigInt(burned.balance.balance) > 0n);
    assert.equal(burned.token.burned_supply, "1000000000000");

    // Integer overflow check
    assert.throws(() => checkedAddU128(U128_MAX, 1n), /overflow/);

    // Supply conservation
    const conservation = kernel.verifySupplyConservation(token.token_id);
    assert.equal(conservation.conserved, true);

    // Snapshot & verification
    const snap = kernel.createAndStoreSnapshot();
    assert.equal(kernel.verifySnapshot(snap), true);

    const tokenId = token.token_id;
    const primaryId = primary.wallet_id;
    kernel.close();

    // Restart and verify persistence + replay
    kernel = new AtlasKernel(dir);
    assert.ok(kernel.store.getTokenBalance(tokenId, primaryId));
    const replay = kernel.replayCanonicalHistory();
    assert.equal(replay.matches_stored_state, true);

    // Tampered event rejected by validateEventIntegrity
    const events = kernel.store.listEvents();
    const tampered = structuredClone(events[0]);
    tampered.actor_public_key = "tampered";
    assert.throws(() => validateEventIntegrity(tampered), /payload_hash mismatch/);

    // DAG validation rejects missing parent
    const orphan = structuredClone(events[0]);
    orphan.parent_hashes = ["missing-parent-hash"];
    assert.throws(() => validateDag([orphan]), /missing parent/);

    // BFT consensus validator & attestation test
    kernel.registerValidator({
      node_id: kernel.nodeId,
      public_key_hex: kernel.nodePubkey,
      label: "Local Node",
      weight: 100,
      active: true,
    });
    kernel.attestEventWithLocalNode(events[0].event_hash, true);
    const round = kernel.getConsensusRound(events[0].event_hash);
    assert.equal(round.finalized, true);

    // Sync bundle export/import test
    const bundle = kernel.exportSyncBundle();
    assert.equal(bundle.events.length, events.length);

    const importDir = makeTempDir("atlas-import-");
    try {
      const importKernel = new AtlasKernel(importDir);
      importKernel.importPeerSyncBundle(bundle);
      assert.equal(importKernel.store.listEvents().length, events.length);
      importKernel.close();
    } finally {
      fs.rmSync(importDir, { recursive: true, force: true });
    }

    // Backup verification
    const backupFile = path.join(dir, "backup.db");
    kernel.store.backupTo(backupFile);
    assert.equal(fs.existsSync(backupFile), true);
    kernel.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
