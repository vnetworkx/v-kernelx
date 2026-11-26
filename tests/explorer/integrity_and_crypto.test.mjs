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
  const proxySrc = readFileSync(path.join(ROOT, "lib/server/network-proxy.ts"), "utf8");
  const formatSrc = readFileSync(path.join(ROOT, "lib/format.ts"), "utf8");
  const healthRouteSrc = readFileSync(path.join(ROOT, "app/api/health/route.ts"), "utf8");
  const replayRouteSrc = readFileSync(path.join(ROOT, "app/api/replay/route.ts"), "utf8");
  const tokensPanelSrc = readFileSync(path.join(ROOT, "components/TokensPanel.tsx"), "utf8");

  assert.doesNotMatch(proxySrc, /rust-wal-sqlite/);
  assert.doesNotMatch(proxySrc, /db_integrity_ok:\s*true/);
  assert.doesNotMatch(proxySrc, /certified:\s*true/);
  assert.doesNotMatch(proxySrc, /sum_of_balances:\s*totalSupply/);
  assert.doesNotMatch(proxySrc, /replay_verified:\s*Boolean\(replayHash\)/);

  assert.doesNotMatch(formatSrc, /baseBps\s*=\s*200/);
  assert.doesNotMatch(tokensPanelSrc, /\?\?\s*200/);

  assert.match(healthRouteSrc, /wal_consistency_ok/);
  assert.match(healthRouteSrc, /equivocation_store_ok/);
  assert.match(replayRouteSrc, /\/v1\/ledger\/replay/);
});
