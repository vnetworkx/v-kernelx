import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalJsonBytes as jsCanonicalJsonBytes,
  canonicalTransferApprovalObject as jsTransferObj,
  ClientIdentity as JsIdentity,
  loadModulesForSource as jsLoadModules,
  signEd25519 as jsSignEd25519,
  verifyEd25519 as jsVerifyEd25519,
  VectorNetworkClient as JsVectorNetworkClient,
} from "../../sdks/javascript/index.js";
import {
  browserKeypairFromPrivateHex as jsBrowserFromPriv,
  canonicalProgramSubmitObject as jsBrowserProgramObj,
  canonicalTransferApprovalObject as jsBrowserTransferObj,
  canonicalWalletPopObject as jsBrowserPopObj,
  deriveNodeId as jsBrowserNodeId,
  deriveParticipantId as jsBrowserParticipantId,
  generateBrowserKeypair as jsBrowserGenerateKeypair,
  signBrowserEd25519 as jsBrowserSign,
  verifyBrowserEd25519 as jsBrowserVerify,
  BrowserVectorNetworkClient as JsBrowserVectorNetworkClient,
} from "../../sdks/javascript/browser.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("JS, TS, Browser-JS, Browser-TS, and Python SDKs produce bit-identical BLAKE3, canonical JSON, IDs, and Ed25519 signatures", async () => {
  const jsOut = JSON.parse(
    execFileSync("node", [path.join(ROOT, "tests/cross_language/verify_parity.mjs")], {
      encoding: "utf8",
    }),
  );
  let tsCmd = "tsx";
  try {
    execFileSync("tsx", ["--version"], { stdio: "ignore" });
  } catch {
    tsCmd = "bun";
  }
  const tsOut = JSON.parse(
    execFileSync(tsCmd, [path.join(ROOT, "tests/cross_language/verify_parity.ts")], {
      encoding: "utf8",
    }),
  );
  const pyOut = JSON.parse(
    execFileSync("python3", [path.join(ROOT, "tests/cross_language/verify_parity.py")], {
      encoding: "utf8",
    }),
  );

  const fields = [
    "empty_b3",
    "hello_b3",
    "multi_b3",
    "canon_str",
    "participant_pubkey",
    "participant_id",
    "node_id",
    "sig",
    "submit_str",
    "submit_sig",
    "pop_str",
    "pop_sig",
    "xfer_str",
    "xfer_sig",
  ];

  for (const field of fields) {
    assert.equal(tsOut[field], jsOut[field], `TS vs JS mismatch on ${field}`);
    assert.equal(pyOut[field], jsOut[field], `Python vs JS mismatch on ${field}`);
  }

  const parsedXfer = JSON.parse(jsOut.xfer_str);
  assert.equal(parsedXfer.domain, "vnetwork/transfer-approval/v1");
  assert.equal("drain_bps" in parsedXfer, false);

  // Browser WebCrypto JS parity against Node parity vector
  const SEED_HEX = "1111111111111111111111111111111111111111111111111111111111111111";
  const NODE_SEED_HEX = "2222222222222222222222222222222222222222222222222222222222222222";
  const browserP = await jsBrowserFromPriv("participant", SEED_HEX);
  const browserN = await jsBrowserFromPriv("node", NODE_SEED_HEX);
  assert.equal(browserP.public_key_hex, jsOut.participant_pubkey);
  assert.equal(browserP.derived_id, jsOut.participant_id);
  assert.equal(browserN.derived_id, jsOut.node_id);
  assert.equal(jsBrowserParticipantId(browserP.public_key_hex), jsOut.participant_id);
  assert.equal(jsBrowserNodeId(browserN.public_key_hex), jsOut.node_id);
  assert.notEqual(
    jsBrowserParticipantId(browserP.public_key_hex),
    jsBrowserNodeId(browserP.public_key_hex),
    "Participant ID and Node ID domain prefixes must separate identical pubkeys",
  );

  const bCanon = jsCanonicalJsonBytes({ b: 2, nil: null, html: "<a>&", a: { z: true, m: [3, 1, 2] } });
  const bSig = await jsBrowserSign(SEED_HEX, bCanon);
  assert.equal(bSig, jsOut.sig);
  assert.equal(await jsBrowserVerify(browserP.public_key_hex, bCanon, bSig), true);

  const bXfer = jsCanonicalJsonBytes(
    jsBrowserTransferObj({
      networkId: "vector-devnet-1",
      tokenId: "tok_atlas",
      fromWalletId: "wal_a",
      toWalletId: "wal_b",
      amount: 250,
    }),
  );
  assert.equal(Buffer.from(bXfer).toString("utf8"), jsOut.xfer_str);
  assert.equal(await jsBrowserSign(SEED_HEX, bXfer), jsOut.xfer_sig);

  const bSubmit = jsCanonicalJsonBytes(
    jsBrowserProgramObj({
      actorPubkey: browserP.public_key_hex,
      fileName: "bootstrap-atlas.vx",
      sourceBytes: "Wallet Main;",
      modules: { "policies.vdx": "Space ATLAS;" },
      networkId: "vector-devnet-1",
      requestId: "req_0001",
      nonce: 7,
      executionParams: { dry: false },
    }),
  );
  assert.equal(Buffer.from(bSubmit).toString("utf8"), jsOut.submit_str);

  const bPop = jsCanonicalJsonBytes(
    jsBrowserPopObj({
      networkId: "vector-devnet-1",
      walletId: "wal_demo",
      participantIdentity: browserP.derived_id,
      authorizedPubkey: browserN.public_key_hex,
      purpose: "wallet_key_authorization",
      nonce: "pop_1",
      expiresAtMs: null,
    }),
  );
  assert.equal(Buffer.from(bPop).toString("utf8"), jsOut.pop_str);

  const genKp = await jsBrowserGenerateKeypair("participant");
  const genSig = await jsBrowserSign(genKp.private_key_hex, Buffer.from("browser-roundtrip"));
  assert.equal(await jsBrowserVerify(genKp.public_key_hex, Buffer.from("browser-roundtrip"), genSig), true);
  assert.equal(jsVerifyEd25519(genKp.public_key_hex, Buffer.from("browser-roundtrip"), genSig), true);
});

test("Large u128 decimal string amounts preserve exact precision without precision loss", () => {
  const huge = "123456789012345678901234567890";
  const obj = jsTransferObj({
    networkId: "vector-devnet-1",
    tokenId: "tok_atlas",
    fromWalletId: "wal_a",
    toWalletId: "wal_b",
    amount: huge,
  });
  assert.equal(obj.amount, huge);

  const objBig = jsTransferObj({
    networkId: "vector-devnet-1",
    tokenId: "tok_atlas",
    fromWalletId: "wal_a",
    toWalletId: "wal_b",
    amount: 123456789012345678901234567890n,
  });
  assert.equal(objBig.amount, huge);
  assert.throws(() =>
    jsTransferObj({
      networkId: "vector-devnet-1",
      tokenId: "tok_atlas",
      fromWalletId: "wal_a",
      toWalletId: "wal_b",
      amount: -5,
    }),
  );
  assert.throws(() =>
    jsTransferObj({
      networkId: "vector-devnet-1",
      tokenId: "tok_atlas",
      fromWalletId: "wal_a",
      toWalletId: "wal_b",
      amount: "12.34",
    }),
  );
});

test("Node SDK persists and serializes request nonce reservations across client restarts", async () => {
  const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "vnetwork_sdk_nonce_"));
  try {
    const identity = JsIdentity.fromKeys(
      "nonce-test",
      "1111111111111111111111111111111111111111111111111111111111111111",
      "2222222222222222222222222222222222222222222222222222222222222222",
    );
    const storePath = path.join(tmpRoot, "request-nonce.json");
    const clients = [
      new JsVectorNetworkClient("http://127.0.0.1:8080", identity, "nonce-test-network", storePath),
      new JsVectorNetworkClient("http://127.0.0.1:8080", identity, "nonce-test-network", storePath),
    ];
    for (const client of clients) client.connectedNetworkId = "nonce-test-network";
    const reserved = await Promise.all(clients.map((client) => client.reserveNonce()));
    assert.deepEqual(reserved.sort((a, b) => a - b), [1, 2]);

    const restarted = new JsVectorNetworkClient(
      "http://127.0.0.1:8080", identity, "nonce-test-network", storePath,
    );
    restarted.connectedNetworkId = "nonce-test-network";
    assert.equal(await restarted.reserveNonce(), 3);

    const saved = JSON.parse(await fs.readFile(storePath, "utf8"));
    assert.equal(saved.version, 1);
    assert.equal(saved.network_id, "nonce-test-network");
    assert.equal(saved.actor_pubkey, identity.participant_key.public_key_hex);
    assert.equal(saved.next_nonce, 4);
  } finally {
    await fs.rm(tmpRoot, { recursive: true, force: true });
  }
});

test("Browser SDK persists nonce reservations across tabs and page restarts", async () => {
  const identity = JsIdentity.fromKeys(
    "browser-nonce-test",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
  );
  const values = new Map();
  const storage = {
    getItem(key) { return values.has(key) ? values.get(key) : null; },
    setItem(key, value) { values.set(key, String(value)); },
  };
  let lockQueue = Promise.resolve();
  const lockManager = {
    request(_name, callback) {
      const result = lockQueue.then(callback);
      lockQueue = result.then(() => undefined, () => undefined);
      return result;
    },
  };
  const clients = [
    new JsBrowserVectorNetworkClient("https://node.invalid", identity, "browser-network", storage, lockManager),
    new JsBrowserVectorNetworkClient("https://node.invalid", identity, "browser-network", storage, lockManager),
  ];
  for (const client of clients) client.connectedNetworkId = "browser-network";
  const reserved = await Promise.all(clients.map((client) => client.reserveNonce()));
  assert.deepEqual(reserved.sort((a, b) => a - b), [1, 2]);

  const restarted = new JsBrowserVectorNetworkClient(
    "https://node.invalid", identity, "browser-network", storage, lockManager,
  );
  restarted.connectedNetworkId = "browser-network";
  assert.equal(await restarted.reserveNonce(), 3);
  const entry = [...values.entries()][0];
  const saved = JSON.parse(entry[1]);
  assert.equal(saved.version, 1);
  assert.equal(saved.network_id, "browser-network");
  assert.equal(saved.actor_pubkey, identity.participant_key.public_key_hex);
  assert.equal(saved.next_nonce, 4);
});

test("Negative crypto parity: rejects weak pubkeys, tampered fields, and malformed signatures", async () => {
  const ident = JsIdentity.fromKeys(
    "neg",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
  );
  const msg = jsCanonicalJsonBytes({ amount: "250", to: "wal_b" });
  const sig = jsSignEd25519(ident.participant_key.private_key_hex, msg);

  assert.equal(jsVerifyEd25519("0".repeat(64), msg, sig), false);
  assert.equal(jsVerifyEd25519("01" + "0".repeat(62), msg, sig), false);
  assert.equal(jsVerifyEd25519("zzzz".repeat(16), msg, sig), false);
  assert.equal(jsVerifyEd25519(ident.participant_key.public_key_hex, msg, "00".repeat(32)), false);
  assert.equal(
    jsVerifyEd25519(
      ident.participant_key.public_key_hex,
      jsCanonicalJsonBytes({ amount: "251", to: "wal_b" }),
      sig,
    ),
    false,
  );

  assert.equal(await jsBrowserVerify("0".repeat(64), msg, sig), false);
  assert.equal(await jsBrowserVerify("01" + "0".repeat(62), msg, sig), false);
  assert.equal(
    await jsBrowserVerify(
      ident.participant_key.public_key_hex,
      jsCanonicalJsonBytes({ amount: "251", to: "wal_b" }),
      sig,
    ),
    false,
  );
});

test("SDK module loader rejects path traversal, absolute imports, and symlink escapes", async () => {
  const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "vnetwork_sdk_mod_"));
  try {
    const baseDir = path.join(tmpRoot, "prog");
    await fs.mkdir(baseDir, { recursive: true });
    const safeMod = path.join(baseDir, "safe.vdx");
    const outsideMod = path.join(tmpRoot, "secret.vdx");
    await fs.writeFile(safeMod, 'space create Safe { visibility = "public" }\n', "utf8");
    await fs.writeFile(outsideMod, 'space create Secret { visibility = "public" }\n', "utf8");
    await fs.symlink(outsideMod, path.join(baseDir, "link_out.vdx"));

    const okMods = await jsLoadModules('import "safe.vdx";\nquery network;\n', baseDir);
    assert.ok("safe.vdx" in okMods);

    await assert.rejects(
      () => jsLoadModules('import "../secret.vdx";\nquery network;\n', baseDir),
      /Unsafe module import path/,
    );
    await assert.rejects(
      () => jsLoadModules(`import "${outsideMod}";\nquery network;\n`, baseDir),
      /Unsafe module import path/,
    );
    await assert.rejects(
      () => jsLoadModules('import "link_out.vdx";\nquery network;\n', baseDir),
      /escapes base directory/,
    );
  } finally {
    await fs.rm(tmpRoot, { recursive: true, force: true });
  }
});

test("TypeScript Browser SDK verify and canonical objects match parity via runtime", () => {
  let tsCmd = "tsx";
  try {
    execFileSync("tsx", ["--version"], { stdio: "ignore" });
  } catch {
    tsCmd = "bun";
  }
  const script = `
    import assert from "node:assert/strict";
    import {
      browserKeypairFromPrivateHex,
      canonicalTransferApprovalObject,
      signBrowserEd25519,
      verifyBrowserEd25519,
    } from "./sdks/typescript/src/browser.js";
    import { canonicalJsonBytes } from "./sdks/typescript/src/canonical.js";
    import { loadModulesForSource } from "./sdks/typescript/src/client.js";
    import fs from "node:fs/promises";
    import os from "node:os";
    import path from "node:path";

    const kp = await browserKeypairFromPrivateHex("participant", "11".repeat(32));
    const msg = canonicalJsonBytes(canonicalTransferApprovalObject({
      networkId: "vector-devnet-1",
      tokenId: "tok_atlas",
      fromWalletId: "wal_a",
      toWalletId: "wal_b",
      amount: "123456789012345678901234567890",
    }));
    const sig = await signBrowserEd25519("11".repeat(32), msg);
    assert.equal(await verifyBrowserEd25519(kp.public_key_hex, msg, sig), true);
    assert.equal(await verifyBrowserEd25519("0".repeat(64), msg, sig), false);

    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "ts_mod_"));
    try {
      const dir = path.join(tmp, "proj");
      await fs.mkdir(dir);
      const out = path.join(tmp, "out.vdx");
      await fs.writeFile(out, "query network;", "utf8");
      await fs.symlink(out, path.join(dir, "sym.vdx"));
      await assert.rejects(() => loadModulesForSource('import "../out.vdx";', dir));
      await assert.rejects(() => loadModulesForSource('import "sym.vdx";', dir));
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  `;
  execFileSync(tsCmd, ["--input-type=module", "-e", script], { cwd: ROOT, stdio: "pipe" });
});

test("JS, Browser-JS, TS, and Browser-TS expose full contracts, loans, explorer, and signed envelope APIs", async () => {
  const { VectorNetworkClient } = await import(path.join(ROOT, "sdks/javascript/index.js"));
  const {
    BrowserVectorNetworkClient,
    browserKeypairFromPrivateHex,
    normalizeVerificationStatus,
  } = await import(path.join(ROOT, "sdks/javascript/browser.js"));

  assert.equal(normalizeVerificationStatus("UNKNOWN"), "UNAVAILABLE");
  assert.equal(normalizeVerificationStatus("VERIFIED"), "VERIFIED");

  const jsIdent = JsIdentity.fromKeys("api", "11".repeat(32), "22".repeat(32));
  const jsClient = new VectorNetworkClient("http://127.0.0.1:8080", jsIdent, "vector-devnet-1");
  const browserIdent = await browserKeypairFromPrivateHex("participant", "11".repeat(32));
  const bClient = new BrowserVectorNetworkClient("http://127.0.0.1:8080", browserIdent, "vector-devnet-1");

  const requiredMethods = [
    "listSpaces",
    "listNodes",
    "getNodeDetails",
    "getExplorerNetwork",
    "listContracts",
    "getContract",
    "listLoans",
    "getLoan",
    "createContract",
    "executeContract",
    "createLoan",
    "executeLoan",
    "submitOperation",
  ];
  for (const m of requiredMethods) {
    assert.equal(typeof jsClient[m], "function", `JS VectorNetworkClient missing ${m}`);
    assert.equal(typeof bClient[m], "function", `BrowserVectorNetworkClient missing ${m}`);
  }

  let tsCmd = "tsx";
  try {
    execFileSync("tsx", ["--version"], { stdio: "ignore" });
  } catch {
    tsCmd = "bun";
  }
  const tsCheck = `
    import assert from "node:assert/strict";
    import { VectorNetworkClient, ClientIdentity } from "./sdks/typescript/src/index.js";
    import { BrowserVectorNetworkClient, browserKeypairFromPrivateHex } from "./sdks/typescript/src/browser.js";

    const id = ClientIdentity.fromKeys("api", "11".repeat(32), "22".repeat(32));
    const c = new VectorNetworkClient("http://127.0.0.1:8080", id, "vector-devnet-1");
    const kp = await browserKeypairFromPrivateHex("participant", "11".repeat(32));
    const bc = new BrowserVectorNetworkClient("http://127.0.0.1:8080", kp, "vector-devnet-1");
    for (const m of ${JSON.stringify(requiredMethods)}) {
      assert.equal(typeof (c as any)[m], "function", "TS VectorNetworkClient missing " + m);
      assert.equal(typeof (bc as any)[m], "function", "TS BrowserVectorNetworkClient missing " + m);
    }
  `;
  execFileSync(tsCmd, ["--input-type=module", "-e", tsCheck], { cwd: ROOT, stdio: "pipe" });
});


