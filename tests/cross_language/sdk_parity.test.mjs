import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("JS, TS, and Python SDKs produce bit-identical BLAKE3, canonical JSON, IDs, and Ed25519 signatures", () => {
  const jsOut = JSON.parse(
    execFileSync("node", [path.join(ROOT, "tests/cross_language/verify_parity.mjs")], {
      encoding: "utf8",
    }),
  );
  const tsOut = JSON.parse(
    execFileSync("tsx", [path.join(ROOT, "tests/cross_language/verify_parity.ts")], {
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
});
