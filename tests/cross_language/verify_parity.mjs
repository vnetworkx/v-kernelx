import {
  blake3Hex,
  canonicalJsonBytes,
  canonicalProgramSubmitObject,
  canonicalTransferApprovalObject,
  canonicalWalletPopObject,
  ClientIdentity,
  signEd25519,
  verifyEd25519,
} from "../../sdks/javascript/index.js";

const SEED_HEX = "1111111111111111111111111111111111111111111111111111111111111111";
const NODE_SEED_HEX = "2222222222222222222222222222222222222222222222222222222222222222";
const id = ClientIdentity.fromKeys("parity", SEED_HEX, NODE_SEED_HEX);
const multiChunk = "vector-network-".repeat(200); // > 1024 bytes (3000 bytes)
const canon = canonicalJsonBytes({ b: 2, nil: null, html: "<a>&", a: { z: true, m: [3, 1, 2] } });
const sig = signEd25519(SEED_HEX, canon);
if (!verifyEd25519(id.participant_key.public_key_hex, canon, sig)) {
  throw new Error("JS Ed25519 self-verify failed");
}

const submitCanon = canonicalJsonBytes(canonicalProgramSubmitObject({
  actorPubkey: id.participant_key.public_key_hex,
  fileName: "bootstrap-atlas.vx",
  sourceBytes: "Wallet Main;",
  modules: { "policies.vdx": "Space ATLAS;" },
  networkId: "vector-devnet-1",
  requestId: "req_0001",
  nonce: 7,
  executionParams: { dry: false },
}));
const submitSig = signEd25519(SEED_HEX, submitCanon);

const popCanon = canonicalJsonBytes(canonicalWalletPopObject({
  networkId: "vector-devnet-1",
  walletId: "wal_demo",
  participantIdentity: id.participant_id,
  authorizedPubkey: id.node_key.public_key_hex,
  purpose: "wallet_key_authorization",
  nonce: "pop_1",
  expiresAtMs: null,
}));
const popSig = signEd25519(NODE_SEED_HEX, popCanon);

const xferCanon = canonicalJsonBytes(canonicalTransferApprovalObject({
  networkId: "vector-devnet-1",
  tokenId: "tok_atlas",
  fromWalletId: "wal_a",
  toWalletId: "wal_b",
  amount: 250,
}));
const xferSig = signEd25519(SEED_HEX, xferCanon);

console.log(JSON.stringify({
  lang: "javascript",
  empty_b3: blake3Hex(""),
  hello_b3: blake3Hex("hello world"),
  multi_b3: blake3Hex(multiChunk),
  canon_str: Buffer.from(canon).toString("utf8"),
  participant_pubkey: id.participant_key.public_key_hex,
  participant_id: id.participant_id,
  node_id: id.node_id,
  sig,
  submit_str: Buffer.from(submitCanon).toString("utf8"),
  submit_sig: submitSig,
  pop_str: Buffer.from(popCanon).toString("utf8"),
  pop_sig: popSig,
  xfer_str: Buffer.from(xferCanon).toString("utf8"),
  xfer_sig: xferSig,
}));
