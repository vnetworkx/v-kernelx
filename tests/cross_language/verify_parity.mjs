import { blake3Hex, canonicalJsonBytes, ClientIdentity, signEd25519, verifyEd25519 } from "../../sdks/javascript/index.js";

const SEED_HEX = "1111111111111111111111111111111111111111111111111111111111111111";
const NODE_SEED_HEX = "2222222222222222222222222222222222222222222222222222222222222222";
const id = ClientIdentity.fromKeys("parity", SEED_HEX, NODE_SEED_HEX);
const multiChunk = "vector-network-".repeat(200); // > 1024 bytes (3000 bytes)
const canon = canonicalJsonBytes({ b: 2, a: { z: true, m: [3, 1, 2] } });
const sig = signEd25519(SEED_HEX, canon);
if (!verifyEd25519(id.participant_key.public_key_hex, canon, sig)) {
  throw new Error("JS Ed25519 self-verify failed");
}
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
}));
