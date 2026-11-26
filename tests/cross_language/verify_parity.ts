import { blake3Hex, canonicalJsonBytes, ClientIdentity, signEd25519 } from "../../sdks/typescript/src/index.ts";

const SEED_HEX = "1111111111111111111111111111111111111111111111111111111111111111";
const NODE_SEED_HEX = "2222222222222222222222222222222222222222222222222222222222222222";
const id = ClientIdentity.fromKeys("parity", SEED_HEX, NODE_SEED_HEX);
const multiChunk = "vector-network-".repeat(200);
const canon = canonicalJsonBytes({ b: 2, a: { z: true, m: [3, 1, 2] } });
const sig = signEd25519(SEED_HEX, canon);

console.log(JSON.stringify({
  lang: "typescript",
  empty_b3: blake3Hex(""),
  hello_b3: blake3Hex("hello world"),
  multi_b3: blake3Hex(multiChunk),
  canon_str: Buffer.from(canon).toString("utf8"),
  participant_pubkey: id.participant_key.public_key_hex,
  participant_id: id.participant_id,
  node_id: id.node_id,
  sig,
}));
