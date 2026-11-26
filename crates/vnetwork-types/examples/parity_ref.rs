use vnetwork_types::*;

fn main() {
    let seed = "1111111111111111111111111111111111111111111111111111111111111111";
    let node_seed = "2222222222222222222222222222222222222222222222222222222222222222";
    let pk = KeypairMaterial::from_private_hex("participant", seed).unwrap();
    let nk = KeypairMaterial::from_private_hex("node", node_seed).unwrap();
    let multi_chunk = "vector-network-".repeat(200);
    let canon = canonical_json_bytes(&serde_json::json!({
        "b": 2,
        "a": { "z": true, "m": [3, 1, 2] }
    })).unwrap();
    let sig = pk.sign(&canon).unwrap();
    let out = serde_json::json!({
        "lang": "rust",
        "empty_b3": blake3_hex(b""),
        "hello_b3": blake3_hex(b"hello world"),
        "multi_b3": blake3_hex(multi_chunk.as_bytes()),
        "canon_str": String::from_utf8(canon).unwrap(),
        "participant_pubkey": pk.public_key_hex,
        "participant_id": derive_participant_id(&pk.public_key_hex),
        "node_id": derive_node_id(&nk.public_key_hex),
        "sig": sig,
    });
    println!("{out}");
}
