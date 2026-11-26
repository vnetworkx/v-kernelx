use vnetwork_types::*;

fn main() {
    let seed = "1111111111111111111111111111111111111111111111111111111111111111";
    let node_seed = "2222222222222222222222222222222222222222222222222222222222222222";
    let pk = KeypairMaterial::from_private_hex("participant", seed).unwrap();
    let nk = KeypairMaterial::from_private_hex("node", node_seed).unwrap();
    let multi_chunk = "vector-network-".repeat(200);
    let canon = canonical_json_bytes(&serde_json::json!({
        "b": 2,
        "nil": serde_json::Value::Null,
        "html": "<a>&",
        "a": { "z": true, "m": [3, 1, 2] }
    })).unwrap();
    let sig = pk.sign(&canon).unwrap();

    let submit_canon = canonical_json_bytes(&serde_json::json!({
        "actor_pubkey": pk.public_key_hex,
        "compiler_version": "vectorspace-compiler/1.2.0",
        "execution_params": { "dry": false },
        "file_kind": "vx",
        "file_name": "bootstrap-atlas.vx",
        "language_version": "v-langx/1.2.0",
        "module_hashes": { "policies.vdx": blake3_hex(b"Space ATLAS;") },
        "network_id": "vector-devnet-1",
        "nonce": 7,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": "req_0001",
        "source_hash": blake3_hex(b"Wallet Main;"),
    })).unwrap();
    let submit_sig = pk.sign(&submit_canon).unwrap();

    let pop_canon = canonical_json_bytes(&serde_json::json!({
        "authorized_pubkey": nk.public_key_hex,
        "expires_at_ms": serde_json::Value::Null,
        "network_id": "vector-devnet-1",
        "nonce": "pop_1",
        "participant_identity": derive_participant_id(&pk.public_key_hex),
        "protocol_version": PROTOCOL_VERSION,
        "purpose": "wallet_key_authorization",
        "wallet_id": "wal_demo",
    })).unwrap();
    let pop_sig = nk.sign(&pop_canon).unwrap();

    let xfer_canon = canonical_json_bytes(&serde_json::json!({
        "amount": "250",
        "domain": DOM_TRANSFER_APPROVAL_V1,
        "from_wallet_id": "wal_a",
        "network_id": "vector-devnet-1",
        "protocol_version": PROTOCOL_VERSION,
        "to_wallet_id": "wal_b",
        "token_id": "tok_atlas",
    })).unwrap();
    let xfer_sig = pk.sign(&xfer_canon).unwrap();

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
        "submit_str": String::from_utf8(submit_canon).unwrap(),
        "submit_sig": submit_sig,
        "pop_str": String::from_utf8(pop_canon).unwrap(),
        "pop_sig": pop_sig,
        "xfer_str": String::from_utf8(xfer_canon).unwrap(),
        "xfer_sig": xfer_sig,
    });
    println!("{out}");
}
