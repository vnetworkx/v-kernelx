use std::collections::BTreeMap;
use std::path::PathBuf;
use vnetwork_sdk::{ClientIdentity, VectorNetworkClient};
use vnetwork_types::{ParticipationLevel, ProgramLifecycleStatus};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint =
        std::env::var("VNETWORK_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let network_id =
        std::env::var("VNETWORK_NETWORK_ID").unwrap_or_else(|_| "vector-devnet-1".to_string());
    let vx_path = std::env::args().nth(1).map(PathBuf::from);

    let identity = ClientIdentity::generate("rust-sdk-participant");
    assert_ne!(
        identity.participant_key.public_key_hex, identity.node_key.public_key_hex,
        "participant and node keys must remain distinct"
    );

    let mut client = VectorNetworkClient::new(&endpoint, identity).with_expected_network(&network_id);
    let info = client.connect().await?;
    println!("Connected to network {} (profile={}, height={})", info.network_id, info.profile, info.height);

    let mut events_rx = client.subscribe_events().await?;
    let join_res = client
        .join(vec![
            ParticipationLevel::Network,
            ParticipationLevel::Space,
            ParticipationLevel::Region,
            ParticipationLevel::Wallet,
            ParticipationLevel::Token,
        ])
        .await?;
    println!("Joined participant: {}", join_res["participant"]["participant_id"]);

    let submission = if let Some(path) = vx_path {
        client.submit_vx_file(path).await?
    } else {
        let src = r#"
space create RustSdkSpace {
    name = "Rust SDK Space";
    visibility = "public";
}
region create RustSdkRegion in "RustSdkSpace" {
    prefix = "RST";
    visibility = "public";
    section = 1;
}
wallet create RustWalletA in "RustSdkRegion" {
    name = "Rust Wallet A";
}
wallet create RustWalletB in "RustSdkRegion" {
    name = "Rust Wallet B";
}
token create RSTOK in "RustWalletA" {
    name = "Rust Token";
    symbol = "RSTOK";
    dimensions = 3;
    vector = [25000, 1000, 0];
    max_supply = 25000;
    drain_bps = 100;
    purpose = "Rust SDK integration";
    external_monetary_value = "None";
}
transfer "RSTOK" from "RustWalletA" to "RustWalletB" amount 400;
verify proof network;
"#;
        client.submit_program("rust_workflow.vx", src, BTreeMap::new()).await?
    };

    assert_eq!(submission.status, ProgramLifecycleStatus::Committed);
    println!(
        "Committed .vx program {} (state_root={}, events={})",
        submission.program_id,
        submission.final_state_root.as_deref().unwrap_or(""),
        submission.resulting_event_ids.len()
    );

    if let Some(token_entity) = submission.created_entities.iter().find(|e| e.kind == "token") {
        let rep = client.verify_reconstruction("token", &token_entity.id).await?;
        assert_eq!(rep["verified"], serde_json::json!(true));
        println!("Reconstruction verified for {} => hash={}", token_entity.id, rep["reconstructed_hash"]);
    }

    if let Ok(Some(ws_evt)) = tokio::time::timeout(std::time::Duration::from_secs(2), events_rx.recv()).await {
        println!("Received WebSocket event: {}", ws_evt["event_type"]);
    }

    Ok(())
}
