use vnetwork_core::engine::ProtocolEngine;
use vnetwork_core::state::GenesisConfig;
use vnetwork_storage::StorageDatabase;
use vnetwork_types::*;

#[test]
fn test_wal_persistence_crash_recovery_and_profile_guard() {
    let dir = std::env::temp_dir().join(format!(
        "vnetwork_wal_test_{}_{}",
        std::process::id(),
        now_ms()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let val_kp = KeypairMaterial::generate("validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vnetwork-testnet-1",
        "Testnet",
        vec![ConsensusValidator {
            validator_id: "val_1".to_string(),
            node_id: "nod_val_1".to_string(),
            validator_pubkey_hex: val_kp.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
    );

    let (db, state, _) = StorageDatabase::open_and_recover(&dir, &genesis).unwrap();
    assert_eq!(state.height, 0);
    drop(db);

    // Attempting to reopen with mismatched profile must fail loudly!
    let wrong_genesis = GenesisConfig::for_profile(
        NetworkProfile::Production,
        "vnetwork-testnet-1",
        "Prod",
        vec![],
    );
    let mismatch = StorageDatabase::open_and_recover(&dir, &wrong_genesis);
    assert!(mismatch.is_err());

    // Reopening with matching genesis recovers cleanly
    let (_db2, state2, rep) = StorageDatabase::open_and_recover(&dir, &genesis).unwrap();
    assert_eq!(rep.final_height, 0);
    let _ = ProtocolEngine::from_restored(genesis, state2);
    let _ = std::fs::remove_dir_all(&dir);
}
