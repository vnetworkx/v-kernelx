use v_kernelx::{find_valid_nonce, SimulationHarness};

#[test]
fn smoke_flow_runs_end_to_end() {
    let mut harness = SimulationHarness::new();
    let report = harness.basic_flow().expect("simulation should complete");

    assert_eq!(report.vectors.len(), 2);
    assert!(report.records >= 6);

    let v_a = report
        .vectors
        .iter()
        .find(|v| v.vector_id == "v-a")
        .expect("v-a exists");
    let v_b = report
        .vectors
        .iter()
        .find(|v| v.vector_id == "v-b")
        .expect("v-b exists");

    assert_eq!(v_a.components.len(), 2);
    assert_eq!(v_b.components.len(), 2);
    assert!(v_a.certification.certified);
    assert!(v_b.certification.certified);
}

#[test]
fn origin_nonce_search_finds_valid_nonce() {
    let seed = "seed-for-test";
    let nonce = find_valid_nonce(seed, 1, 1_000_000).expect("nonce should exist");
    assert!(v_kernelx::verify_origin(seed, nonce, 1));
}
