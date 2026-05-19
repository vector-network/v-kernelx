use v_kernelx::{
    canonical_event_hash, canonical_payload_hash, find_valid_nonce, validate_dag, verify_origin,
    KernelEngine, MemoryStore, OperationType, SettlementOutcome, SimulationHarness, VectorEvent,
    VectorState,
};

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
    assert!(verify_origin(seed, nonce, 1));
}

#[test]
fn replay_is_deterministic_for_same_history() {
    let mut engine = KernelEngine::<MemoryStore>::new();

    let seed_a = "seed-a";
    let nonce_a = find_valid_nonce(seed_a, 1, 1_000_000).expect("nonce for a");
    let seed_b = "seed-b";
    let nonce_b = find_valid_nonce(seed_b, 1, 1_000_000).expect("nonce for b");

    let _a = engine
        .origin_create(
            "v-a",
            "pk-a",
            "space-main",
            vec![100, 50],
            seed_a,
            nonce_a,
            1,
        )
        .expect("origin a");

    let _b = engine
        .origin_create(
            "v-b",
            "pk-b",
            "space-main",
            vec![25, 25],
            seed_b,
            nonce_b,
            1,
        )
        .expect("origin b");

    let _ = engine
        .transfer("v-a", "v-b", vec![10, 5])
        .expect("transfer should succeed");

    let _ = engine.drain("v-a", 100).expect("drain should succeed");

    let _ = engine
        .project("v-b", vec![5, 5], "escrow-1")
        .expect("project should succeed");

    let _ = engine
        .reconstruct(
            "v-b",
            SettlementOutcome {
                outcome_tag: "settled".to_string(),
                gains: vec![1, 2],
                losses: vec![0, 1],
            },
        )
        .expect("reconstruct should succeed");

    let replay_1 = engine
        .replay_canonical_history()
        .expect("first replay should succeed");
    let replay_2 = engine
        .replay_canonical_history()
        .expect("second replay should succeed");

    assert_eq!(replay_1, replay_2);
    assert_eq!(replay_1.state_root, replay_2.state_root);
    assert_eq!(replay_1.replay_hash, replay_2.replay_hash);
    assert_eq!(replay_1.final_state, replay_2.final_state);
}

#[test]
fn dag_validation_rejects_missing_parent() {
    let mut state_before = VectorState::zero(2, "pk-a", "STANDARD");
    state_before.components = vec![10, 20];

    let mut state_after = state_before.clone();
    state_after.components = vec![5, 15];

    let mut event = VectorEvent::new(
        "event-1",
        vec!["missing-parent-hash".to_string()],
        "space-main",
        "v-a",
        OperationType::Transfer,
        state_before,
        state_after,
        1.0,
        true,
        "pk-a",
        1,
        1,
    );

    event.payload_hash = canonical_payload_hash(&event);
    event.event_hash = canonical_event_hash(&event);

    let result = validate_dag(&[event]);
    assert!(result.is_err());
}