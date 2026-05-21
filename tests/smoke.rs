use std::collections::BTreeMap;
use v_kernelx::{
    canonical_event_hash, canonical_payload_hash, find_valid_nonce, region_state_from_event,
    validate_dag, verify_origin, KernelEngine, MemoryStore, OperationType, SettlementOutcome,
    SimulationHarness, VectorEvent, VectorState,
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
fn query_results_are_clone_safe_and_do_not_mutate_engine_state() {
    let mut engine = KernelEngine::<MemoryStore>::new();

    let seed_a = "clone-safe-a";
    let nonce_a = find_valid_nonce(seed_a, 1, 1_000_000).expect("nonce a");
    let seed_b = "clone-safe-b";
    let nonce_b = find_valid_nonce(seed_b, 1, 1_000_000).expect("nonce b");

    let _ = engine
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

    let _ = engine
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

    let original_vector = engine
        .query_vector("v-a")
        .expect("query vector")
        .expect("vector exists");

    let mut mutated_vector = original_vector.clone();
    mutated_vector.components[0] = 999_999;
    mutated_vector.owner_pubkey = "tampered".to_string();

    let fresh_vector = engine
        .query_vector("v-a")
        .expect("query vector again")
        .expect("vector exists again");

    assert_eq!(fresh_vector.components[0], 100);
    assert_eq!(fresh_vector.owner_pubkey, "pk-a");
    assert_ne!(mutated_vector, fresh_vector);

    let original_events = engine.query_events().expect("query events");
    assert!(!original_events.is_empty());

    let mut tampered_events = original_events.clone();
    tampered_events[0].event_hash = "tampered-hash".to_string();
    tampered_events[0].payload_hash = "tampered-payload".to_string();

    let fresh_events = engine.query_events().expect("query events again");

    assert_eq!(original_events, fresh_events);
    assert_ne!(tampered_events, fresh_events);
}

#[test]
fn region_state_can_be_derived_from_region_event() {
    let mut metadata = BTreeMap::new();
    metadata.insert("region_kind".to_string(), "region".to_string());
    metadata.insert("region_name".to_string(), "SSP20".to_string());
    metadata.insert("normalized_name".to_string(), "ssp20".to_string());
    metadata.insert("region_prefix".to_string(), "SSP".to_string());
    metadata.insert(
        "suggested_title".to_string(),
        "Spatial Service Protocol".to_string(),
    );
    metadata.insert("visibility".to_string(), "public".to_string());
    metadata.insert("creator_public_key".to_string(), "pk-region".to_string());
    metadata.insert(
        "trigger_event_hash".to_string(),
        "trigger-hash-1".to_string(),
    );
    metadata.insert(
        "creation_proof_hash".to_string(),
        "proof-hash-1".to_string(),
    );
    metadata.insert("access_key_hash".to_string(), "".to_string());

    let before = VectorState::zero(0, "", "region");
    let after = VectorState::new(Vec::new(), "", "region", metadata);

    let mut event = VectorEvent::new(
        VectorEvent::canonical_event_id(
            "SSP::rgn_demo::1",
            "SSP::rgn_demo::1",
            &OperationType::Other("REGION_CREATE".to_string()),
            0,
            1,
        ),
        vec!["trigger-hash-1".to_string()],
        "SSP::rgn_demo::1",
        "SSP::rgn_demo::1",
        OperationType::Other("REGION_CREATE".to_string()),
        before,
        after,
        1.0,
        true,
        "pk-region",
        0,
        1_234,
    );

    event.payload_hash = canonical_payload_hash(&event);
    event.event_hash = canonical_event_hash(&event);

    let derived = region_state_from_event(&event).expect("region should derive");
    assert_eq!(derived.region_id, "SSP::rgn_demo::1");
    assert_eq!(derived.region_root, event.event_hash);
    assert_eq!(derived.region_name, "SSP20");
    assert_eq!(derived.normalized_name, "ssp20");
    assert_eq!(derived.visibility.as_str(), "public");
    assert_eq!(derived.creator_public_key, "pk-region");
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
