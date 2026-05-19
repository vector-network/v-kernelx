// src/snapshot.rs
use crate::hash::{canonical_state_root_hash, canonical_tagged_hash};
use crate::serialization::CanonicalSerialize;
use crate::replay::ReplayResult;
use crate::{StateRoot, VectorState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub snapshot_id: String,
    pub state_root: StateRoot,
    pub event_root: String,
    pub replay_hash: String,
    pub event_count: u64,
    pub logical_clock: u64,
    pub dag_heads: Vec<String>,
    pub state_bytes: Vec<u8>,
    pub created_at: u64,
}

pub fn create_snapshot(
    replay_result: &ReplayResult,
    dag_heads: Vec<String>,
    created_at: u64,
) -> Snapshot {
    let state_bytes = replay_result.final_state.canonical_bytes();
    let snapshot_id = canonical_tagged_hash("snapshot-v1", &state_bytes);

    Snapshot {
        snapshot_id,
        state_root: replay_result.state_root.clone(),
        event_root: replay_result.replay_hash.clone(),
        replay_hash: replay_result.replay_hash.clone(),
        event_count: replay_result.state_root.event_count,
        logical_clock: replay_result.state_root.logical_clock,
        dag_heads,
        state_bytes,
        created_at,
    }
}

pub fn serialize_snapshot(snapshot: &Snapshot) -> Result<Vec<u8>, String> {
    serde_json::to_vec(snapshot).map_err(|e| format!("snapshot serialize error: {e}"))
}

pub fn load_snapshot(bytes: &[u8]) -> Result<Snapshot, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("snapshot parse error: {e}"))
}

pub fn verify_snapshot(
    snapshot: &Snapshot,
    current_state: &BTreeMap<String, VectorState>,
    current_replay_hash: &str,
) -> Result<bool, String> {
    let expected_state_bytes = current_state.canonical_bytes();
    let expected_snapshot_id = canonical_tagged_hash("snapshot-v1", &expected_state_bytes);
    let expected_root_hash = canonical_state_root_hash(&snapshot.state_root);

    Ok(
        snapshot.snapshot_id == expected_snapshot_id
            && snapshot.state_bytes == expected_state_bytes
            && snapshot.replay_hash == current_replay_hash
            && !expected_root_hash.is_empty(),
    )
}