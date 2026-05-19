use crate::dag::{topological_order, validate_dag};
use crate::event::{OperationType, StateRoot, VectorEvent, VectorState};
use crate::hash::{canonical_replay_hash, canonical_state_root_hash};
use crate::serialization::{canonical_state_map_bytes, CanonicalSerialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayResult {
    pub final_state: BTreeMap<String, VectorState>,
    pub state_root: StateRoot,
    pub replay_hash: String,
    pub applied_event_hashes: Vec<String>,
}

pub struct ReplayEngine {
    pub events: Vec<VectorEvent>,
}

impl ReplayEngine {
    pub fn new(events: Vec<VectorEvent>) -> Self {
        Self { events }
    }

    pub fn replay(&self) -> Result<ReplayResult, String> {
        replay_events(&self.events)
    }
}

fn apply_event(
    state: &mut BTreeMap<String, VectorState>,
    event: &VectorEvent,
) -> Result<(), String> {
    let current = state.get(&event.entity_id);

    match &event.operation {
        OperationType::OriginCreate => {
            if current.is_some() {
                return Err(format!("origin create attempted for existing entity_id: {}", event.entity_id));
            }
        }
        _ => {
            let current_state = current.ok_or_else(|| {
                format!(
                    "non-origin event references missing entity state: {}",
                    event.entity_id
                )
            })?;

            if current_state != &event.vector_before {
                return Err(format!(
                    "vector_before mismatch for entity_id {}",
                    event.entity_id
                ));
            }
        }
    }

    state.insert(event.entity_id.clone(), event.vector_after.clone());
    Ok(())
}

pub fn replay_events(events: &[VectorEvent]) -> Result<ReplayResult, String> {
    validate_dag(events)?;
    let ordered = topological_order(events)?;

    let mut state = BTreeMap::<String, VectorState>::new();
    let mut applied_event_hashes = Vec::<String>::with_capacity(ordered.len());
    let mut logical_clock = 0_u64;

    for event in &ordered {
        apply_event(&mut state, event)?;
        applied_event_hashes.push(event.event_hash.clone());
        logical_clock = logical_clock.max(event.logical_clock);
    }

    let replay_hash = canonical_replay_hash(&applied_event_hashes);
    let state_root = compute_state_root(&state, ordered.len() as u64, logical_clock);

    Ok(ReplayResult {
        final_state: state,
        state_root,
        replay_hash,
        applied_event_hashes,
    })
}

pub fn compute_state_root(
    state: &BTreeMap<String, VectorState>,
    event_count: u64,
    logical_clock: u64,
) -> StateRoot {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"state-root-v1");
    bytes.extend_from_slice(&event_count.to_be_bytes());
    bytes.extend_from_slice(&logical_clock.to_be_bytes());
    bytes.extend_from_slice(&canonical_state_map_bytes(state));

    let root_hash = blake3::hash(&bytes).to_hex().to_string();

    StateRoot {
        root_hash,
        event_count,
        logical_clock,
    }
}

pub fn verify_replay(events: &[VectorEvent], expected_state_root: &StateRoot, expected_replay_hash: &str) -> Result<bool, String> {
    let result = replay_events(events)?;
    Ok(result.state_root == *expected_state_root && result.replay_hash == expected_replay_hash)
}

/// Convenience helper for deterministic state serialization if you need it in tests.
pub fn canonical_final_state_bytes(result: &ReplayResult) -> Vec<u8> {
    result.final_state.canonical_bytes()
}