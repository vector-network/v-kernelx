use crate::dag::validate_dag;
use crate::hash::canonical_replay_hash;
use crate::serialization::{canonical_state_map_bytes, CanonicalSerialize};
use crate::{OperationType, StateRoot, VectorEvent, VectorState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

fn sort_key(event: &VectorEvent) -> (u64, u64, String, String, String) {
    (
        event.logical_clock,
        event.timestamp,
        event.entity_id.clone(),
        event.event_id.clone(),
        event.event_hash.clone(),
    )
}

fn apply_event(
    state: &mut BTreeMap<String, VectorState>,
    event: &VectorEvent,
) -> Result<(), String> {
    let current = state.get(&event.entity_id);

    match &event.operation {
        OperationType::OriginCreate => {
            if current.is_some() {
                return Err(format!(
                    "origin create attempted for existing entity_id: {}",
                    event.entity_id
                ));
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

fn order_entity_events(events: &[&VectorEvent]) -> Result<Vec<VectorEvent>, String> {
    if events.is_empty() {
        return Ok(Vec::new());
    }

    let mut by_hash: HashMap<String, &VectorEvent> = HashMap::new();
    for event in events {
        if by_hash
            .insert(event.event_hash.clone(), *event)
            .is_some()
        {
            return Err(format!("duplicate event_hash detected: {}", event.event_hash));
        }
    }

    let mut indegree: BTreeMap<String, usize> = BTreeMap::new();
    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for event in events {
        indegree.entry(event.event_hash.clone()).or_insert(0);
        children.entry(event.event_hash.clone()).or_default();
    }

    for event in events {
        let mut seen_parents = BTreeSet::new();

        for parent_hash in &event.parent_hashes {
            if !seen_parents.insert(parent_hash.clone()) {
                return Err(format!(
                    "duplicate parent hash in event: {}",
                    event.event_hash
                ));
            }

            if by_hash.contains_key(parent_hash) {
                *indegree.entry(event.event_hash.clone()).or_insert(0) += 1;
                children
                    .entry(parent_hash.clone())
                    .or_default()
                    .push(event.event_hash.clone());
            }
        }
    }

    let root_count = indegree.values().filter(|&&deg| deg == 0).count();
    if root_count != 1 {
        return Err(format!(
            "entity history must have exactly one root event, found {} roots",
            root_count
        ));
    }

    let mut ready: Vec<String> = indegree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(hash, _)| hash.clone())
        .collect();

    ready.sort_by(|a, b| sort_key(by_hash.get(a).unwrap()).cmp(&sort_key(by_hash.get(b).unwrap())));

    let mut ordered = Vec::with_capacity(events.len());

    while !ready.is_empty() {
        let node = ready.remove(0);

        let ev = by_hash
            .get(&node)
            .ok_or_else(|| format!("missing node in entity replay map: {node}"))?;

        ordered.push((*ev).clone());

        let mut next_children = children.get(&node).cloned().unwrap_or_default();
        next_children.sort_by(|a, b| {
            sort_key(by_hash.get(a).unwrap()).cmp(&sort_key(by_hash.get(b).unwrap()))
        });

        for child in next_children {
            if let Some(entry) = indegree.get_mut(&child) {
                *entry -= 1;
                if *entry == 0 {
                    ready.push(child);
                }
            }
        }

        ready.sort_by(|a, b| sort_key(by_hash.get(a).unwrap()).cmp(&sort_key(by_hash.get(b).unwrap())));
    }

    if ordered.len() != events.len() {
        return Err("entity replay ordering failed due to unresolved ancestry or cycle".to_string());
    }

    Ok(ordered)
}

pub fn replay_events(events: &[VectorEvent]) -> Result<ReplayResult, String> {
    validate_dag(events)?;

    let mut by_entity: BTreeMap<String, Vec<&VectorEvent>> = BTreeMap::new();
    for event in events {
        by_entity.entry(event.entity_id.clone()).or_default().push(event);
    }

    let mut state = BTreeMap::<String, VectorState>::new();
    let mut applied_event_hashes = Vec::<String>::with_capacity(events.len());
    let mut logical_clock = 0_u64;

    for (_entity_id, entity_events) in by_entity {
        let ordered = order_entity_events(&entity_events)?;

        for event in ordered {
            apply_event(&mut state, &event)?;
            applied_event_hashes.push(event.event_hash.clone());
            logical_clock = logical_clock.max(event.logical_clock);
        }
    }

    let replay_hash = canonical_replay_hash(&applied_event_hashes);
    let state_root = compute_state_root(&state, applied_event_hashes.len() as u64, logical_clock);

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

pub fn verify_replay(
    events: &[VectorEvent],
    expected_state_root: &StateRoot,
    expected_replay_hash: &str,
) -> Result<bool, String> {
    let result = replay_events(events)?;
    Ok(result.state_root == *expected_state_root && result.replay_hash == expected_replay_hash)
}

/// Convenience helper for deterministic state serialization if you need it in tests.
pub fn canonical_final_state_bytes(result: &ReplayResult) -> Vec<u8> {
    result.final_state.canonical_bytes()
}