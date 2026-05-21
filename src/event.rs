use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::state::StateRoot;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum OperationType {
    OriginCreate,
    Certify,
    Transfer,
    Drain,
    Project,
    Reconstruct,
    Move,
    Rotate,
    Scale,
    Normalize,
    Constrain,
    Query,
    Record,
    Other(String),
}

impl OperationType {
    pub fn canonical_name(&self) -> &str {
        match self {
            OperationType::OriginCreate => "ORIGIN_CREATE",
            OperationType::Certify => "CERTIFY",
            OperationType::Transfer => "TRANSFER",
            OperationType::Drain => "DRAIN",
            OperationType::Project => "PROJECT",
            OperationType::Reconstruct => "RECONSTRUCT",
            OperationType::Move => "MOVE",
            OperationType::Rotate => "ROTATE",
            OperationType::Scale => "SCALE",
            OperationType::Normalize => "NORMALIZE",
            OperationType::Constrain => "CONSTRAIN",
            OperationType::Query => "QUERY",
            OperationType::Record => "RECORD",
            OperationType::Other(_) => "OTHER",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorState {
    pub components: Vec<u64>,
    pub owner_public_key: String,
    pub type_tag: String,
    pub metadata: BTreeMap<String, String>,
}

impl VectorState {
    pub fn new(
        components: Vec<u64>,
        owner_public_key: impl Into<String>,
        type_tag: impl Into<String>,
        metadata: BTreeMap<String, String>,
    ) -> Self {
        Self {
            components,
            owner_public_key: owner_public_key.into(),
            type_tag: type_tag.into(),
            metadata,
        }
    }

    pub fn zero(
        dimensions: usize,
        owner_public_key: impl Into<String>,
        type_tag: impl Into<String>,
    ) -> Self {
        Self {
            components: vec![0_u64; dimensions],
            owner_public_key: owner_public_key.into(),
            type_tag: type_tag.into(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn magnitude(&self) -> u128 {
        self.components
            .iter()
            .fold(0_u128, |acc, &x| acc + x as u128)
    }

    pub fn is_zero(&self) -> bool {
        self.components.iter().all(|&x| x == 0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VectorEvent {
    pub event_id: String,
    pub parent_hashes: Vec<String>,
    pub region_id: String,
    pub entity_id: String,
    pub operation: OperationType,
    pub vector_before: VectorState,
    pub vector_after: VectorState,
    pub auth_ratio: f64,
    pub certified: bool,
    pub actor_public_key: String,
    pub logical_clock: u64,
    pub timestamp: u64,
    pub payload_hash: String,
    pub event_hash: String,
    pub signature: String,
}

impl VectorEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: impl Into<String>,
        parent_hashes: Vec<String>,
        region_id: impl Into<String>,
        entity_id: impl Into<String>,
        operation: OperationType,
        vector_before: VectorState,
        vector_after: VectorState,
        auth_ratio: f64,
        certified: bool,
        actor_public_key: impl Into<String>,
        logical_clock: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            parent_hashes,
            region_id: region_id.into(),
            entity_id: entity_id.into(),
            operation,
            vector_before,
            vector_after,
            auth_ratio,
            certified,
            actor_public_key: actor_public_key.into(),
            logical_clock,
            timestamp,
            payload_hash: String::new(),
            event_hash: String::new(),
            signature: String::new(),
        }
    }

    pub fn canonical_event_id(
        entity_id: &str,
        region_id: &str,
        operation: &OperationType,
        logical_clock: u64,
        sequence: u64,
    ) -> String {
        format!(
            "{}::{}::{}::{}::{}",
            entity_id,
            region_id,
            operation.canonical_name(),
            logical_clock,
            sequence
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub event: VectorEvent,
    pub state_root: StateRoot,
    pub replay_hash: String,
}
