use crate::error::KernelXError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const STATE_SCHEMA_V1: &str = "v.kernelx/VectorStateV1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VectorType {
    Standard,
    Origin,
    Projected,
    Escrow,
    Settlement,
    Locked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VectorStatus {
    Active,
    Projected,
    Escrowed,
    Settled,
    Archived,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificationState {
    pub certified: bool,
    pub auth_ratio: u16,
    pub threshold: u16,
    pub last_checked_at_ms: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectionState {
    pub escrow_id: String,
    pub projected_components: Vec<u128>,
    pub settled_components: Vec<u128>,
    pub started_at_ms: u64,
    pub settlement_at_ms: Option<u64>,
    pub outcome_tag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginState {
    pub seed: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub proof_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorStateV1 {
    pub schema: String,
    pub vector_id: String,
    pub owner_pubkey: String,
    pub space_id: String,
    pub vector_type: VectorType,
    pub status: VectorStatus,
    pub components: Vec<u128>,
    pub type_metadata: BTreeMap<String, String>,
    pub certification: CertificationState,
    pub projection: Option<ProjectionState>,
    pub origin: Option<OriginState>,
    pub version: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectionShare {
    pub component_index: usize,
    pub numerator: u128,
    pub denominator: u128,
}

/// Canonical state root for kernel-side state snapshots and replay verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateRoot {
    pub root_hash: String,
    pub event_count: u64,
    pub logical_clock: u64,
}

impl VectorStateV1 {
    pub fn new(
        vector_id: impl Into<String>,
        owner_pubkey: impl Into<String>,
        space_id: impl Into<String>,
        components: Vec<u128>,
        vector_type: VectorType,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            schema: STATE_SCHEMA_V1.to_string(),
            vector_id: vector_id.into(),
            owner_pubkey: owner_pubkey.into(),
            space_id: space_id.into(),
            vector_type,
            status: VectorStatus::Active,
            components,
            type_metadata: BTreeMap::new(),
            certification: CertificationState {
                certified: false,
                auth_ratio: 0,
                threshold: 700,
                last_checked_at_ms: timestamp_ms,
                reason: Some("not yet certified".to_string()),
            },
            projection: None,
            origin: None,
            version: 1,
            created_at_ms: timestamp_ms,
            updated_at_ms: timestamp_ms,
        }
    }

    pub fn magnitude(&self) -> u128 {
        self.components.iter().copied().sum()
    }

    pub fn is_zero(&self) -> bool {
        self.components.iter().all(|v| *v == 0)
    }

    pub fn direction_shares(&self) -> Result<Vec<DirectionShare>, KernelXError> {
        let magnitude = self.magnitude();
        if magnitude == 0 {
            return Err(KernelXError::ZeroNormalization);
        }
        Ok(self
            .components
            .iter()
            .enumerate()
            .map(|(i, component)| DirectionShare {
                component_index: i,
                numerator: *component,
                denominator: magnitude,
            })
            .collect())
    }

    pub fn ensure_same_shape(&self, other: &Self) -> Result<(), KernelXError> {
        if self.components.len() != other.components.len() {
            return Err(KernelXError::DimensionMismatch);
        }
        Ok(())
    }

    pub fn with_components(mut self, components: Vec<u128>, timestamp_ms: u64) -> Self {
        self.components = components;
        self.updated_at_ms = timestamp_ms;
        self.version += 1;
        self
    }

    pub fn with_status(mut self, status: VectorStatus, timestamp_ms: u64) -> Self {
        self.status = status;
        self.updated_at_ms = timestamp_ms;
        self.version += 1;
        self
    }
}

fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

fn write_bool(buf: &mut Vec<u8>, v: bool) {
    write_u8(buf, if v { 1 } else { 0 });
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_u128(buf: &mut Vec<u8>, v: u128) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_str(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    write_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn write_vec_u128(buf: &mut Vec<u8>, values: &[u128]) {
    write_u64(buf, values.len() as u64);
    for v in values {
        write_u128(buf, *v);
    }
}

fn write_btreemap_str_str(buf: &mut Vec<u8>, map: &BTreeMap<String, String>) {
    write_u64(buf, map.len() as u64);
    for (k, v) in map {
        write_str(buf, k);
        write_str(buf, v);
    }
}

fn write_vector_type(buf: &mut Vec<u8>, value: &VectorType) {
    let tag = match value {
        VectorType::Standard => "STANDARD",
        VectorType::Origin => "ORIGIN",
        VectorType::Projected => "PROJECTED",
        VectorType::Escrow => "ESCROW",
        VectorType::Settlement => "SETTLEMENT",
        VectorType::Locked => "LOCKED",
    };
    write_str(buf, tag);
}

fn write_vector_status(buf: &mut Vec<u8>, value: &VectorStatus) {
    let tag = match value {
        VectorStatus::Active => "ACTIVE",
        VectorStatus::Projected => "PROJECTED",
        VectorStatus::Escrowed => "ESCROWED",
        VectorStatus::Settled => "SETTLED",
        VectorStatus::Archived => "ARCHIVED",
    };
    write_str(buf, tag);
}

fn write_certification_state(buf: &mut Vec<u8>, value: &CertificationState) {
    write_bool(buf, value.certified);
    write_u64(buf, value.auth_ratio as u64);
    write_u64(buf, value.threshold as u64);
    write_u64(buf, value.last_checked_at_ms);
    match &value.reason {
        Some(reason) => {
            write_bool(buf, true);
            write_str(buf, reason);
        }
        None => write_bool(buf, false),
    }
}

fn write_projection_state(buf: &mut Vec<u8>, value: &ProjectionState) {
    write_str(buf, &value.escrow_id);
    write_vec_u128(buf, &value.projected_components);
    write_vec_u128(buf, &value.settled_components);
    write_u64(buf, value.started_at_ms);
    match value.settlement_at_ms {
        Some(ts) => {
            write_bool(buf, true);
            write_u64(buf, ts);
        }
        None => write_bool(buf, false),
    }
    match &value.outcome_tag {
        Some(tag) => {
            write_bool(buf, true);
            write_str(buf, tag);
        }
        None => write_bool(buf, false),
    }
}

fn write_origin_state(buf: &mut Vec<u8>, value: &OriginState) {
    write_str(buf, &value.seed);
    write_u64(buf, value.nonce);
    write_u64(buf, value.difficulty as u64);
    write_str(buf, &value.proof_hash);
}

fn canonical_vector_state_bytes(state: &VectorStateV1) -> Vec<u8> {
    let mut buf = Vec::new();

    write_str(&mut buf, &state.schema);
    write_str(&mut buf, &state.vector_id);
    write_str(&mut buf, &state.owner_pubkey);
    write_str(&mut buf, &state.space_id);
    write_vector_type(&mut buf, &state.vector_type);
    write_vector_status(&mut buf, &state.status);
    write_vec_u128(&mut buf, &state.components);
    write_btreemap_str_str(&mut buf, &state.type_metadata);
    write_certification_state(&mut buf, &state.certification);

    match &state.projection {
        Some(projection) => {
            write_bool(&mut buf, true);
            write_projection_state(&mut buf, projection);
        }
        None => write_bool(&mut buf, false),
    }

    match &state.origin {
        Some(origin) => {
            write_bool(&mut buf, true);
            write_origin_state(&mut buf, origin);
        }
        None => write_bool(&mut buf, false),
    }

    write_u64(&mut buf, state.version);
    write_u64(&mut buf, state.created_at_ms);
    write_u64(&mut buf, state.updated_at_ms);

    buf
}

/// Deterministically compute a state root from the current state set.
/// The state list is ordered by vector_id before hashing.
pub fn compute_state_root(states: &[VectorStateV1], logical_clock: u64) -> StateRoot {
    let mut ordered = states.to_vec();
    ordered.sort_by(|a, b| {
        a.vector_id
            .cmp(&b.vector_id)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.updated_at_ms.cmp(&b.updated_at_ms))
    });

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"v-kernelx/state-root-v1");
    write_u64(&mut bytes, ordered.len() as u64);
    write_u64(&mut bytes, logical_clock);

    for state in &ordered {
        let canonical = canonical_vector_state_bytes(state);
        write_u64(&mut bytes, canonical.len() as u64);
        bytes.extend_from_slice(&canonical);
    }

    let root_hash = blake3::hash(&bytes).to_hex().to_string();

    StateRoot {
        root_hash,
        event_count: ordered.len() as u64,
        logical_clock,
    }
}

pub fn validate_canonical_state(state: &VectorStateV1) -> Result<(), KernelXError> {
    if state.schema != STATE_SCHEMA_V1 {
        return Err(KernelXError::InvalidState("schema mismatch".to_string()));
    }
    if state.components.is_empty() {
        return Err(KernelXError::InvalidState(
            "a vector must contain at least one component".to_string(),
        ));
    }
    if state.owner_pubkey.is_empty() || state.vector_id.is_empty() || state.space_id.is_empty() {
        return Err(KernelXError::InvalidState(
            "vector_id, owner_pubkey, and space_id are required".to_string(),
        ));
    }
    Ok(())
}

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}