use crate::{OperationType, StateRoot, VectorEvent, VectorState};
use std::collections::BTreeMap;

/// Deterministic binary serialization helpers.
///
/// This is intentionally explicit and field-ordered. Do not replace with map-based
/// generic serialization for canonical protocol paths.
pub trait CanonicalSerialize {
    fn canonical_bytes(&self) -> Vec<u8>;
}

fn write_u8(buf: &mut Vec<u8>, value: u8) {
    buf.push(value);
}

fn write_bool(buf: &mut Vec<u8>, value: bool) {
    write_u8(buf, if value { 1 } else { 0 });
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(buf: &mut Vec<u8>, value: u64) {
    let hi = (value >> 32) as u32;
    let lo = (value & 0xFFFF_FFFF) as u32;
    write_u32(buf, hi);
    write_u32(buf, lo);
}

fn write_f64(buf: &mut Vec<u8>, value: f64) {
    buf.extend_from_slice(&value.to_bits().to_be_bytes());
}

fn write_str(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    write_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn write_vec_str(buf: &mut Vec<u8>, values: &[String]) {
    write_u64(buf, values.len() as u64);
    for v in values {
        write_str(buf, v);
    }
}

fn write_btreemap_str_str(buf: &mut Vec<u8>, map: &BTreeMap<String, String>) {
    write_u64(buf, map.len() as u64);
    for (k, v) in map {
        write_str(buf, k);
        write_str(buf, v);
    }
}

fn write_vec_u64(buf: &mut Vec<u8>, values: &[u64]) {
    write_u64(buf, values.len() as u64);
    for v in values {
        write_u64(buf, *v);
    }
}

impl CanonicalSerialize for OperationType {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            OperationType::OriginCreate => write_str(&mut buf, "ORIGIN_CREATE"),
            OperationType::Certify => write_str(&mut buf, "CERTIFY"),
            OperationType::Transfer => write_str(&mut buf, "TRANSFER"),
            OperationType::Drain => write_str(&mut buf, "DRAIN"),
            OperationType::Project => write_str(&mut buf, "PROJECT"),
            OperationType::Reconstruct => write_str(&mut buf, "RECONSTRUCT"),
            OperationType::Move => write_str(&mut buf, "MOVE"),
            OperationType::Rotate => write_str(&mut buf, "ROTATE"),
            OperationType::Scale => write_str(&mut buf, "SCALE"),
            OperationType::Normalize => write_str(&mut buf, "NORMALIZE"),
            OperationType::Constrain => write_str(&mut buf, "CONSTRAIN"),
            OperationType::Query => write_str(&mut buf, "QUERY"),
            OperationType::Record => write_str(&mut buf, "RECORD"),
            OperationType::Other(name) => {
                write_str(&mut buf, "OTHER");
                write_str(&mut buf, name);
            }
        }
        buf
    }
}

impl CanonicalSerialize for VectorState {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_vec_u64(&mut buf, &self.components);
        write_str(&mut buf, &self.owner_public_key);
        write_str(&mut buf, &self.type_tag);
        write_btreemap_str_str(&mut buf, &self.metadata);
        buf
    }
}

impl CanonicalSerialize for StateRoot {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_str(&mut buf, &self.root_hash);
        write_u64(&mut buf, self.event_count);
        write_u64(&mut buf, self.logical_clock);
        buf
    }
}

impl<V: CanonicalSerialize> CanonicalSerialize for BTreeMap<String, V> {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_u64(&mut buf, self.len() as u64);
        for (key, value) in self {
            write_str(&mut buf, key);
            buf.extend_from_slice(&value.canonical_bytes());
        }
        buf
    }
}

/// Canonical payload bytes used for payload hashing and signing.
///
/// Excludes payload_hash, event_hash, and signature to prevent circularity.
pub fn canonical_event_payload_bytes(event: &VectorEvent) -> Vec<u8> {
    let mut buf = Vec::new();
    write_str(&mut buf, &event.event_id);
    write_vec_str(&mut buf, &event.parent_hashes);
    write_str(&mut buf, &event.region_id);
    write_str(&mut buf, &event.entity_id);
    buf.extend_from_slice(&event.operation.canonical_bytes());
    buf.extend_from_slice(&event.vector_before.canonical_bytes());
    buf.extend_from_slice(&event.vector_after.canonical_bytes());
    write_f64(&mut buf, event.auth_ratio);
    write_bool(&mut buf, event.certified);
    write_str(&mut buf, &event.actor_public_key);
    write_u64(&mut buf, event.logical_clock);
    write_u64(&mut buf, event.timestamp);
    buf
}

/// Canonical full event bytes used for event hashing.
///
/// Excludes signature and event_hash. Includes payload_hash so that the event hash
/// binds to the payload hash.
pub fn canonical_event_bytes(event: &VectorEvent) -> Vec<u8> {
    let mut buf = canonical_event_payload_bytes(event);
    write_str(&mut buf, &event.payload_hash);
    buf
}

/// Canonical ordered state map bytes used for replay and state roots.
pub fn canonical_state_map_bytes(state: &BTreeMap<String, VectorState>) -> Vec<u8> {
    let mut buf = Vec::new();
    write_u64(&mut buf, state.len() as u64);
    for (entity_id, vector) in state {
        write_str(&mut buf, entity_id);
        buf.extend_from_slice(&vector.canonical_bytes());
    }
    buf
}

/// Canonical event sequence bytes used for replay hashes.
pub fn canonical_event_sequence_bytes(event_hashes: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_u64(&mut buf, event_hashes.len() as u64);
    for h in event_hashes {
        write_str(&mut buf, h);
    }
    buf
}

/// Deterministic helper for protocol-wide hashable blobs.
pub fn canonical_blob_bytes(tag: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_str(&mut buf, tag);
    write_bytes(&mut buf, payload);
    buf
}