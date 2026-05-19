// src/hash.rs
use crate::serialization::{
    canonical_blob_bytes, canonical_event_bytes, canonical_event_payload_bytes, CanonicalSerialize,
};
use crate::{StateRoot, VectorEvent};

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Hash of the canonical event payload.
pub fn canonical_payload_hash(event: &VectorEvent) -> String {
    blake3_hex(&canonical_event_payload_bytes(event))
}

/// Hash of the full canonical event record, excluding signature.
pub fn canonical_event_hash(event: &VectorEvent) -> String {
    blake3_hex(&canonical_event_bytes(event))
}

/// Hash of the canonical state root struct.
pub fn canonical_state_root_hash(state_root: &StateRoot) -> String {
    blake3_hex(&state_root.canonical_bytes())
}

/// Hash of a deterministic replay material blob.
pub fn canonical_replay_hash(event_hashes: &[String]) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(&canonical_blob_bytes("replay-v1", &[]));
    buf.extend_from_slice(&crate::serialization::canonical_event_sequence_bytes(event_hashes));
    blake3_hex(&buf)
}

/// Generic deterministic hash helper for any tagged canonical blob.
pub fn canonical_tagged_hash(tag: &str, payload: &[u8]) -> String {
    blake3_hex(&canonical_blob_bytes(tag, payload))
}