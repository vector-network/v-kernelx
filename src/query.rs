// src/query.rs
use crate::error::KernelXError;
use crate::record::VectorRecordV1;
use crate::snapshot::Snapshot;
use crate::state::VectorStateV1;
use crate::storage::{EventStore, ReplayStore, SnapshotStore, StateStore};
use crate::VectorEvent;

pub fn get_vector<S: StateStore>(store: &S, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError> {
    store.get_state(vector_id)
}

pub fn list_vectors<S: StateStore>(store: &S) -> Result<Vec<VectorStateV1>, KernelXError> {
    store.list_states()
}

pub fn get_record<S: StateStore>(store: &S, record_id: &str) -> Result<Option<VectorRecordV1>, KernelXError> {
    store.get_record(record_id)
}

pub fn list_records<S: StateStore>(store: &S) -> Result<Vec<VectorRecordV1>, KernelXError> {
    store.list_records()
}

pub fn get_event<S: EventStore>(store: &S, event_id: &str) -> Result<Option<VectorEvent>, KernelXError> {
    store.get_event(event_id)
}

pub fn get_event_by_hash<S: EventStore>(store: &S, event_hash: &str) -> Result<Option<VectorEvent>, KernelXError> {
    store.get_event_by_hash(event_hash)
}

pub fn list_events<S: EventStore>(store: &S) -> Result<Vec<VectorEvent>, KernelXError> {
    store.list_events()
}

pub fn get_snapshot<S: SnapshotStore>(store: &S, snapshot_id: &str) -> Result<Option<Snapshot>, KernelXError> {
    store.get_snapshot(snapshot_id)
}

pub fn list_snapshots<S: SnapshotStore>(store: &S) -> Result<Vec<Snapshot>, KernelXError> {
    store.list_snapshots()
}

pub fn load_events_for_replay<S: ReplayStore>(store: &S) -> Result<Vec<VectorEvent>, KernelXError> {
    store.load_events_for_replay()
}

pub fn load_latest_snapshot<S: ReplayStore>(store: &S) -> Result<Option<Snapshot>, KernelXError> {
    store.load_latest_snapshot()
}