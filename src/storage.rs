use crate::error::KernelXError;
use crate::record::VectorRecordV1;
use crate::snapshot::Snapshot;
use crate::state::VectorStateV1;
use crate::VectorEvent;
use std::collections::BTreeMap;

pub trait StateStore {
    fn put_state(&mut self, state: VectorStateV1) -> Result<(), KernelXError>;
    fn get_state(&self, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError>;
    fn list_states(&self) -> Result<Vec<VectorStateV1>, KernelXError>;
    fn put_record(&mut self, record: VectorRecordV1) -> Result<(), KernelXError>;
    fn get_record(&self, record_id: &str) -> Result<Option<VectorRecordV1>, KernelXError>;
    fn list_records(&self) -> Result<Vec<VectorRecordV1>, KernelXError>;
}

pub trait EventStore {
    fn append_event(&mut self, event: VectorEvent) -> Result<(), KernelXError>;
    fn get_event(&self, event_id: &str) -> Result<Option<VectorEvent>, KernelXError>;
    fn get_event_by_hash(&self, event_hash: &str) -> Result<Option<VectorEvent>, KernelXError>;
    fn list_events(&self) -> Result<Vec<VectorEvent>, KernelXError>;
}

pub trait SnapshotStore {
    fn put_snapshot(&mut self, snapshot: Snapshot) -> Result<(), KernelXError>;
    fn get_snapshot(&self, snapshot_id: &str) -> Result<Option<Snapshot>, KernelXError>;
    fn list_snapshots(&self) -> Result<Vec<Snapshot>, KernelXError>;
}

pub trait ReplayStore {
    fn load_events_for_replay(&self) -> Result<Vec<VectorEvent>, KernelXError>;
    fn load_latest_snapshot(&self) -> Result<Option<Snapshot>, KernelXError>;
}

pub trait KernelStore: StateStore + EventStore + SnapshotStore + ReplayStore {}
impl<T> KernelStore for T where T: StateStore + EventStore + SnapshotStore + ReplayStore {}

#[derive(Clone, Default)]
pub struct MemoryStore {
    states: BTreeMap<String, VectorStateV1>,
    records: BTreeMap<String, VectorRecordV1>,
    /// Canonical immutable event store keyed by event_hash.
    /// This prevents accidental overwrite of a different event with the same event_id.
    events: BTreeMap<String, VectorEvent>,
    snapshots: BTreeMap<String, Snapshot>,
}

impl StateStore for MemoryStore {
    fn put_state(&mut self, state: VectorStateV1) -> Result<(), KernelXError> {
        self.states.insert(state.vector_id.clone(), state);
        Ok(())
    }

    fn get_state(&self, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError> {
        Ok(self.states.get(vector_id).cloned())
    }

    fn list_states(&self) -> Result<Vec<VectorStateV1>, KernelXError> {
        Ok(self.states.values().cloned().collect())
    }

    fn put_record(&mut self, record: VectorRecordV1) -> Result<(), KernelXError> {
        self.records.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn get_record(&self, record_id: &str) -> Result<Option<VectorRecordV1>, KernelXError> {
        Ok(self.records.get(record_id).cloned())
    }

    fn list_records(&self) -> Result<Vec<VectorRecordV1>, KernelXError> {
        Ok(self.records.values().cloned().collect())
    }
}

impl EventStore for MemoryStore {
    fn append_event(&mut self, event: VectorEvent) -> Result<(), KernelXError> {
        if event.event_id.is_empty() {
            return Err(KernelXError::InvalidState(
                "attempted to append event with empty event_id".to_string(),
            ));
        }

        if event.event_hash.is_empty() {
            return Err(KernelXError::InvalidState(
                "attempted to append event with empty event_hash".to_string(),
            ));
        }

        // Same hash means the exact same canonical event already exists.
        // Keep the original and reject the duplicate append attempt.
        if self.events.contains_key(&event.event_hash) {
            return Err(KernelXError::InvalidState(format!(
                "duplicate canonical event_hash detected: {}",
                event.event_hash
            )));
        }

        // Same event_id with a different hash is a security violation:
        // someone is trying to inject a conflicting event identity.
        if self.events.values().any(|existing| existing.event_id == event.event_id) {
            return Err(KernelXError::InvalidState(format!(
                "duplicate event_id detected: {}",
                event.event_id
            )));
        }

        self.events.insert(event.event_hash.clone(), event);
        Ok(())
    }

    fn get_event(&self, event_id: &str) -> Result<Option<VectorEvent>, KernelXError> {
        Ok(self
            .events
            .values()
            .find(|event| event.event_id == event_id)
            .cloned())
    }

    fn get_event_by_hash(&self, event_hash: &str) -> Result<Option<VectorEvent>, KernelXError> {
        Ok(self.events.get(event_hash).cloned())
    }

    fn list_events(&self) -> Result<Vec<VectorEvent>, KernelXError> {
        Ok(self.events.values().cloned().collect())
    }
}

impl SnapshotStore for MemoryStore {
    fn put_snapshot(&mut self, snapshot: Snapshot) -> Result<(), KernelXError> {
        self.snapshots.insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

    fn get_snapshot(&self, snapshot_id: &str) -> Result<Option<Snapshot>, KernelXError> {
        Ok(self.snapshots.get(snapshot_id).cloned())
    }

    fn list_snapshots(&self) -> Result<Vec<Snapshot>, KernelXError> {
        Ok(self.snapshots.values().cloned().collect())
    }
}

fn canonical_event_sort_key(event: &VectorEvent) -> (u64, u64, String, String) {
    (
        event.logical_clock,
        event.timestamp,
        event.event_hash.clone(),
        event.event_id.clone(),
    )
}

impl ReplayStore for MemoryStore {
    fn load_events_for_replay(&self) -> Result<Vec<VectorEvent>, KernelXError> {
        let mut events: Vec<VectorEvent> = self.events.values().cloned().collect();
        events.sort_by(|a, b| canonical_event_sort_key(a).cmp(&canonical_event_sort_key(b)));
        Ok(events)
    }

    fn load_latest_snapshot(&self) -> Result<Option<Snapshot>, KernelXError> {
        Ok(self
            .snapshots
            .values()
            .cloned()
            .max_by(|a, b| a.snapshot_id.cmp(&b.snapshot_id)))
    }
}