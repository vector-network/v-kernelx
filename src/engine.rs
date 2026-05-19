use crate::certification::certify_state;
use crate::consensus::{accept_record, ConsensusPolicy};
use crate::drain::apply_drain;
use crate::error::KernelXError;
use crate::event::{OperationType, VectorEvent, VectorState};
use crate::hash::{canonical_event_hash, canonical_payload_hash};
use crate::origin::create_origin_vector;
use crate::projection::project_vector;
use crate::query::{get_event_by_hash, get_vector, list_records, list_vectors};
use crate::record::{make_record_id, OperationKind, VectorRecordV1};
use crate::reconstruction::reconstruct_vector;
use crate::reconstruction::SettlementOutcome;
use crate::replay::{replay_events, ReplayResult};
use crate::state::{compute_state_root, now_ms, StateRoot, VectorStateV1};
use crate::storage::{EventStore, KernelStore, MemoryStore, ReplayStore, StateStore};
use crate::transfer::{transfer_components, transfer_record};
use crate::validation::{validate_event, validate_state};

#[derive(Clone)]
pub struct KernelEngine<S: KernelStore> {
    pub store: S,
    pub consensus: ConsensusPolicy,
}

impl KernelEngine<MemoryStore> {
    pub fn new() -> Self {
        Self {
            store: MemoryStore::default(),
            consensus: ConsensusPolicy::default(),
        }
    }
}

impl<S: KernelStore> KernelEngine<S> {
    pub fn with_store(store: S) -> Self {
        Self {
            store,
            consensus: ConsensusPolicy::default(),
        }
    }

    fn op_kind_to_event_kind(kind: &OperationKind) -> OperationType {
        match kind {
            OperationKind::OriginCreate => OperationType::OriginCreate,
            OperationKind::Certify => OperationType::Certify,
            OperationKind::Transfer => OperationType::Transfer,
            OperationKind::Drain => OperationType::Drain,
            OperationKind::Project => OperationType::Project,
            OperationKind::Reconstruct => OperationType::Reconstruct,
            OperationKind::Query => OperationType::Query,
            OperationKind::Custom(name) => OperationType::Other(name.clone()),
        }
    }

    fn assert_record_operation_kind(record: &VectorRecordV1, expected: OperationType) {
        debug_assert_eq!(
            Self::op_kind_to_event_kind(&record.operation).canonical_name(),
            expected.canonical_name()
        );
    }

    fn vector_v1_to_event_state(state: &VectorStateV1) -> Result<VectorState, KernelXError> {
        let mut components = Vec::with_capacity(state.components.len());
        for component in &state.components {
            let value = u64::try_from(*component).map_err(|_| {
                KernelXError::InvalidState(
                    "component value exceeds u64 canonical event limit".to_string(),
                )
            })?;
            components.push(value);
        }

        let mut metadata = std::collections::BTreeMap::new();
        for (k, v) in &state.type_metadata {
            metadata.insert(k.clone(), v.clone());
        }

        Ok(VectorState::new(
            components,
            state.owner_pubkey.clone(),
            format!("{:?}", state.vector_type),
            metadata,
        ))
    }

    fn latest_parent_hash_for_entity(&self, entity_id: &str) -> Result<Vec<String>, KernelXError> {
        let mut events = <S as ReplayStore>::load_events_for_replay(&self.store)?;
        events.sort_by(|a, b| {
            a.logical_clock
                .cmp(&b.logical_clock)
                .then_with(|| a.timestamp.cmp(&b.timestamp))
                .then_with(|| a.event_hash.cmp(&b.event_hash))
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        let parent = events
            .into_iter()
            .rev()
            .find(|event| event.entity_id == entity_id)
            .map(|event| event.event_hash);

        Ok(parent.into_iter().collect())
    }

    fn next_event_sequence_for_entity(
        &self,
        entity_id: &str,
        region_id: &str,
    ) -> Result<u64, KernelXError> {
        let events = <S as ReplayStore>::load_events_for_replay(&self.store)?;
        let count = events
            .iter()
            .filter(|event| event.entity_id == entity_id && event.region_id == region_id)
            .count();

        let next = count
            .checked_add(1)
            .ok_or_else(|| KernelXError::InvalidState("event sequence overflow".to_string()))?;

        u64::try_from(next)
            .map_err(|_| KernelXError::InvalidState("event sequence overflow".to_string()))
    }

    fn build_transition_event(
        &self,
        before: Option<&VectorStateV1>,
        after: &VectorStateV1,
        operation: OperationType,
        logical_clock: u64,
        timestamp: u64,
        parent_hashes: Vec<String>,
    ) -> Result<VectorEvent, KernelXError> {
        let vector_before = match before {
            Some(state) => Self::vector_v1_to_event_state(state)?,
            None => VectorState::zero(
                after.components.len(),
                after.owner_pubkey.clone(),
                format!("{:?}", after.vector_type),
            ),
        };

        let vector_after = Self::vector_v1_to_event_state(after)?;
        let auth_ratio = after.certification.auth_ratio as f64 / 1000.0;
        let certified = after.certification.certified;

        let sequence = self.next_event_sequence_for_entity(&after.vector_id, &after.space_id)?;
        let event_id = VectorEvent::canonical_event_id(
            &after.vector_id,
            &after.space_id,
            &operation,
            logical_clock,
            sequence,
        );

        let mut event = VectorEvent::new(
            event_id,
            parent_hashes,
            after.space_id.clone(),
            after.vector_id.clone(),
            operation,
            vector_before,
            vector_after,
            auth_ratio,
            certified,
            after.owner_pubkey.clone(),
            logical_clock,
            timestamp,
        );

        event.payload_hash = canonical_payload_hash(&event);
        event.event_hash = canonical_event_hash(&event);
        Ok(event)
    }

    fn ensure_parent_closure(&self, event: &VectorEvent) -> Result<(), KernelXError> {
        for parent_hash in &event.parent_hashes {
            if <S as EventStore>::get_event_by_hash(&self.store, parent_hash)?.is_none() {
                return Err(KernelXError::InvalidState(format!(
                    "orphan event {} references missing parent {}",
                    event.event_hash, parent_hash
                )));
            }
        }
        Ok(())
    }

    fn append_canonical_event(&mut self, event: VectorEvent) -> Result<(), KernelXError> {
        validate_event(&event)?;
        self.ensure_parent_closure(&event)?;
        <S as EventStore>::append_event(&mut self.store, event)?;
        Ok(())
    }

    pub fn replay_canonical_history(&self) -> Result<ReplayResult, KernelXError> {
        let events = <S as ReplayStore>::load_events_for_replay(&self.store)?;
        replay_events(&events).map_err(KernelXError::InvalidState)
    }

    pub fn current_state_root(&self) -> Result<StateRoot, KernelXError> {
        let states = <S as StateStore>::list_states(&self.store)?;
        let logical_clock = states.iter().map(|s| s.updated_at_ms).max().unwrap_or(0);
        Ok(compute_state_root(&states, logical_clock))
    }

    pub fn certify(&mut self, vector_id: &str) -> Result<VectorStateV1, KernelXError> {
        let state = self
            .store
            .get_state(vector_id)?
            .ok_or(KernelXError::VectorNotFound)?;
        let mut updated = state.clone();
        updated.certification = certify_state(&state, true, true);
        updated.updated_at_ms = now_ms();
        updated.version += 1;
        self.store.put_state(updated.clone())?;

        let record = VectorRecordV1::new(
            make_record_id(
                "certify",
                vector_id,
                format!("version={};auth={}", updated.version, updated.certification.auth_ratio),
            ),
            vector_id.to_string(),
            Some(state.clone()),
            updated.clone(),
            OperationKind::Certify,
            serde_json::json!({}),
        );
        Self::assert_record_operation_kind(&record, OperationType::Certify);

        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }

        let event = self.build_transition_event(
            Some(&state),
            &updated,
            OperationType::Certify,
            updated.version,
            updated.updated_at_ms,
            self.latest_parent_hash_for_entity(&updated.vector_id)?,
        )?;
        self.append_canonical_event(event)?;

        Ok(updated)
    }

    pub fn origin_create(
        &mut self,
        vector_id: impl Into<String>,
        owner_pubkey: impl Into<String>,
        space_id: impl Into<String>,
        components: Vec<u128>,
        seed: impl Into<String>,
        nonce: u64,
        difficulty: u32,
    ) -> Result<VectorStateV1, KernelXError> {
        let mut state = create_origin_vector(
            vector_id,
            owner_pubkey,
            space_id,
            components,
            seed,
            nonce,
            difficulty,
        )?;
        validate_state(&state)?;
        state.certification = certify_state(&state, true, true);
        self.store.put_state(state.clone())?;

        let record = VectorRecordV1::new(
            make_record_id(
                "origin",
                &state.vector_id,
                format!("difficulty={};version={}", difficulty, state.version),
            ),
            state.vector_id.clone(),
            None,
            state.clone(),
            OperationKind::OriginCreate,
            serde_json::json!({ "difficulty": difficulty }),
        );
        Self::assert_record_operation_kind(&record, OperationType::OriginCreate);

        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }

        let event = self.build_transition_event(
            None,
            &state,
            OperationType::OriginCreate,
            state.version,
            state.created_at_ms,
            Vec::new(),
        )?;
        self.append_canonical_event(event)?;

        Ok(state)
    }

    pub fn transfer(
        &mut self,
        from_id: &str,
        to_id: &str,
        amount: Vec<u128>,
    ) -> Result<(VectorStateV1, VectorStateV1), KernelXError> {
        let from = self
            .store
            .get_state(from_id)?
            .ok_or(KernelXError::VectorNotFound)?;
        let to = self
            .store
            .get_state(to_id)?
            .ok_or(KernelXError::VectorNotFound)?;
        let before_from = from.clone();
        let before_to = to.clone();
        let (mut after_from, mut after_to) = transfer_components(from, to, amount.clone())?;
        after_from.certification = certify_state(&after_from, true, true);
        after_to.certification = certify_state(&after_to, true, true);
        self.store.put_state(after_from.clone())?;
        self.store.put_state(after_to.clone())?;

        let (mut sender_record, mut receiver_record) = transfer_record(
            &before_from,
            &before_to,
            &after_from,
            &after_to,
            amount,
        );
        sender_record.certification = after_from.certification.clone();
        receiver_record.certification = after_to.certification.clone();

        Self::assert_record_operation_kind(&sender_record, OperationType::Transfer);
        Self::assert_record_operation_kind(&receiver_record, OperationType::Transfer);

        if accept_record(&sender_record, &self.consensus) {
            self.store.put_record(sender_record)?;
        }
        if accept_record(&receiver_record, &self.consensus) {
            self.store.put_record(receiver_record)?;
        }

        let sender_event = self.build_transition_event(
            Some(&before_from),
            &after_from,
            OperationType::Transfer,
            after_from.version,
            now_ms(),
            self.latest_parent_hash_for_entity(&after_from.vector_id)?,
        )?;
        self.append_canonical_event(sender_event)?;

        let receiver_event = self.build_transition_event(
            Some(&before_to),
            &after_to,
            OperationType::Transfer,
            after_to.version,
            now_ms(),
            self.latest_parent_hash_for_entity(&after_to.vector_id)?,
        )?;
        self.append_canonical_event(receiver_event)?;

        Ok((after_from, after_to))
    }

    pub fn drain(
        &mut self,
        vector_id: &str,
        basis_points: u16,
    ) -> Result<VectorStateV1, KernelXError> {
        let mut state = self
            .store
            .get_state(vector_id)?
            .ok_or(KernelXError::VectorNotFound)?;

        let before = state.clone();

        let (_drained, remaining) = apply_drain(
            &before.components,
            basis_points,
            before.certification.auth_ratio,
            before.certification.threshold,
        )?;

        state.components = remaining;
        state.certification = certify_state(&state, true, true);
        state.updated_at_ms = now_ms();
        state.version += 1;
        self.store.put_state(state.clone())?;

        let record_params = serde_json::json!({
            "basis_points": basis_points,
            "remaining": state.components.clone()
        });

        let record = VectorRecordV1::new(
            make_record_id("drain", vector_id, record_params.to_string()),
            vector_id.to_string(),
            Some(before.clone()),
            state.clone(),
            OperationKind::Drain,
            record_params,
        );
        Self::assert_record_operation_kind(&record, OperationType::Drain);

        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }

        let event = self.build_transition_event(
            Some(&before),
            &state,
            OperationType::Drain,
            state.version,
            state.updated_at_ms,
            self.latest_parent_hash_for_entity(&state.vector_id)?,
        )?;
        self.append_canonical_event(event)?;

        Ok(state)
    }

    pub fn project(
        &mut self,
        vector_id: &str,
        projected_components: Vec<u128>,
        escrow_id: impl Into<String>,
    ) -> Result<VectorStateV1, KernelXError> {
        let state = self
            .store
            .get_state(vector_id)?
            .ok_or(KernelXError::VectorNotFound)?;
        let before = state.clone();
        let mut after = project_vector(state, projected_components.clone(), escrow_id)?;
        after.certification = certify_state(&after, true, true);
        self.store.put_state(after.clone())?;

        let record = VectorRecordV1::new(
            make_record_id(
                "project",
                vector_id,
                serde_json::to_string(&serde_json::json!({ "projected_components": projected_components }))
                    .unwrap_or_default(),
            ),
            vector_id.to_string(),
            Some(before.clone()),
            after.clone(),
            OperationKind::Project,
            serde_json::json!({ "projected_components": projected_components }),
        );
        Self::assert_record_operation_kind(&record, OperationType::Project);

        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }

        let event = self.build_transition_event(
            Some(&before),
            &after,
            OperationType::Project,
            after.version,
            after.updated_at_ms,
            self.latest_parent_hash_for_entity(&after.vector_id)?,
        )?;
        self.append_canonical_event(event)?;

        Ok(after)
    }

    pub fn reconstruct(
        &mut self,
        vector_id: &str,
        outcome: SettlementOutcome,
    ) -> Result<VectorStateV1, KernelXError> {
        let state = self
            .store
            .get_state(vector_id)?
            .ok_or(KernelXError::VectorNotFound)?;
        let before = state.clone();
        let outcome_tag = outcome.outcome_tag.clone();
        let gains = outcome.gains.clone();
        let losses = outcome.losses.clone();
        let mut after = reconstruct_vector(state, outcome)?;
        after.certification = certify_state(&after, true, true);
        self.store.put_state(after.clone())?;

        let record_params = serde_json::json!({
            "outcome_tag": outcome_tag,
            "gains": gains,
            "losses": losses
        });

        let record = VectorRecordV1::new(
            make_record_id("reconstruct", vector_id, record_params.to_string()),
            vector_id.to_string(),
            Some(before.clone()),
            after.clone(),
            OperationKind::Reconstruct,
            record_params,
        );
        Self::assert_record_operation_kind(&record, OperationType::Reconstruct);

        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }

        let event = self.build_transition_event(
            Some(&before),
            &after,
            OperationType::Reconstruct,
            after.version,
            after.updated_at_ms,
            self.latest_parent_hash_for_entity(&after.vector_id)?,
        )?;
        self.append_canonical_event(event)?;

        Ok(after)
    }

    pub fn query_vector(&self, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError> {
        get_vector(&self.store, vector_id)
    }

    pub fn query_vectors(&self) -> Result<Vec<VectorStateV1>, KernelXError> {
        list_vectors(&self.store)
    }

    pub fn query_records(&self) -> Result<Vec<VectorRecordV1>, KernelXError> {
        list_records(&self.store)
    }

    pub fn query_event_by_hash(&self, event_hash: &str) -> Result<Option<VectorEvent>, KernelXError> {
        get_event_by_hash(&self.store, event_hash)
    }
}