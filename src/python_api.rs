use crate::engine::KernelEngine;
use crate::reconstruction::SettlementOutcome;
use crate::storage::MemoryStore;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::Serialize;

fn to_json<T: Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyclass(unsendable)]
pub struct PyKernelEngine {
    inner: KernelEngine<MemoryStore>,
}

#[pymethods]
impl PyKernelEngine {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: KernelEngine::new(),
        }
    }

    pub fn origin_create(
        &mut self,
        vector_id: String,
        owner_pubkey: String,
        space_id: String,
        components: Vec<u128>,
        seed: String,
        nonce: u64,
        difficulty: u32,
    ) -> PyResult<String> {
        let state = self
            .inner
            .origin_create(
                vector_id,
                owner_pubkey,
                space_id,
                components,
                seed,
                nonce,
                difficulty,
            )
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&state)
    }

    pub fn transfer(
        &mut self,
        from_id: String,
        to_id: String,
        amount: Vec<u128>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .transfer(&from_id, &to_id, amount)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&result)
    }

    pub fn drain(&mut self, vector_id: String, basis_points: u16) -> PyResult<String> {
        let state = self
            .inner
            .drain(&vector_id, basis_points)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&state)
    }

    pub fn project(
        &mut self,
        vector_id: String,
        projected_components: Vec<u128>,
        escrow_id: String,
    ) -> PyResult<String> {
        let state = self
            .inner
            .project(&vector_id, projected_components, escrow_id)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&state)
    }

    pub fn reconstruct(
        &mut self,
        vector_id: String,
        outcome_tag: String,
        gains: Vec<u128>,
        losses: Vec<u128>,
    ) -> PyResult<String> {
        let outcome = SettlementOutcome {
            outcome_tag,
            gains,
            losses,
        };

        let state = self
            .inner
            .reconstruct(&vector_id, outcome)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&state)
    }

    pub fn query_vector(&self, vector_id: String) -> PyResult<String> {
        let result = self
            .inner
            .query_vector(&vector_id)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&result)
    }

    pub fn query_vectors(&self) -> PyResult<String> {
        let result = self
            .inner
            .query_vectors()
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&result)
    }

    pub fn query_records(&self) -> PyResult<String> {
        let result = self
            .inner
            .query_records()
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&result)
    }

    pub fn query_event_by_hash(&self, event_hash: String) -> PyResult<String> {
        let result = self
            .inner
            .query_event_by_hash(&event_hash)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&result)
    }

    pub fn replay_canonical_history(&self) -> PyResult<String> {
        let result = self
            .inner
            .replay_canonical_history()
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&result)
    }

    pub fn current_state_root(&self) -> PyResult<String> {
        let result = self
            .inner
            .current_state_root()
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        to_json(&result)
    }
}