use crate::engine::KernelEngine;
use crate::reconstruction::SettlementOutcome;
use crate::region::{RegionCreateRequest, RegionVisibility};
use crate::storage::MemoryStore;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::Serialize;
use std::collections::BTreeMap;

fn to_json<T: Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(|err| PyValueError::new_err(err.to_string()))
}

fn map_err<E: ToString>(err: E) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn parse_region_visibility(value: &str) -> PyResult<RegionVisibility> {
    match value.trim().to_ascii_lowercase().as_str() {
        "public" => Ok(RegionVisibility::Public),
        "private" => Ok(RegionVisibility::Private),
        other => Err(PyValueError::new_err(format!(
            "invalid region visibility: {other}"
        ))),
    }
}

#[pyclass(unsendable)]
pub struct PyKernelEngine {
    inner: KernelEngine<MemoryStore>,
}

impl Default for PyKernelEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl PyKernelEngine {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: KernelEngine::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
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
            .map_err(map_err)?;

        to_json(&state)
    }

    pub fn certify(&mut self, vector_id: String) -> PyResult<String> {
        let state = self.inner.certify(&vector_id).map_err(map_err)?;
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
            .map_err(map_err)?;

        to_json(&result)
    }

    pub fn drain(&mut self, vector_id: String, basis_points: u16) -> PyResult<String> {
        let state = self
            .inner
            .drain(&vector_id, basis_points)
            .map_err(map_err)?;
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
            .map_err(map_err)?;

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
            .map_err(map_err)?;

        to_json(&state)
    }

    pub fn create_region(
        &mut self,
        region_name: String,
        actor_public_key: String,
        trigger_event_hash: String,
        creation_proof: String,
        visibility: String,
        request_signature: String,
        region_prefix: Option<String>,
        suggested_title: Option<String>,
        access_key: Option<String>,
        metadata: Option<BTreeMap<String, String>>,
    ) -> PyResult<String> {
        let request = RegionCreateRequest {
            region_name,
            region_prefix,
            suggested_title,
            visibility: parse_region_visibility(&visibility)?,
            trigger_event_hash,
            creation_proof,
            access_key,
            metadata: metadata.unwrap_or_default(),
            request_signature,
        };

        let state = self
            .inner
            .create_region(request, actor_public_key)
            .map_err(map_err)?;

        to_json(&state)
    }

    pub fn query_region(&self, region_id: String) -> PyResult<String> {
        let result = self.inner.query_region(&region_id).map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_region_by_name(
        &self,
        region_name: String,
        region_prefix: Option<String>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .query_region_by_name(&region_name, region_prefix.as_deref())
            .map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_regions(&self) -> PyResult<String> {
        let result = self.inner.query_regions().map_err(map_err)?;
        to_json(&result)
    }

    pub fn resolve_region_id(
        &self,
        region_name: String,
        region_prefix: Option<String>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .resolve_region_id(&region_name, region_prefix.as_deref())
            .map_err(map_err)?;
        to_json(&result)
    }

    pub fn region_exists(
        &self,
        region_name: String,
        region_prefix: Option<String>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .region_exists(&region_name, region_prefix.as_deref())
            .map_err(map_err)?;
        to_json(&result)
    }

    pub fn authorize_region(
        &self,
        region_id: String,
        access_key: Option<String>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .authorize_region(&region_id, access_key.as_deref())
            .map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_vector(&self, vector_id: String) -> PyResult<String> {
        let result = self.inner.query_vector(&vector_id).map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_vectors(&self) -> PyResult<String> {
        let result = self.inner.query_vectors().map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_records(&self) -> PyResult<String> {
        let result = self.inner.query_records().map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_event_by_hash(&self, event_hash: String) -> PyResult<String> {
        let result = self
            .inner
            .query_event_by_hash(&event_hash)
            .map_err(map_err)?;

        to_json(&result)
    }

    pub fn replay_canonical_history(&self) -> PyResult<String> {
        let result = self.inner.replay_canonical_history().map_err(map_err)?;

        to_json(&result)
    }

    pub fn current_state_root(&self) -> PyResult<String> {
        let result = self.inner.current_state_root().map_err(map_err)?;
        to_json(&result)
    }

    pub fn metrics(&self) -> PyResult<String> {
        let result = self.inner.metrics().map_err(map_err)?;
        to_json(&result)
    }
}
