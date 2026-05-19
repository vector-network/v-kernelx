use crate::error::KernelXError;
use crate::state::{now_ms, ProjectionState, VectorStateV1, VectorStatus, VectorType};

pub fn project_vector(
    mut state: VectorStateV1,
    projected_components: Vec<u128>,
    escrow_id: impl Into<String>,
) -> Result<VectorStateV1, KernelXError> {
    if projected_components.len() != state.components.len() {
        return Err(KernelXError::DimensionMismatch);
    }

    if projected_components
        .iter()
        .zip(state.components.iter())
        .any(|(p, c)| p > c)
    {
        return Err(KernelXError::InsufficientBalance);
    }

    let started_at_ms = now_ms();

    let remainder: Vec<u128> = state
        .components
        .iter()
        .zip(projected_components.iter())
        .map(|(c, p)| c.saturating_sub(*p))
        .collect();

    state.components = remainder;
    state.status = VectorStatus::Projected;
    state.vector_type = VectorType::Projected;
    state.projection = Some(ProjectionState {
        escrow_id: escrow_id.into(),
        projected_components,
        settled_components: Vec::new(),
        started_at_ms,
        settlement_at_ms: None,
        outcome_tag: None,
    });
    state.updated_at_ms = started_at_ms;
    state.version += 1;

    Ok(state)
}