use crate::error::KernelXError;
use crate::state::{now_ms, VectorStateV1, VectorStatus, VectorType};

#[derive(Clone, Debug)]
pub struct SettlementOutcome {
    pub outcome_tag: String,
    pub gains: Vec<u128>,
    pub losses: Vec<u128>,
}

pub fn reconstruct_vector(
    mut state: VectorStateV1,
    outcome: SettlementOutcome,
) -> Result<VectorStateV1, KernelXError> {
    let projection = state
        .projection
        .clone()
        .ok_or_else(|| KernelXError::SettlementRejected("missing projection".to_string()))?;

    if projection.projected_components.len() != outcome.gains.len()
        || projection.projected_components.len() != outcome.losses.len()
    {
        return Err(KernelXError::DimensionMismatch);
    }

    let settled_at_ms = now_ms();
    let mut restored = state.components.clone();
    let mut settled = Vec::with_capacity(projection.projected_components.len());

    for (index, ((principal, gain), loss)) in projection
        .projected_components
        .iter()
        .zip(outcome.gains.iter())
        .zip(outcome.losses.iter())
        .enumerate()
    {
        let after_gain = principal.saturating_add(*gain);
        if *loss > after_gain {
            return Err(KernelXError::SettlementRejected(
                "loss exceeds projected value".to_string(),
            ));
        }

        let net = after_gain - *loss;
        settled.push(net);

        if let Some(slot) = restored.get_mut(index) {
            *slot = slot.saturating_add(net);
        } else {
            restored.push(net);
        }
    }

    state.components = restored;

    if let Some(mut p) = state.projection {
        p.settled_components = settled;
        p.settlement_at_ms = Some(settled_at_ms);
        p.outcome_tag = Some(outcome.outcome_tag);
        state.projection = Some(p);
    }

    state.vector_type = VectorType::Settlement;
    state.status = VectorStatus::Settled;
    state.updated_at_ms = settled_at_ms;
    state.version += 1;

    Ok(state)
}