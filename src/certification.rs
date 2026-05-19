use crate::state::{now_ms, CertificationState, VectorStateV1};

pub fn compute_auth_ratio(state: &VectorStateV1, ownership_verified: bool, structure_verified: bool) -> u16 {
    let magnitude_score = if state.magnitude() == 0 { 100 } else { 400 };
    let direction_score = if state.components.is_empty() { 0 } else { 200 };
    let ownership_score = if ownership_verified { 300 } else { 0 };
    let structure_score = if structure_verified { 100 } else { 0 };
    let total = magnitude_score + direction_score + ownership_score + structure_score;
    total.min(1000) as u16
}

pub fn compute_auth_ratio_unit(state: &VectorStateV1, ownership_verified: bool, structure_verified: bool) -> f64 {
    compute_auth_ratio(state, ownership_verified, structure_verified) as f64 / 1000.0
}

pub fn certify_state(
    state: &VectorStateV1,
    ownership_verified: bool,
    structure_verified: bool,
) -> CertificationState {
    let auth_ratio = compute_auth_ratio(state, ownership_verified, structure_verified);
    let threshold = state.certification.threshold;
    CertificationState {
        certified: auth_ratio >= threshold,
        auth_ratio,
        threshold,
        last_checked_at_ms: now_ms(),
        reason: if auth_ratio >= threshold {
            None
        } else {
            Some(format!("auth_ratio {} below threshold {}", auth_ratio, threshold))
        },
    }
}

pub fn is_certified(state: &VectorStateV1) -> bool {
    state.certification.certified
}