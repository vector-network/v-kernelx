use crate::certification::certify_state;
use crate::error::KernelXError;
use crate::record::{make_record_id, OperationKind, VectorRecordV1};
use crate::state::{VectorStateV1, VectorType};
use serde_json::json;

pub fn transfer_components(
    from: VectorStateV1,
    to: VectorStateV1,
    amount: Vec<u128>,
) -> Result<(VectorStateV1, VectorStateV1), KernelXError> {
    from.ensure_same_shape(&to)?;
    if from.components.len() != amount.len() {
        return Err(KernelXError::DimensionMismatch);
    }

    if amount.iter().zip(from.components.iter()).any(|(a, b)| a > b) {
        return Err(KernelXError::InsufficientBalance);
    }

    let mut sender = from.clone();
    let mut receiver = to.clone();

    sender.components = sender
        .components
        .iter()
        .zip(amount.iter())
        .map(|(c, a)| c.saturating_sub(*a))
        .collect();

    receiver.components = receiver
        .components
        .iter()
        .zip(amount.iter())
        .map(|(c, a)| c.saturating_add(*a))
        .collect();

    sender.vector_type = VectorType::Standard;
    receiver.vector_type = VectorType::Standard;

    Ok((sender, receiver))
}

pub fn transfer_record(
    before_from: &VectorStateV1,
    before_to: &VectorStateV1,
    after_from: &VectorStateV1,
    after_to: &VectorStateV1,
    amount: Vec<u128>,
) -> (VectorRecordV1, VectorRecordV1) {
    let sender_cert = certify_state(after_from, true, true);
    let receiver_cert = certify_state(after_to, true, true);

    let sender_params = json!({
        "direction": "out",
        "amount": amount.clone(),
        "version": after_from.version
    });
    let receiver_params = json!({
        "direction": "in",
        "amount": amount,
        "version": after_to.version
    });

    let sender = VectorRecordV1::new(
        make_record_id("transfer-out", &after_from.vector_id, sender_params.to_string()),
        after_from.vector_id.clone(),
        Some(before_from.clone()),
        after_from.clone(),
        OperationKind::Transfer,
        sender_params,
    );
    let receiver = VectorRecordV1::new(
        make_record_id("transfer-in", &after_to.vector_id, receiver_params.to_string()),
        after_to.vector_id.clone(),
        Some(before_to.clone()),
        after_to.clone(),
        OperationKind::Transfer,
        receiver_params,
    );

    let mut sender = sender;
    let mut receiver = receiver;
    sender.certification = sender_cert;
    receiver.certification = receiver_cert;

    (sender, receiver)
}