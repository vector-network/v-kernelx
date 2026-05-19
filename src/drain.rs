use crate::error::KernelXError;

pub fn apply_drain(
    amounts: &[u128],
    basis_points: u16,
    auth_ratio: u16,
    threshold: u16,
) -> Result<(Vec<u128>, Vec<u128>), KernelXError> {
    if basis_points > 10_000 {
        return Err(KernelXError::Rejected(
            "drain basis points must be <= 10000".to_string(),
        ));
    }

    let discount = if auth_ratio >= threshold {
        basis_points / 2
    } else {
        basis_points
    };

    let mut drained = Vec::with_capacity(amounts.len());
    let mut remaining = Vec::with_capacity(amounts.len());

    for amount in amounts {
        let fee = amount.saturating_mul(discount as u128) / 10_000u128;
        drained.push(fee);
        remaining.push(amount.saturating_sub(fee));
    }

    Ok((drained, remaining))
}