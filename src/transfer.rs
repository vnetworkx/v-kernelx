use crate::certification::certify_state;
use crate::drain::{apply_transfer_drain, DrainRewardDistribution};
use crate::error::KernelXError;
use crate::record::{make_record_id, OperationKind, VectorRecordV1};
use crate::state::{now_ms, VectorStateV1, VectorType};
use serde_json::json;

pub fn transport_components(
    reserve: VectorStateV1,
    recipient: VectorStateV1,
    amount: Vec<u128>,
) -> Result<(VectorStateV1, VectorStateV1), KernelXError> {
    reserve.ensure_same_shape(&recipient)?;
    if reserve.components.len() != amount.len() {
        return Err(KernelXError::DimensionMismatch);
    }
    if amount.iter().all(|a| *a == 0) {
        return Err(KernelXError::Rejected(
            "transport amount must contain at least one positive component".to_string(),
        ));
    }
    if amount
        .iter()
        .zip(reserve.components.iter())
        .any(|(a, r)| a > r)
    {
        return Err(KernelXError::InsufficientBalance);
    }

    let ts = now_ms();
    let mut reserve_after = reserve;
    let mut recipient_after = recipient;

    reserve_after.components = reserve_after
        .components
        .iter()
        .zip(amount.iter())
        .map(|(r, a)| r.saturating_sub(*a))
        .collect();
    recipient_after.components = recipient_after
        .components
        .iter()
        .zip(amount.iter())
        .map(|(c, a)| c.saturating_add(*a))
        .collect();

    reserve_after.updated_at_ms = ts;
    reserve_after.version += 1;
    recipient_after.updated_at_ms = ts;
    recipient_after.version += 1;
    recipient_after.vector_type = VectorType::Standard;

    Ok((reserve_after, recipient_after))
}

pub fn transfer_components(
    from: VectorStateV1,
    to: VectorStateV1,
    amount: Vec<u128>,
) -> Result<(VectorStateV1, VectorStateV1), KernelXError> {
    from.ensure_same_shape(&to)?;
    if from.components.len() != amount.len() {
        return Err(KernelXError::DimensionMismatch);
    }

    if amount
        .iter()
        .zip(from.components.iter())
        .any(|(a, b)| a > b)
    {
        return Err(KernelXError::InsufficientBalance);
    }

    let ts = now_ms();
    let mut sender = from;
    let mut receiver = to;

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
    sender.updated_at_ms = ts;
    receiver.updated_at_ms = ts;
    sender.version += 1;
    receiver.version += 1;

    Ok((sender, receiver))
}

pub fn transfer_components_with_drain(
    from: VectorStateV1,
    to: VectorStateV1,
    amount: Vec<u128>,
    drain_basis_points: u16,
) -> Result<(VectorStateV1, VectorStateV1, DrainRewardDistribution), KernelXError> {
    from.ensure_same_shape(&to)?;
    if from.components.len() != amount.len() {
        return Err(KernelXError::DimensionMismatch);
    }
    if amount
        .iter()
        .zip(from.components.iter())
        .any(|(a, b)| a > b)
    {
        return Err(KernelXError::InsufficientBalance);
    }

    let distribution = apply_transfer_drain(
        &amount,
        drain_basis_points,
        from.certification.auth_ratio,
        from.certification.threshold,
    )?;

    let ts = now_ms();
    let mut sender = from;
    let mut receiver = to;

    sender.components = sender
        .components
        .iter()
        .zip(amount.iter())
        .map(|(c, a)| c.saturating_sub(*a))
        .collect();

    receiver.components = receiver
        .components
        .iter()
        .zip(distribution.net_received.iter())
        .map(|(c, net)| c.saturating_add(*net))
        .collect();

    sender.vector_type = VectorType::Standard;
    receiver.vector_type = VectorType::Standard;
    sender.updated_at_ms = ts;
    receiver.updated_at_ms = ts;
    sender.version += 1;
    receiver.version += 1;

    Ok((sender, receiver, distribution))
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
        make_record_id(
            "transfer-out",
            &after_from.vector_id,
            sender_params.to_string(),
        ),
        after_from.vector_id.clone(),
        Some(before_from.clone()),
        after_from.clone(),
        OperationKind::Transfer,
        sender_params,
    );
    let receiver = VectorRecordV1::new(
        make_record_id(
            "transfer-in",
            &after_to.vector_id,
            receiver_params.to_string(),
        ),
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
