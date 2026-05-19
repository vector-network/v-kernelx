use crate::error::KernelXError;
use crate::state::{now_ms, OriginState, VectorStateV1, VectorType};

pub fn origin_proof_hash(seed: &str, nonce: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed.as_bytes());
    hasher.update(&nonce.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

pub fn verify_origin(seed: &str, nonce: u64, difficulty: u32) -> bool {
    let proof = origin_proof_hash(seed, nonce);
    let leading_zero_nibbles = proof.chars().take_while(|c| *c == '0').count() as u32;
    leading_zero_nibbles >= difficulty
}

pub fn find_valid_nonce(seed: &str, difficulty: u32, max_attempts: u64) -> Option<u64> {
    if difficulty == 0 {
        return Some(0);
    }
    (0..max_attempts).find(|nonce| verify_origin(seed, *nonce, difficulty))
}

pub fn create_origin_vector(
    vector_id: impl Into<String>,
    owner_pubkey: impl Into<String>,
    space_id: impl Into<String>,
    components: Vec<u128>,
    seed: impl Into<String>,
    nonce: u64,
    difficulty: u32,
) -> Result<VectorStateV1, KernelXError> {
    let seed = seed.into();
    if !verify_origin(&seed, nonce, difficulty) {
        return Err(KernelXError::OriginRejected);
    }

    let timestamp = now_ms();
    let vector_id = vector_id.into();
    let proof_hash = origin_proof_hash(&seed, nonce);

    let mut state = VectorStateV1::new(
        vector_id.clone(),
        owner_pubkey,
        space_id,
        components,
        VectorType::Origin,
        timestamp,
    );

    state.origin = Some(OriginState {
        seed,
        nonce,
        difficulty,
        proof_hash,
    });
    state.certification.certified = true;
    state.certification.auth_ratio = 1000;
    state.certification.reason = None;

    Ok(state)
}