use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KernelXError {
    #[error("zero vector cannot be normalized")]
    ZeroNormalization,
    #[error("vector not certified")]
    NotCertified,
    #[error("invalid vector state: {0}")]
    InvalidState(String),
    #[error("signature verification failed")]
    Signature,
    #[error("wallet not found")]
    WalletNotFound,
    #[error("vector not found")]
    VectorNotFound,
    #[error("insufficient balance")]
    InsufficientBalance,
    #[error("dimension mismatch")]
    DimensionMismatch,
    #[error("operation rejected: {0}")]
    Rejected(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("origin proof rejected")]
    OriginRejected,
    #[error("settlement rejected: {0}")]
    SettlementRejected(String),
    #[error("replay failed: {0}")]
    Replay(String),
    #[error("snapshot error: {0}")]
    Snapshot(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("validation error: {0}")]
    Validation(String),
}