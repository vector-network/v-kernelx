use crate::error::KernelXError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletIdentity {
    pub public_key_hex: String,
    pub metadata: std::collections::BTreeMap<String, String>,
}

pub struct WalletContext {
    signing_key: SigningKey,
    public_key_hex: String,
    pub metadata: std::collections::BTreeMap<String, String>,
}

impl WalletContext {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            public_key_hex,
            metadata: std::collections::BTreeMap::new(),
        }
    }

    pub fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    pub fn identity(&self) -> WalletIdentity {
        WalletIdentity {
            public_key_hex: self.public_key_hex(),
            metadata: self.metadata.clone(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        hex::encode(signature.to_bytes())
    }
}

pub fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey, KernelXError> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| KernelXError::Signature)?;
    let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| KernelXError::Signature)?;
    VerifyingKey::from_bytes(&pk_array).map_err(|_| KernelXError::Signature)
}

pub fn verify_signature(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), KernelXError> {
    let verifying_key = verifying_key_from_hex(public_key_hex)?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| KernelXError::Signature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| KernelXError::Signature)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| KernelXError::Signature)
}