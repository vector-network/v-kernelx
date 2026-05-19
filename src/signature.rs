use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", byte as char)),
    }
}

fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_value(bytes[i])?;
        let lo = hex_value(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Sign canonical payload bytes and return a hex-encoded Ed25519 signature.
///
/// This signs the payload bytes that the replay/validation layer agrees are canonical.
pub fn sign_event(signing_key: &SigningKey, payload: &[u8]) -> String {
    let signature: Signature = signing_key.sign(payload);
    hex_encode(&signature.to_bytes())
}

/// Verify a hex-encoded signature against canonical payload bytes.
pub fn verify_event_signature(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_hex: &str,
) -> Result<bool, String> {
    let sig_bytes = hex_decode(signature_hex)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| format!("signature parse error: {e}"))?;
    Ok(verifying_key.verify(payload, &signature).is_ok())
}

/// Parse a hex-encoded Ed25519 public key.
pub fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey, String> {
    let bytes = hex_decode(public_key_hex)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "ed25519 verifying key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("public key parse error: {e}"))
}

/// Parse a hex-encoded Ed25519 signing key.
///
/// The expected input is 32 bytes for the secret key material.
pub fn signing_key_from_hex(secret_key_hex: &str) -> Result<SigningKey, String> {
    let bytes = hex_decode(secret_key_hex)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "ed25519 signing key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&key_bytes))
}