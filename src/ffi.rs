// src/ffi.rs
use crate::dag::{topological_order, validate_dag};
use crate::hash::{canonical_event_hash, canonical_payload_hash};
use crate::replay::{compute_state_root, replay_events};
use crate::serialization::CanonicalSerialize;
use crate::signature::{verifying_key_from_hex, verify_event_signature};
use crate::{VectorEvent, VectorState};
use serde_json::json;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new(r#"{"ok":false,"error":"invalid cstring"}"#).unwrap())
        .into_raw()
}

fn from_c_string(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null pointer passed to kernel FFI".to_string());
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map_err(|e| format!("utf8 error in FFI string: {e}"))
        .map(|s| s.to_string())
}

fn ok_json(value: serde_json::Value) -> *mut c_char {
    to_c_string(json!({ "ok": true, "result": value }).to_string())
}

fn err_json(error: impl Into<String>) -> *mut c_char {
    to_c_string(json!({ "ok": false, "error": error.into() }).to_string())
}

fn parse_event(input: &str) -> Result<VectorEvent, String> {
    serde_json::from_str::<VectorEvent>(input).map_err(|e| format!("event parse error: {e}"))
}

fn validate_event_internal(event: &VectorEvent) -> Result<serde_json::Value, String> {
    let payload_hash = canonical_payload_hash(event);
    let event_hash = canonical_event_hash(event);

    let mut signature_ok = false;
    let mut signature_error: Option<String> = None;

    if !event.actor_public_key.is_empty() && !event.signature.is_empty() {
        match verifying_key_from_hex(&event.actor_public_key) {
            Ok(vk) => match verify_event_signature(
                &vk,
                &crate::serialization::canonical_event_payload_bytes(event),
                &event.signature,
            ) {
                Ok(ok) => signature_ok = ok,
                Err(e) => signature_error = Some(e),
            },
            Err(e) => signature_error = Some(e),
        }
    }

    let hashes_ok = payload_hash == event.payload_hash && event_hash == event.event_hash;
    let dag_ok = validate_dag(std::slice::from_ref(event)).is_ok();

    Ok(json!({
        "event_id": event.event_id,
        "payload_hash_ok": payload_hash == event.payload_hash,
        "event_hash_ok": event_hash == event.event_hash,
        "hashes_ok": hashes_ok,
        "signature_ok": signature_ok,
        "signature_error": signature_error,
        "dag_ok": dag_ok
    }))
}

/// Validate a single event passed as JSON.
/// Input: a JSON-encoded VectorEvent.
#[no_mangle]
pub extern "C" fn kernel_validate_event(input_json: *const c_char) -> *mut c_char {
    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => return err_json(e),
    };

    let event = match parse_event(&input) {
        Ok(v) => v,
        Err(e) => return err_json(e),
    };

    match validate_event_internal(&event) {
        Ok(result) => ok_json(result),
        Err(e) => err_json(e),
    }
}

/// Execute a batch of events passed as JSON.
/// Input: JSON array of VectorEvent.
/// Output: canonical replay result.
#[no_mangle]
pub extern "C" fn kernel_execute_operation(input_json: *const c_char) -> *mut c_char {
    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => return err_json(e),
    };

    let events: Vec<VectorEvent> = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => return err_json(format!("batch parse error: {e}")),
    };

    match replay_events(&events) {
        Ok(result) => ok_json(json!({
            "state_root": result.state_root,
            "replay_hash": result.replay_hash,
            "applied_event_hashes": result.applied_event_hashes,
            "final_state": result.final_state,
        })),
        Err(e) => err_json(e),
    }
}

/// Replay a batch of events passed as JSON.
/// This is intentionally separated from execute to keep the ABI explicit.
#[no_mangle]
pub extern "C" fn kernel_replay(input_json: *const c_char) -> *mut c_char {
    kernel_execute_operation(input_json)
}

/// Compute a state root from a replay-result-like JSON payload.
///
/// Expected input schema:
/// {
///   "final_state": { "entity_id": { ... VectorState ... }, ... },
///   "event_count": 12,
///   "logical_clock": 99
/// }
#[no_mangle]
pub extern "C" fn kernel_compute_state_root(input_json: *const c_char) -> *mut c_char {
    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => return err_json(e),
    };

    let value: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => return err_json(format!("state root input parse error: {e}")),
    };

    let final_state_value = match value.get("final_state") {
        Some(v) => v.clone(),
        None => return err_json("missing final_state".to_string()),
    };

    let event_count = match value.get("event_count").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return err_json("missing or invalid event_count".to_string()),
    };

    let logical_clock = match value.get("logical_clock").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return err_json("missing or invalid logical_clock".to_string()),
    };

    let final_state: std::collections::BTreeMap<String, VectorState> =
        match serde_json::from_value(final_state_value) {
            Ok(v) => v,
            Err(e) => return err_json(format!("final_state parse error: {e}")),
        };

    let state_root = compute_state_root(&final_state, event_count, logical_clock);
    ok_json(json!(state_root))
}

/// Verify a signature passed as JSON.
///
/// Expected input schema:
/// {
///   "public_key": "<hex 32-byte ed25519 verifying key>",
///   "payload": "<canonical payload utf8 string OR hex string depending on your integration>",
///   "signature": "<hex signature>"
/// }
///
/// For now the payload is interpreted as raw UTF-8 bytes.
#[no_mangle]
pub extern "C" fn kernel_verify_signature(input_json: *const c_char) -> *mut c_char {
    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => return err_json(e),
    };

    let value: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => return err_json(format!("signature input parse error: {e}")),
    };

    let public_key = match value.get("public_key").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return err_json("missing public_key".to_string()),
    };
    let payload = match value.get("payload").and_then(|v| v.as_str()) {
        Some(v) => v.as_bytes().to_vec(),
        None => return err_json("missing payload".to_string()),
    };
    let signature = match value.get("signature").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return err_json("missing signature".to_string()),
    };

    let vk = match verifying_key_from_hex(public_key) {
        Ok(v) => v,
        Err(e) => return err_json(e),
    };

    match verify_event_signature(&vk, &payload, signature) {
        Ok(ok) => ok_json(json!({ "verified": ok })),
        Err(e) => err_json(e),
    }
}

/// Free a string returned by the FFI functions above.
#[no_mangle]
pub extern "C" fn kernel_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}