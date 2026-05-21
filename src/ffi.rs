use crate::dag::{topological_order, validate_dag};
use crate::engine::KernelEngine;
use crate::event::{VectorEvent, VectorState};
use crate::hash::{canonical_event_hash, canonical_payload_hash};
use crate::reconstruction::SettlementOutcome;
use crate::replay::{replay_events, ReplayResult};
use crate::serialization::canonical_state_map_bytes;
use crate::signature::{verify_event_signature, verifying_key_from_hex};
use crate::state::{compute_state_root, VectorStateV1};
use crate::storage::MemoryStore;
use crate::transfer::transfer_components;
use crate::validation::validate_event;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::Mutex;

struct KernelInner {
    engine: KernelEngine<MemoryStore>,
    last_error: Option<String>,
    seen_request_ids: BTreeSet<String>,
}

pub struct KernelHandle {
    inner: Mutex<KernelInner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubmitEventRequest {
    request_id: String,
    operation: String,
    actor_public_key: String,
    signature: String,
    params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReconstructRequest {
    vector_id: String,
    outcome_tag: String,
    gains: Vec<u128>,
    losses: Vec<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OriginCreateRequest {
    vector_id: String,
    owner_pubkey: String,
    space_id: String,
    components: Vec<u128>,
    seed: String,
    nonce: u64,
    difficulty: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferRequest {
    from_id: String,
    to_id: String,
    amount: Vec<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DrainRequest {
    vector_id: String,
    basis_points: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectRequest {
    vector_id: String,
    projected_components: Vec<u128>,
    escrow_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertifyRequest {
    vector_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueryVectorRequest {
    vector_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueryEventByHashRequest {
    event_hash: String,
}

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

fn set_last_error(handle: *mut KernelHandle, msg: impl Into<String>) {
    if handle.is_null() {
        return;
    }
    let msg = msg.into();
    let handle_ref = unsafe { &*handle };
    if let Ok(mut inner) = handle_ref.inner.lock() {
        inner.last_error = Some(msg);
    }
}

fn clear_last_error(handle: *mut KernelHandle) {
    if handle.is_null() {
        return;
    }
    let handle_ref = unsafe { &*handle };
    if let Ok(mut inner) = handle_ref.inner.lock() {
        inner.last_error = None;
    }
}

fn last_error_string(handle: *mut KernelHandle) -> Option<String> {
    if handle.is_null() {
        return Some("kernel handle is null".to_string());
    }
    let handle_ref = unsafe { &*handle };
    let inner = handle_ref.inner.lock().ok()?;
    inner.last_error.clone()
}

fn parse_event(input: &str) -> Result<VectorEvent, String> {
    serde_json::from_str::<VectorEvent>(input).map_err(|e| format!("event parse error: {e}"))
}

fn parse_event_list(input: &str) -> Result<Vec<VectorEvent>, String> {
    if let Ok(v) = serde_json::from_str::<Vec<VectorEvent>>(input) {
        return Ok(v);
    }

    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|e| format!("batch parse error: {e}"))?;

    if let Some(events) = value.get("events") {
        serde_json::from_value::<Vec<VectorEvent>>(events.clone())
            .map_err(|e| format!("batch events parse error: {e}"))
    } else {
        Err("missing events array".to_string())
    }
}

fn parse_submit_request(input: &str) -> Result<SubmitEventRequest, String> {
    serde_json::from_str::<SubmitEventRequest>(input)
        .map_err(|e| format!("submit request parse error: {e}"))
}

fn parse_submit_request_list(input: &str) -> Result<Vec<SubmitEventRequest>, String> {
    if let Ok(v) = serde_json::from_str::<Vec<SubmitEventRequest>>(input) {
        return Ok(v);
    }

    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|e| format!("submit batch parse error: {e}"))?;

    if let Some(requests) = value.get("requests") {
        serde_json::from_value::<Vec<SubmitEventRequest>>(requests.clone())
            .map_err(|e| format!("submit batch request parse error: {e}"))
    } else {
        Err("missing requests array".to_string())
    }
}

fn canonical_submit_request_bytes(req: &SubmitEventRequest) -> Result<Vec<u8>, String> {
    let mut payload = BTreeMap::new();
    payload.insert("request_id".to_string(), req.request_id.clone());
    payload.insert("operation".to_string(), req.operation.clone());
    payload.insert("actor_public_key".to_string(), req.actor_public_key.clone());
    payload.insert(
        "params".to_string(),
        serde_json::to_string(&req.params)
            .map_err(|e| format!("canonical request serialization error: {e}"))?,
    );
    serde_json::to_vec(&payload).map_err(|e| format!("canonical request serialization error: {e}"))
}

fn operation_name(operation: &str) -> String {
    operation.trim().to_ascii_lowercase()
}

fn validate_operation_shape(operation: &str, params: &Value) -> Result<(), String> {
    match operation_name(operation).as_str() {
        "origin_create" | "create" | "origin" => {
            serde_json::from_value::<OriginCreateRequest>(params.clone())
                .map_err(|e| format!("origin_create params invalid: {e}"))?;
            Ok(())
        }
        "transfer" => {
            serde_json::from_value::<TransferRequest>(params.clone())
                .map_err(|e| format!("transfer params invalid: {e}"))?;
            Ok(())
        }
        "drain" => {
            serde_json::from_value::<DrainRequest>(params.clone())
                .map_err(|e| format!("drain params invalid: {e}"))?;
            Ok(())
        }
        "project" => {
            serde_json::from_value::<ProjectRequest>(params.clone())
                .map_err(|e| format!("project params invalid: {e}"))?;
            Ok(())
        }
        "reconstruct" => {
            serde_json::from_value::<ReconstructRequest>(params.clone())
                .map_err(|e| format!("reconstruct params invalid: {e}"))?;
            Ok(())
        }
        "certify" => {
            serde_json::from_value::<CertifyRequest>(params.clone())
                .map_err(|e| format!("certify params invalid: {e}"))?;
            Ok(())
        }
        other => Err(format!("unsupported operation: {other}")),
    }
}

fn validate_submit_request(
    inner: &KernelInner,
    request: &SubmitEventRequest,
) -> Result<Value, String> {
    if request.request_id.trim().is_empty() {
        return Err("missing request_id".to_string());
    }
    if request.actor_public_key.trim().is_empty() {
        return Err("missing actor_public_key".to_string());
    }
    if request.signature.trim().is_empty() {
        return Err("missing signature".to_string());
    }

    validate_operation_shape(&request.operation, &request.params)?;

    if inner.seen_request_ids.contains(&request.request_id) {
        return Err(format!("duplicate request_id: {}", request.request_id));
    }

    let verifying_key = verifying_key_from_hex(&request.actor_public_key)?;
    let bytes = canonical_submit_request_bytes(request)?;
    let signature_ok = verify_event_signature(&verifying_key, &bytes, &request.signature)
        .map_err(|e| format!("request signature verification error: {e}"))?;

    if !signature_ok {
        return Err("request signature verification failed".to_string());
    }

    Ok(json!({
        "request_id": request.request_id,
        "operation": request.operation,
        "shape_ok": true,
        "signature_ok": true
    }))
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

fn sort_events(events: &mut [VectorEvent]) {
    events.sort_by(|a, b| {
        a.logical_clock
            .cmp(&b.logical_clock)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.event_hash.cmp(&b.event_hash))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
}

fn compute_heads(events: &[VectorEvent]) -> Vec<String> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut referenced_as_parent = BTreeSet::new();
    for event in events {
        for parent_hash in &event.parent_hashes {
            referenced_as_parent.insert(parent_hash.clone());
        }
    }

    let mut heads: Vec<String> = events
        .iter()
        .filter(|event| !referenced_as_parent.contains(&event.event_hash))
        .map(|event| event.event_hash.clone())
        .collect();

    heads.sort();
    heads.dedup();
    heads
}

fn replay_from_events(events: &[VectorEvent]) -> Result<serde_json::Value, String> {
    let ordered = if events.is_empty() {
        Vec::new()
    } else {
        topological_order(events).map_err(|e| format!("batch ordering error: {e}"))?
    };

    if ordered.is_empty() {
        let empty_state: BTreeMap<String, VectorState> = BTreeMap::new();
        let empty_states: [VectorStateV1; 0] = [];
        let _canonical_bytes = canonical_state_map_bytes(&empty_state);
        let state_root = compute_state_root(&empty_states, 0);

        return Ok(json!({
            "state_root": state_root,
            "replay_hash": "",
            "applied_event_hashes": [],
            "final_state": empty_state,
            "event_count": 0u64,
            "latest_clock": 0u64,
            "heads": [],
            "verified": true
        }));
    }

    let result = replay_events(&ordered).map_err(|e| format!("replay error: {e}"))?;
    let ReplayResult {
        final_state,
        state_root,
        replay_hash,
        applied_event_hashes,
    } = result;

    let event_count = applied_event_hashes.len() as u64;
    let latest_clock = state_root.logical_clock;
    let heads = compute_heads(&ordered);

    Ok(json!({
        "state_root": state_root,
        "replay_hash": replay_hash,
        "applied_event_hashes": applied_event_hashes,
        "final_state": final_state,
        "event_count": event_count,
        "latest_clock": latest_clock,
        "heads": heads,
        "verified": true
    }))
}

fn engine_events(inner: &KernelInner) -> Result<Vec<VectorEvent>, String> {
    inner.engine.query_events().map_err(|e| format!("{e}"))
}

fn engine_replay_summary(inner: &KernelInner) -> Result<serde_json::Value, String> {
    let replay = inner
        .engine
        .replay_canonical_history()
        .map_err(|e| format!("{e}"))?;

    let events = engine_events(inner)?;
    let heads = compute_heads(&events);

    Ok(json!({
        "state_root": replay.state_root,
        "replay_hash": replay.replay_hash,
        "applied_event_hashes": replay.applied_event_hashes,
        "final_state": replay.final_state,
        "event_count": replay.applied_event_hashes.len() as u64,
        "latest_clock": replay.state_root.logical_clock,
        "heads": heads,
        "verified": true
    }))
}

fn collect_new_events(before: &[VectorEvent], after: &[VectorEvent]) -> Vec<VectorEvent> {
    let before_hashes: BTreeSet<String> = before.iter().map(|e| e.event_hash.clone()).collect();
    let mut new_events: Vec<VectorEvent> = after
        .iter()
        .filter(|event| !before_hashes.contains(&event.event_hash))
        .cloned()
        .collect();
    sort_events(&mut new_events);
    new_events
}

fn execute_and_collect<F>(
    inner: &mut KernelInner,
    operation: &str,
    f: F,
) -> Result<serde_json::Value, String>
where
    F: FnOnce(&mut KernelEngine<MemoryStore>) -> Result<serde_json::Value, String>,
{
    let before_events = engine_events(inner)?;
    let operation_result = f(&mut inner.engine)?;
    let after_events = engine_events(inner)?;
    let new_events = collect_new_events(&before_events, &after_events);

    if new_events.is_empty() {
        return Err(format!(
            "{operation} completed without emitting a canonical event"
        ));
    }

    let replay = engine_replay_summary(inner)?;
    let event_count = after_events.len() as u64;
    let latest_clock = replay
        .get("latest_clock")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Ok(json!({
        "accepted": true,
        "operation": operation,
        "result": operation_result,
        "records": new_events,
        "event_count": event_count,
        "latest_clock": latest_clock,
        "replay": replay
    }))
}

fn kernel_not_implemented(name: &str) -> *mut c_char {
    err_json(format!(
        "{name} is not implemented yet in the embedded FFI layer"
    ))
}

#[no_mangle]
pub extern "C" fn kernel_init() -> *mut KernelHandle {
    let handle = Box::new(KernelHandle {
        inner: Mutex::new(KernelInner {
            engine: KernelEngine::new(),
            last_error: None,
            seen_request_ids: BTreeSet::new(),
        }),
    });
    Box::into_raw(handle)
}

#[no_mangle]
pub unsafe extern "C" fn kernel_free(handle: *mut KernelHandle) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
}

#[no_mangle]
pub unsafe extern "C" fn kernel_last_error(handle: *mut KernelHandle) -> *mut c_char {
    match last_error_string(handle) {
        Some(msg) => to_c_string(msg),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = CString::from_raw(ptr);
}

#[no_mangle]
pub extern "C" fn kernel_validate_event(input_json: *const c_char) -> *mut c_char {
    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => return err_json(e),
    };

    if let Ok(request) = parse_submit_request(&input) {
        let validation = match validate_operation_shape(&request.operation, &request.params) {
            Ok(_) => {
                let verifying_key = match verifying_key_from_hex(&request.actor_public_key) {
                    Ok(v) => v,
                    Err(e) => return err_json(e),
                };
                let bytes = match canonical_submit_request_bytes(&request) {
                    Ok(v) => v,
                    Err(e) => return err_json(e),
                };
                match verify_event_signature(&verifying_key, &bytes, &request.signature) {
                    Ok(ok) => json!({
                        "kind": "submit_request",
                        "request_id": request.request_id,
                        "operation": request.operation,
                        "shape_ok": true,
                        "signature_ok": ok
                    }),
                    Err(e) => return err_json(e),
                }
            }
            Err(e) => return err_json(e),
        };

        return ok_json(validation);
    }

    let event = match parse_event(&input) {
        Ok(v) => v,
        Err(e) => return err_json(e),
    };

    match validate_event_internal(&event) {
        Ok(result) => ok_json(result),
        Err(e) => err_json(e),
    }
}

fn parse_request_payload<T: for<'de> Deserialize<'de>>(
    params: &Value,
    label: &str,
) -> Result<T, String> {
    serde_json::from_value::<T>(params.clone()).map_err(|e| format!("{label} parse error: {e}"))
}

fn execute_submit_request(
    handle: *mut KernelHandle,
    request: SubmitEventRequest,
) -> Result<serde_json::Value, String> {
    if handle.is_null() {
        return Err("kernel handle is null".to_string());
    }

    let handle_ref = unsafe { &*handle };
    let mut inner = handle_ref
        .inner
        .lock()
        .map_err(|_| "kernel state lock poisoned".to_string())?;

    let _validation = validate_submit_request(&inner, &request)?;

    let result = match operation_name(&request.operation).as_str() {
        "origin_create" | "create" | "origin" => {
            let params: OriginCreateRequest =
                parse_request_payload(&request.params, "origin_create")?;
            execute_and_collect(&mut inner, "origin_create", |engine| {
                let state = engine
                    .origin_create(
                        params.vector_id,
                        params.owner_pubkey,
                        params.space_id,
                        params.components,
                        params.seed,
                        params.nonce,
                        params.difficulty,
                    )
                    .map_err(|e| format!("{e}"))?;
                Ok(json!({ "state": state }))
            })?
        }
        "transfer" => {
            let params: TransferRequest = parse_request_payload(&request.params, "transfer")?;
            execute_and_collect(&mut inner, "transfer", |engine| {
                let (from_state, to_state) = engine
                    .transfer(&params.from_id, &params.to_id, params.amount)
                    .map_err(|e| format!("{e}"))?;
                Ok(json!({
                    "from_state": from_state,
                    "to_state": to_state
                }))
            })?
        }
        "drain" => {
            let params: DrainRequest = parse_request_payload(&request.params, "drain")?;
            execute_and_collect(&mut inner, "drain", |engine| {
                let state = engine
                    .drain(&params.vector_id, params.basis_points)
                    .map_err(|e| format!("{e}"))?;
                Ok(json!({ "state": state }))
            })?
        }
        "project" => {
            let params: ProjectRequest = parse_request_payload(&request.params, "project")?;
            execute_and_collect(&mut inner, "project", |engine| {
                let state = engine
                    .project(
                        &params.vector_id,
                        params.projected_components,
                        params.escrow_id,
                    )
                    .map_err(|e| format!("{e}"))?;
                Ok(json!({ "state": state }))
            })?
        }
        "reconstruct" => {
            let params: ReconstructRequest = parse_request_payload(&request.params, "reconstruct")?;
            execute_and_collect(&mut inner, "reconstruct", |engine| {
                let state = engine
                    .reconstruct(
                        &params.vector_id,
                        SettlementOutcome {
                            outcome_tag: params.outcome_tag,
                            gains: params.gains,
                            losses: params.losses,
                        },
                    )
                    .map_err(|e| format!("{e}"))?;
                Ok(json!({ "state": state }))
            })?
        }
        "certify" => {
            let params: CertifyRequest = parse_request_payload(&request.params, "certify")?;
            execute_and_collect(&mut inner, "certify", |engine| {
                let state = engine
                    .certify(&params.vector_id)
                    .map_err(|e| format!("{e}"))?;
                Ok(json!({ "state": state }))
            })?
        }
        other => return Err(format!("unsupported operation: {other}")),
    };

    inner.seen_request_ids.insert(request.request_id.clone());
    clear_last_error(handle);

    Ok(json!({
        "request_validation": validate_submit_request(&inner, &request)?,
        "accepted": true,
        "request_id": request.request_id,
        "operation": request.operation,
        "result": result.get("result").cloned().unwrap_or_else(|| json!(null)),
        "records": result.get("records").cloned().unwrap_or_else(|| json!([])),
        "replay": result.get("replay").cloned().unwrap_or_else(|| json!(null)),
        "event_count": result.get("event_count").cloned().unwrap_or_else(|| json!(0)),
        "latest_clock": result.get("latest_clock").cloned().unwrap_or_else(|| json!(0))
    }))
}

#[no_mangle]
pub extern "C" fn kernel_submit_event(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let request = match parse_submit_request(&input) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    match execute_submit_request(handle, request) {
        Ok(result) => ok_json(result),
        Err(e) => {
            set_last_error(handle, e.clone());
            err_json(e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_execute_operation(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let requests = match parse_submit_request_list(&input) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let mut results = Vec::with_capacity(requests.len());

    for request in requests {
        match execute_submit_request(handle, request) {
            Ok(v) => results.push(v),
            Err(e) => {
                set_last_error(handle, e.clone());
                return err_json(e);
            }
        }
    }

    clear_last_error(handle);
    ok_json(json!({ "results": results }))
}

#[no_mangle]
pub unsafe extern "C" fn kernel_replay(handle: *mut KernelHandle) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let handle_ref = &*handle;
    let inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match engine_replay_summary(&inner) {
        Ok(result) => {
            clear_last_error(handle);
            to_c_string(result.to_string())
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            let empty_states: [VectorStateV1; 0] = [];
            let empty_state_root = compute_state_root(&empty_states, 0);
            to_c_string(
                json!({
                    "state_root": empty_state_root,
                    "replay_hash": "",
                    "applied_event_hashes": [],
                    "final_state": {},
                    "event_count": 0u64,
                    "latest_clock": 0u64,
                    "heads": [],
                    "verified": false,
                    "error": e
                })
                .to_string(),
            )
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_compute_state_root(handle: *mut KernelHandle) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let handle_ref = &*handle;
    let inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    let output = match inner.engine.current_state_root() {
        Ok(state_root) => {
            let event_count = inner
                .engine
                .query_events()
                .map(|v| v.len() as u64)
                .unwrap_or(0);
            json!({
                "ok": true,
                "state_root": state_root,
                "event_count": event_count,
                "logical_clock": state_root.logical_clock
            })
        }
        Err(e) => {
            let msg = format!("{e}");
            set_last_error(handle, msg.clone());
            json!({
                "ok": false,
                "error": msg,
                "state_root": {
                    "root_hash": "",
                    "event_count": 0u64,
                    "logical_clock": 0u64
                },
                "event_count": 0u64,
                "logical_clock": 0u64
            })
        }
    };

    to_c_string(output.to_string())
}

#[no_mangle]
pub unsafe extern "C" fn kernel_verify_record(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let event = match parse_event(&input) {
        Ok(v) => v,
        Err(_) => {
            let value: serde_json::Value = match serde_json::from_str(&input) {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("record parse error: {e}");
                    set_last_error(handle, msg.clone());
                    return err_json(msg);
                }
            };

            if let Some(raw) = value.get("record") {
                match serde_json::from_value::<VectorEvent>(raw.clone()) {
                    Ok(v) => v,
                    Err(e) => {
                        let msg = format!("record inner parse error: {e}");
                        set_last_error(handle, msg.clone());
                        return err_json(msg);
                    }
                }
            } else {
                let msg = "record JSON did not contain a VectorEvent or record field".to_string();
                set_last_error(handle, msg.clone());
                return err_json(msg);
            }
        }
    };

    match validate_event_internal(&event) {
        Ok(result) => {
            let hashes_ok = result
                .get("hashes_ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let dag_ok = result
                .get("dag_ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let signature_ok = result
                .get("signature_ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let verified = hashes_ok && dag_ok && signature_ok;
            if verified {
                clear_last_error(handle);
                ok_json(json!({ "verified": true }))
            } else {
                let msg = "record verification failed".to_string();
                set_last_error(handle, msg.clone());
                err_json(msg)
            }
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            err_json(e)
        }
    }
}

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

#[no_mangle]
pub unsafe extern "C" fn kernel_origin_create(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_origin_create")
}

#[no_mangle]
pub unsafe extern "C" fn kernel_transfer(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let params: TransferRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("transfer parse error: {e}");
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    let handle_ref = &*handle;
    let mut inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match execute_and_collect(&mut inner, "transfer", |engine| {
        let (from_state, to_state) = engine
            .transfer(&params.from_id, &params.to_id, params.amount)
            .map_err(|e| format!("{e}"))?;
        Ok(json!({
            "from_state": from_state,
            "to_state": to_state
        }))
    }) {
        Ok(result) => {
            clear_last_error(handle);
            ok_json(result)
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            err_json(e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_drain(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let params: DrainRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("drain parse error: {e}");
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    let handle_ref = &*handle;
    let mut inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match execute_and_collect(&mut inner, "drain", |engine| {
        let state = engine
            .drain(&params.vector_id, params.basis_points)
            .map_err(|e| format!("{e}"))?;
        Ok(json!({ "state": state }))
    }) {
        Ok(result) => {
            clear_last_error(handle);
            ok_json(result)
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            err_json(e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_project(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let params: ProjectRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("project parse error: {e}");
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    let handle_ref = &*handle;
    let mut inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match execute_and_collect(&mut inner, "project", |engine| {
        let state = engine
            .project(
                &params.vector_id,
                params.projected_components,
                params.escrow_id,
            )
            .map_err(|e| format!("{e}"))?;
        Ok(json!({ "state": state }))
    }) {
        Ok(result) => {
            clear_last_error(handle);
            ok_json(result)
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            err_json(e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_reconstruct(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let params: ReconstructRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("reconstruct parse error: {e}");
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    let handle_ref = &*handle;
    let mut inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match execute_and_collect(&mut inner, "reconstruct", |engine| {
        let state = engine
            .reconstruct(
                &params.vector_id,
                SettlementOutcome {
                    outcome_tag: params.outcome_tag,
                    gains: params.gains,
                    losses: params.losses,
                },
            )
            .map_err(|e| format!("{e}"))?;
        Ok(json!({ "state": state }))
    }) {
        Ok(result) => {
            clear_last_error(handle);
            ok_json(result)
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            err_json(e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_certify(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let params: CertifyRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("certify parse error: {e}");
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    let handle_ref = &*handle;
    let mut inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match execute_and_collect(&mut inner, "certify", |engine| {
        let state = engine
            .certify(&params.vector_id)
            .map_err(|e| format!("{e}"))?;
        Ok(json!({ "state": state }))
    }) {
        Ok(result) => {
            clear_last_error(handle);
            ok_json(result)
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            err_json(e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_current_state_root(handle: *mut KernelHandle) -> *mut c_char {
    kernel_compute_state_root(handle)
}

#[no_mangle]
pub unsafe extern "C" fn kernel_query_vector(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let request: QueryVectorRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("query_vector parse error: {e}");
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    let handle_ref = &*handle;
    let inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match inner.engine.query_vector(&request.vector_id) {
        Ok(Some(vector)) => {
            clear_last_error(handle);
            ok_json(json!({ "vector": vector }))
        }
        Ok(None) => {
            clear_last_error(handle);
            ok_json(json!({ "found": false }))
        }
        Err(e) => {
            let msg = format!("{e}");
            set_last_error(handle, msg.clone());
            err_json(msg)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_query_vectors(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let _ = input_json;
    let handle_ref = &*handle;
    let inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match inner.engine.query_vectors() {
        Ok(vectors) => {
            clear_last_error(handle);
            ok_json(json!({ "vectors": vectors }))
        }
        Err(e) => {
            let msg = format!("{e}");
            set_last_error(handle, msg.clone());
            err_json(msg)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_query_records(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let _ = input_json;
    let handle_ref = &*handle;
    let inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match inner.engine.query_records() {
        Ok(records) => {
            clear_last_error(handle);
            ok_json(json!({ "records": records }))
        }
        Err(e) => {
            let msg = format!("{e}");
            set_last_error(handle, msg.clone());
            err_json(msg)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn kernel_query_event_by_hash(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }

    let input = match from_c_string(input_json) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let request: QueryEventByHashRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("query_event_by_hash parse error: {e}");
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    let handle_ref = &*handle;
    let inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    match inner.engine.query_event_by_hash(&request.event_hash) {
        Ok(Some(event)) => {
            clear_last_error(handle);
            ok_json(json!({ "event": event }))
        }
        Ok(None) => {
            clear_last_error(handle);
            ok_json(json!({ "found": false }))
        }
        Err(e) => {
            let msg = format!("{e}");
            set_last_error(handle, msg.clone());
            err_json(msg)
        }
    }
}
