use crate::dag::{topological_order, validate_dag};
use crate::event::VectorEvent;
use crate::event::VectorState;
use crate::hash::{canonical_event_hash, canonical_payload_hash};
use crate::replay::{replay_events, ReplayResult};
use crate::serialization::canonical_state_map_bytes;
use crate::signature::{verify_event_signature, verifying_key_from_hex};
use crate::state::{compute_state_root, VectorStateV1};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::Mutex;

struct KernelInner {
    events: Vec<VectorEvent>,
    last_error: Option<String>,
}

pub struct KernelHandle {
    inner: Mutex<KernelInner>,
}

impl KernelHandle {
    fn new() -> Self {
        Self {
            inner: Mutex::new(KernelInner {
                events: Vec::new(),
                last_error: None,
            }),
        }
    }
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

        // Harmless deterministic touch so the canonical serializer remains exercised.
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

fn kernel_not_implemented(name: &str) -> *mut c_char {
    err_json(format!(
        "{name} is not implemented yet in the embedded FFI layer"
    ))
}

/// Create a new embedded kernel handle.
#[no_mangle]
pub extern "C" fn kernel_init() -> *mut KernelHandle {
    let handle = Box::new(KernelHandle::new());
    Box::into_raw(handle)
}

/// Free the embedded kernel handle.
///
/// # Safety
/// `handle` must either be null or a pointer previously returned by
/// `kernel_init`. It must not be used again after this call.
#[no_mangle]
pub unsafe extern "C" fn kernel_free(handle: *mut KernelHandle) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
}

/// Return the last error string stored on the kernel handle.
///
/// # Safety
/// `handle` must either be null or a valid pointer created by `kernel_init`.
/// The returned string must be released with `kernel_string_free`.
#[no_mangle]
pub unsafe extern "C" fn kernel_last_error(handle: *mut KernelHandle) -> *mut c_char {
    match last_error_string(handle) {
        Some(msg) => to_c_string(msg),
        None => ptr::null_mut(),
    }
}

/// Free a string returned by any FFI function in this module.
///
/// # Safety
/// `ptr` must either be null or a pointer previously returned by this module's
/// string-returning functions. It must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn kernel_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = CString::from_raw(ptr);
}

/// Validate a single event passed as JSON.
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

/// Submit a single event into the embedded kernel.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_submit_event(
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
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    match validate_event_internal(&event) {
        Ok(validation) => {
            let hashes_ok = validation
                .get("hashes_ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let dag_ok = validation
                .get("dag_ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let signature_ok = validation
                .get("signature_ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if !hashes_ok || !dag_ok || !signature_ok {
                let msg = format!("event rejected: {validation}");
                set_last_error(handle, msg.clone());
                return err_json(msg);
            }
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    }

    let handle_ref = &*handle;
    let mut inner = match handle_ref.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let msg = "kernel state lock poisoned".to_string();
            set_last_error(handle, msg.clone());
            return err_json(msg);
        }
    };

    inner.events.push(event.clone());
    clear_last_error(handle);

    ok_json(json!({
        "accepted": true,
        "record": event
    }))
}

/// Execute a batch of events passed as JSON.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
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

    let events = match parse_event_list(&input) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(e);
        }
    };

    let ordered = match topological_order(&events) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(handle, e.clone());
            return err_json(format!("batch ordering error: {e}"));
        }
    };

    match replay_from_events(&ordered) {
        Ok(result) => {
            clear_last_error(handle);
            to_c_string(result.to_string())
        }
        Err(e) => {
            set_last_error(handle, e.clone());
            err_json(e)
        }
    }
}

/// Replay the events currently stored in the embedded kernel handle.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
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

    match replay_from_events(&inner.events) {
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

/// Compute a state root from the events currently stored in the kernel handle.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
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

    let output = if inner.events.is_empty() {
        let empty_state: BTreeMap<String, VectorState> = BTreeMap::new();
        let empty_states: [VectorStateV1; 0] = [];
        let _canonical_bytes = canonical_state_map_bytes(&empty_state);
        let state_root = compute_state_root(&empty_states, 0);
        json!({
            "ok": true,
            "state_root": state_root,
            "event_count": 0u64,
            "logical_clock": 0u64
        })
    } else {
        match replay_from_events(&inner.events) {
            Ok(replay_json) => {
                let state_root = replay_json.get("state_root").cloned().unwrap_or_else(|| {
                    json!({
                        "root_hash": "",
                        "event_count": 0u64,
                        "logical_clock": 0u64
                    })
                });

                let event_count = replay_json
                    .get("event_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let logical_clock = replay_json
                    .get("latest_clock")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                json!({
                    "ok": true,
                    "state_root": state_root,
                    "event_count": event_count,
                    "logical_clock": logical_clock
                })
            }
            Err(e) => {
                set_last_error(handle, e.clone());
                json!({
                    "ok": false,
                    "error": e,
                    "state_root": {
                        "root_hash": "",
                        "event_count": 0u64,
                        "logical_clock": 0u64
                    },
                    "event_count": 0u64,
                    "logical_clock": 0u64
                })
            }
        }
    };

    to_c_string(output.to_string())
}

/// Verify a record passed as JSON.
/// Expected input can be a raw VectorEvent or {"record": <VectorEvent>}.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
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

/// Verify a signature passed as JSON.
///
/// Expected input:
/// {
///   "public_key": "<hex verifying key>",
///   "payload": "<raw UTF-8 payload>",
///   "signature": "<hex signature>"
/// }
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

/// Create an origin vector request.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
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

/// Transfer request.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_transfer(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_transfer")
}

/// Drain request.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_drain(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_drain")
}

/// Project request.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_project(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_project")
}

/// Reconstruct request.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_reconstruct(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_reconstruct")
}

/// Certify request.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_certify(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_certify")
}

/// Return the current state root.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
#[no_mangle]
pub unsafe extern "C" fn kernel_current_state_root(handle: *mut KernelHandle) -> *mut c_char {
    kernel_compute_state_root(handle)
}

/// Query a single vector.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_query_vector(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_query_vector")
}

/// Query multiple vectors.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_query_vectors(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_query_vectors")
}

/// Query records.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_query_records(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_query_records")
}

/// Query an event by hash.
///
/// # Safety
/// `handle` must be a valid pointer returned by `kernel_init` or null.
/// `input_json` must point to a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn kernel_query_event_by_hash(
    handle: *mut KernelHandle,
    input_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return err_json("kernel handle is null");
    }
    let _ = input_json;
    kernel_not_implemented("kernel_query_event_by_hash")
}
