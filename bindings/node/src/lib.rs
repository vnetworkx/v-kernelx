use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use vnetwork_core::language::compile_vx_source;
use vnetwork_types::{blake3_hex, canonical_json_string, KeypairMaterial};

#[no_mangle]
pub extern "C" fn vnetwork_blake3_hex(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let c_str = unsafe { CStr::from_ptr(input) };
    let Ok(s) = c_str.to_str() else {
        return std::ptr::null_mut();
    };
    let digest = blake3_hex(s.as_bytes());
    CString::new(digest).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn vnetwork_compile_vx_json(
    source: *const c_char,
    file_name: *const c_char,
    modules_json: *const c_char,
) -> *mut c_char {
    let src = if source.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(source) }.to_str().unwrap_or("")
    };
    let fname = if file_name.is_null() {
        "program.vx"
    } else {
        unsafe { CStr::from_ptr(file_name) }.to_str().unwrap_or("program.vx")
    };
    let modules: BTreeMap<String, String> = if modules_json.is_null() {
        BTreeMap::new()
    } else {
        let raw = unsafe { CStr::from_ptr(modules_json) }.to_str().unwrap_or("{}");
        serde_json::from_str(raw).unwrap_or_default()
    };

    let out = match compile_vx_source(src, fname, &modules, None) {
        Ok(compiled) => serde_json::json!({ "ok": true, "compiled": compiled }),
        Err(err) => serde_json::json!({ "ok": false, "error": err.to_string() }),
    };
    let json_str = canonical_json_string(&out).unwrap_or_else(|_| "{}".to_string());
    CString::new(json_str).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn vnetwork_generate_keypair_json(role: *const c_char) -> *mut c_char {
    let role_str = if role.is_null() {
        "participant"
    } else {
        unsafe { CStr::from_ptr(role) }.to_str().unwrap_or("participant")
    };
    let kp = KeypairMaterial::generate(role_str);
    let json_str = canonical_json_string(&kp).unwrap_or_else(|_| "{}".to_string());
    CString::new(json_str).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn vnetwork_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
