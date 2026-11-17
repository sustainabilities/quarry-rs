//! FFI boundary tests — the paths Miri checks for UB.
//!
//! These drive the C-ABI exports the way a foreign host would: raw
//! pointers, manual lifetimes, the works. Miri's interpreter checks every
//! executed access against the Rust abstract machine — aliasing, alignment,
//! initialization, leak detection.

use std::ffi::{c_char, CStr, CString};

const RULE: &str = "rule \"Shell call\"\ncondition:\n    any call in tool_calls where call.name == \"shell\"\n";
const TRACE: &str = r#"{"messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"shell","arguments":"{}"}}]}]}"#;

#[test]
fn scan_happy_path() {
    let rule = CString::new(RULE).unwrap();
    let trace = CString::new(TRACE).unwrap();
    let mut code: i32 = -99;
    let rc = unsafe {
        quarry_ffi::quarry_scan(
            rule.as_ptr() as *const c_char,
            rule.as_bytes().len(),
            trace.as_ptr() as *const c_char,
            trace.as_bytes().len(),
            &mut code,
        )
    };
    assert_eq!(rc, 0, "authoritative scan returns 0");
    assert_eq!(code, 0);
}

#[test]
fn scan_rejects_null_and_garbage() {
    let rule = CString::new(RULE).unwrap();
    let mut code: i32 = -99;
    // Null pointer: refused, no crash.
    let rc = unsafe {
        quarry_ffi::quarry_scan(
            std::ptr::null(),
            10,
            rule.as_ptr() as *const c_char,
            rule.as_bytes().len(),
            &mut code,
        )
    };
    assert_eq!(rc, -2, "null input refused as InvalidInput");

    // Non-UTF8 bytes: refused, no crash.
    let garbage: [u8; 4] = [0xFF, 0xFE, 0x00, 0x41];
    let rc = unsafe {
        quarry_ffi::quarry_scan(
            rule.as_ptr() as *const c_char,
            rule.as_bytes().len(),
            garbage.as_ptr() as *const c_char,
            garbage.len(),
            &mut code,
        )
    };
    assert_eq!(rc, -2, "non-UTF8 refused as InvalidInput");
}

#[test]
fn handshake_rejects_wrong_ids() {
    let good = CString::new("x").unwrap();
    // A null array is refused outright (count 0 or not).
    let rc = unsafe { quarry_ffi::quarry_handshake(std::ptr::null(), 0) };
    assert_eq!(rc, -1, "null array refused as PassportMismatch");
    // A wrong ID is refused.
    let ids: [*const c_char; 1] = [good.as_ptr()];
    let rc = unsafe { quarry_ffi::quarry_handshake(ids.as_ptr(), 1) };
    assert_ne!(rc, 0, "unregistered passport refused");
}

#[test]
fn override_issue_and_free_roundtrip() {
    let rule = CString::new("Test rule").unwrap();
    let purpose = CString::new("test purpose").unwrap();
    let nonce_ptr = unsafe {
        quarry_ffi::quarry_override_issue(
            rule.as_ptr() as *const c_char,
            rule.as_bytes().len(),
            300,
            purpose.as_ptr() as *const c_char,
            purpose.as_bytes().len(),
        )
    };
    assert!(!nonce_ptr.is_null(), "issue hands back a nonce string");
    let nonce = unsafe { CStr::from_ptr(nonce_ptr) }.to_string_lossy().into_owned();
    unsafe { quarry_ffi::quarry_free(nonce_ptr) };
    assert_eq!(nonce.len(), 64, "256-bit hex nonce");
}

#[test]
fn scan_handles_empty_buffers() {
    // The (ptr,len) contract: len=0 with a valid pointer is legal and must
    // be refused as invalid input (empty rule), never dereferenced.
    let trace = CString::new(TRACE).unwrap();
    let mut code: i32 = -99;
    let rc = unsafe {
        quarry_ffi::quarry_scan(
            trace.as_ptr() as *const c_char,
            0, // empty rule
            trace.as_ptr() as *const c_char,
            trace.as_bytes().len(),
            &mut code,
        )
    };
    assert_eq!(rc, -2, "empty rule refused as InvalidInput");
}
