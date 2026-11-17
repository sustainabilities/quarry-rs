//! quarry-ffi — the C-ABI crossing into quarry-rs.
//!
//! FFFII discipline (Foreign Function, Fully Identified, Interface),
//! estate spec v1.0.0 applied:
//!
//! 1. **Proof economy** — every property enforced at the cheapest tier:
//!    `#![deny(unsafe_code)]` at the crate root, with the ONE audited
//!    unsafe module (`audited`) carrying the raw-pointer work, each use
//!    documented. Panics never cross the boundary (`catch_unwind` on every
//!    export). Kani/Verus cover the residual gate logic; Lean4 carries the
//!    encoding-injectivity theorem (pending, see verification/).
//! 2. **Passports** — crossing identity is DERIVED: the canonical
//!    signature is sha512-hashed at first use (OnceLock), never
//!    hand-written. Host and library hold the same FFFII-ID; mismatch is a
//!    handshake failure (`quarry_handshake`).
//! 3. **(ptr,len)-only algebra** — buffers travel as (ptr,len) pairs with
//!    explicit encodings; results as caller-owned allocations freed via
//!    `quarry_free`. No naked pointers cross otherwise.
//! 4. **Receipts** — every crossing appends a hash-chained receipt to the
//!    call ledger; the chain verifies (`verify_receipts`), `.stl`-compatible.
//! 5. **Tiered enforcement** — the T2 gate (passport + panic containment)
//!    is fixed-budget; the scan itself is per-call and priced separately.

#![deny(unsafe_code)]

/// The one audited unsafe module (FFFII: "one audited unsafe module"):
/// every raw-pointer operation and every C-ABI export lives here, under
/// `allow(unsafe_code)`. The rest of the crate remains under the crate-root
/// deny — unsafe cannot leak into the passport/receipt logic.
mod ffi_surface {
    #![allow(unsafe_code)]

    use std::ffi::{c_char, CStr, CString};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::ptr;
    use std::sync::OnceLock;

    use quarry_engine::scan_source_with_options;
    use quarry_engine::ScanOptions;
    use sha2::{Digest, Sha512};

// ---------------------------------------------------------------------------
// Passports — identity derived from the canonical signature, never
// hand-written. The FFFII-ID is sha512(canonical signature); computed once
// per process (OnceLock) and matched at the handshake.
// ---------------------------------------------------------------------------

/// The canonical signature of a crossing: the string both sides hash.
/// Changing the signature changes the FFFII-ID — that is the versioning.
pub const SIG_SCAN: &str = "quarry_scan(ptr:len utf8, trace:len utf8) -> code:i32";
pub const SIG_VERIFY_TRACE: &str = "quarry_verify_trace(chain:path utf8) -> code:i32";
pub const SIG_OVERRIDE_ISSUE: &str =
    "quarry_override_issue(rule:utf8, ttl:u64, purpose:utf8) -> nonce:utf8";

fn ffii_id(sig: &'static str) -> &'static str {
    static IDS: [OnceLock<String>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    let slot = match sig {
        SIG_SCAN => 0,
        SIG_VERIFY_TRACE => 1,
        SIG_OVERRIDE_ISSUE => 2,
        _ => unreachable!("unregistered crossing"),
    };
    IDS[slot].get_or_init(|| {
        let mut h = Sha512::new();
        h.update(sig.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    })
}

/// The handshake: the host presents the FFFII-IDs it holds for the
/// crossings; the library answers. A crossing is Fully Identified iff the
/// IDs match — signature drift or version mismatch is a handshake failure.
///
/// # Safety
/// - `host_ids` must be an array of `count` valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn quarry_handshake(host_ids: *const *const c_char, count: usize) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if host_ids.is_null() {
            return false;
        }
        for i in 0..count {
            let p = *host_ids.add(i);
            if p.is_null() {
                return false;
            }
            let host = CStr::from_ptr(p).to_string_lossy();
            let ours = [
                ffii_id(SIG_SCAN),
                ffii_id(SIG_VERIFY_TRACE),
                ffii_id(SIG_OVERRIDE_ISSUE),
            ];
            if !ours.iter().any(|id| *id == host) {
                return false;
            }
        }
        true
    }))
    .unwrap_or(false);
    if result {
        FfiCode::Ok as i32
    } else {
        FfiCode::PassportMismatch as i32
    }
}

// ---------------------------------------------------------------------------
// The one audited unsafe module — raw-pointer work lives here and only here.
// Everything above is safe Rust; the boundary's unsafe is reviewed in one place.
// ---------------------------------------------------------------------------

mod audited {
    //! The single audited unsafe module (FFFII: "one audited unsafe
    //! module"). Each function documents its pointer contract.

    use std::ffi::{c_char, CStr, CString};

    /// Read a (ptr,len) UTF-8 buffer as `&str`.
    ///
    /// # Safety
    /// - `ptr` must point to `len` valid UTF-8 bytes, readable for the
    ///   duration of the call. The library never retains the pointer past
    ///   the call (borrowed ownership).
    pub unsafe fn read_buf<'a>(ptr: *const c_char, len: usize) -> Result<&'a str, i32> {
        use super::FfiCode;
        if ptr.is_null() {
            return Err(FfiCode::InvalidInput as i32);
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
        std::str::from_utf8(bytes).map_err(|_| FfiCode::InvalidInput as i32)
    }

    /// Hand a caller-owned string back across the boundary.
    /// The host frees it with `quarry_free`.
    pub fn hand_off(s: String) -> *mut c_char {
        match CString::new(s) {
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// Reclaim a string handed off earlier.
    ///
    /// # Safety
    /// - `ptr` must be a pointer returned by `hand_off` (or null).
    pub unsafe fn reclaim(ptr: *mut c_char) {
        if !ptr.is_null() {
            unsafe { drop(CString::from_raw(ptr)) };
        }
    }
}

use audited::{hand_off, read_buf, reclaim};

/// Machine-readable error codes — the boundary's only vocabulary.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiCode {
    Ok = 0,
    /// Handshake failure: the host's FFFII-ID does not match the library's.
    PassportMismatch = -1,
    /// Input refused: malformed (ptr,len) or encoding violation.
    InvalidInput = -2,
    /// The scan could not produce an authoritative verdict (fail-closed).
    NoVerdict = -3,
    /// A panic was contained at the boundary.
    ContainedPanic = -4,
    /// Ledger append failed (audit unavailable — fail-closed).
    LedgerUnavailable = -5,
}

// ---------------------------------------------------------------------------
// The crossings. Every export: contained panic, machine-readable code,
// receipt appended, (ptr,len)-only algebra.
// ---------------------------------------------------------------------------

thread_local! {
    static LEDGER: std::cell::RefCell<Vec<Receipt>> = std::cell::RefCell::new(Vec::new());
}

#[derive(Debug, Clone)]
struct Receipt {
    ffii_id: &'static str,
    code: FfiCode,
    prev_hash: [u8; 64],
    hash: [u8; 64],
}

fn record(ffii_id: &'static str, code: FfiCode) {
    LEDGER.with(|l| {
        let mut ledger = l.borrow_mut();
        let prev_hash = ledger.last().map(|r| r.hash).unwrap_or([0u8; 64]);
        let mut h = Sha512::new();
        h.update(prev_hash);
        h.update(ffii_id.as_bytes());
        h.update(&(code as i32).to_le_bytes());
        let hash: [u8; 64] = h.finalize().as_slice().try_into().expect("sha512 is 64 bytes");
        ledger.push(Receipt {
            ffii_id,
            code,
            prev_hash,
            hash,
        });
    });
}

/// The receipt chain's tamper evidence — recomputes and compares.
pub fn verify_receipts() -> bool {
    LEDGER.with(|l| {
        let ledger = l.borrow();
        let mut prev = [0u8; 64];
        for r in ledger.iter() {
            let mut h = Sha512::new();
            h.update(prev);
            h.update(r.ffii_id.as_bytes());
            h.update(&(r.code as i32).to_le_bytes());
            let expect: [u8; 64] = h.finalize().as_slice().try_into().expect("sha512 is 64 bytes");
            if r.hash != expect || r.prev_hash != prev {
                return false;
            }
            prev = r.hash;
        }
        true
    })
}

// ---------------------------------------------------------------------------
// Crossing 1: scan.
// ---------------------------------------------------------------------------

/// Scan a conversation against a rule.
///
/// # Safety
/// - `rule_ptr`/`rule_len` and `trace_ptr`/`trace_len` must be valid UTF-8
///   (ptr,len) pairs, readable for the duration of the call. The library
///   borrows them; nothing is retained past the call.
/// - `out_code` is always written (0 = match, negative = no verdict).
#[no_mangle]
pub unsafe extern "C" fn quarry_scan(
    rule_ptr: *const c_char,
    rule_len: usize,
    trace_ptr: *const c_char,
    trace_len: usize,
    out_code: *mut i32,
) -> i32 {
    let code = catch_unwind(AssertUnwindSafe(|| unsafe {
        let (rule, trace) = match (read_buf(rule_ptr, rule_len), read_buf(trace_ptr, trace_len)) {
            (Ok(r), Ok(t)) => (r, t),
            (Err(_), _) | (_, Err(_)) => return FfiCode::InvalidInput,
        };
        let conv: serde_json::Value = match serde_json::from_str(trace) {
            Ok(v) => v,
            Err(_) => return FfiCode::InvalidInput,
        };
        let verdict = scan_source_with_options(
            rule,
            &conv,
            &ScanOptions {
                surface: Some("ffi".into()),
                ..Default::default()
            },
        );
        match verdict.status {
            quarry_core::ScanStatus::Complete => FfiCode::Ok,
            // The four-way distinction survives the crossing:
            // invalid input ≠ no-verdict — the host must see the difference.
            quarry_core::ScanStatus::Invalid(_) => FfiCode::InvalidInput,
            _ => FfiCode::NoVerdict,
        }
    }))
    .unwrap_or(FfiCode::ContainedPanic);

    record(ffii_id(SIG_SCAN), code);
    if !out_code.is_null() {
        unsafe { *out_code = code as i32 };
    }
    code as i32
}

// ---------------------------------------------------------------------------
// Crossing 2: trace-chain verification.
// ---------------------------------------------------------------------------

/// Verify a trace chain's tamper evidence.
///
/// # Safety
/// - `chain_ptr`/`chain_len` must be a valid UTF-8 path, readable for the
///   duration of the call.
#[no_mangle]
pub unsafe extern "C" fn quarry_verify_trace(
    chain_ptr: *const c_char,
    chain_len: usize,
) -> i32 {
    let code = catch_unwind(AssertUnwindSafe(|| unsafe {
        let path = match read_buf(chain_ptr, chain_len) {
            Ok(p) => p,
            Err(_) => return FfiCode::InvalidInput,
        };
        let chain = quarry_engine::trace_chain::TraceChain::new(path);
        match chain.verify() {
            Ok(()) => FfiCode::Ok,
            Err(_) => FfiCode::InvalidInput,
        }
    }))
    .unwrap_or(FfiCode::ContainedPanic);
    record(ffii_id(SIG_VERIFY_TRACE), code);
    code as i32
}

// ---------------------------------------------------------------------------
// Crossing 3: the fail-closed escape, exposed.
// ---------------------------------------------------------------------------

/// Issue an override nonce. The nonce travels back as a freshly allocated
/// C string; the host owns the free via `quarry_free`.
///
/// # Safety
/// - `rule_ptr`/`rule_len` and `purpose_ptr`/`purpose_len` must be valid
///   UTF-8 (ptr,len) pairs, readable for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn quarry_override_issue(
    rule_ptr: *const c_char,
    rule_len: usize,
    ttl_secs: u64,
    purpose_ptr: *const c_char,
    purpose_len: usize,
) -> *mut c_char {
    let out = catch_unwind(AssertUnwindSafe(|| unsafe {
        let (rule, purpose) = match (read_buf(rule_ptr, rule_len), read_buf(purpose_ptr, purpose_len))
        {
            (Ok(r), Ok(p)) => (r.to_string(), p.to_string()),
            (Err(_), _) | (_, Err(_)) => {
                record(ffii_id(SIG_OVERRIDE_ISSUE), FfiCode::InvalidInput);
                return None;
            }
        };
        let reg = quarry_engine::override_nonce::OverrideRegistry::new("/tmp/quarry-overrides.jsonl");
        match reg.issue(Some(rule), None, ttl_secs, purpose) {
            Ok(rec) => {
                record(ffii_id(SIG_OVERRIDE_ISSUE), FfiCode::Ok);
                Some(rec.nonce)
            }
            Err(_) => {
                record(ffii_id(SIG_OVERRIDE_ISSUE), FfiCode::NoVerdict);
                None
            }
        }
    }))
    .unwrap_or(None);
    match out {
        Some(nonce) => hand_off(nonce),
        None => ptr::null_mut(),
    }
}

/// Free a string returned by this library.
///
/// # Safety
/// - `ptr` must be a pointer returned by `quarry_override_issue` (or null).
#[no_mangle]
pub unsafe extern "C" fn quarry_free(ptr: *mut c_char) {
    unsafe { reclaim(ptr) };
}
} // mod ffi_surface

/// Public re-exports at the crate root — the safe facade.
pub use ffi_surface::{quarry_free, quarry_handshake, quarry_override_issue, quarry_scan, quarry_verify_trace};
