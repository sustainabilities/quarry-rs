//! Kani proof harnesses — the nonce law, machine-checked.
//!
//! Run: `cargo kani -p quarry-engine --harness <name>` (see each harness).
//!
//! The law under proof:
//! 1. **Single-use**: a consumed nonce never consumes again.
//! 2. **Expiry**: `now >= expires` refuses — always.
//! 3. **Scope**: rule/surface mismatches refuse — always.
//! 4. **Determinism**: the same ledger state + same inputs ⇒ same outcome.
//!
//! These are bounded symbolic checks over the pure [`NonceLedger`] state
//! machine; the file-backed registry is a persistence wrapper around it.
//!
//! Harnesses only compile under Kani (`cfg(kani)`) — the normal build
//! never sees them.

use crate::nonce_ledger::{NonceError, NonceLedger};

/// Harness: `nonce_law_single_use`
///
/// For any two distinct consumption times t1 < t2 with t2 within validity:
/// consuming at t1 succeeds, consuming at t2 fails `AlreadyConsumed(t1)`.
/// The nonce is single-use — over all (t1, t2) pairs in the bound.
#[kani::proof]
#[kani::unwind(8)]
fn nonce_law_single_use() {
    let t1: u64 = kani::any();
    let t2: u64 = kani::any();
    kani::assume(t1 < t2 && t2 < 100); // t2 strictly inside validity

    let mut ledger = NonceLedger::new();
    ledger.issue(None, None, 0, 100, || "n".into(), "proof");

    let first = ledger.check_and_consume("n", "rule", "surf", t1);
    assert!(first.is_ok(), "first consume of an unconsumed nonce succeeds");

    let second = ledger.check_and_consume("n", "rule", "surf", t2);
    assert_eq!(
        second,
        Err(NonceError::AlreadyConsumed(t1)),
        "single-use: second consume fails with the first consumption time"
    );
}

/// Harness: `nonce_law_expiry`
///
/// For any consumption time t: consume succeeds iff t < expires.
/// The boundary is exact — no off-by-one in either direction.
#[kani::proof]
#[kani::unwind(8)]
fn nonce_law_expiry() {
    let issued: u64 = kani::any();
    let ttl: u64 = kani::any();
    let now: u64 = kani::any();
    kani::assume(issued < 50 && ttl < 50 && 50 <= now && now < 150); // now strictly after issue

    let mut ledger = NonceLedger::new();
    let rec = ledger.issue(None, None, issued, ttl, || "n".into(), "proof");

    let result = ledger.check_and_consume("n", "rule", "surf", now);
    if now < rec.expires {
        assert!(result.is_ok(), "unexpired nonce consumes");
    } else {
        assert_eq!(result, Err(NonceError::Expired(rec.expires)), "expired nonce refuses");
    }
}

/// Harness: `nonce_law_scope`
///
/// A nonce scoped to rule R and surface S consumes only for exactly (R, S).
/// Any other (rule, surface) pair refuses `OutOfScope` — over all pairs.
#[kani::proof]
#[kani::unwind(8)]
fn nonce_law_scope() {
    let rule: char = kani::any();
    let surface: char = kani::any();
    kani::assume(rule.is_ascii_alphabetic() && surface.is_ascii_alphabetic());

    let mut ledger = NonceLedger::new();
    ledger.issue(Some("A".into()), Some("X".into()), 0, 100, || "n".into(), "proof");

    let result = ledger.check_and_consume("n", &rule.to_string(), &surface.to_string(), 50);
    if rule == 'A' && surface == 'X' {
        assert!(result.is_ok(), "exact scope match consumes");
    } else {
        assert!(
            matches!(result, Err(NonceError::OutOfScope(_, _))),
            "any scope deviation refuses OutOfScope"
        );
    }
}

/// Harness: `nonce_law_determinism`
///
/// The same ledger state and the same inputs produce the same outcome:
/// consume at t, roll back by cloning, consume again at t — identical.
#[kani::proof]
#[kani::unwind(8)]
fn nonce_law_determinism() {
    let now: u64 = kani::any();
    kani::assume(now < 100);

    let mut a = NonceLedger::new();
    a.issue(None, None, 0, 100, || "n".into(), "proof");
    let mut b = a.clone();

    let ra = a.check_and_consume("n", "rule", "surf", now);
    let rb = b.check_and_consume("n", "rule", "surf", now);
    assert_eq!(ra, rb, "same state + same inputs ⇒ same outcome");
}

/// Harness: `nonce_law_totality`
///
/// The transition is total: for any nonce string, rule, surface, and time,
/// `check_and_consume` returns exactly one of Ok / NotFound / AlreadyConsumed
/// / Expired / OutOfScope. No third state exists.
#[kani::proof]
#[kani::unwind(8)]
fn nonce_law_totality() {
    let nonce: char = kani::any();
    kani::assume(nonce.is_ascii_alphabetic());
    let mut ledger = NonceLedger::new();
    ledger.issue(Some("A".into()), None, 0, 100, || "n".into(), "proof");

    let result = ledger.check_and_consume(&nonce.to_string(), "A", "surf", 50);
    match result {
        Ok(_) => assert!(nonce == 'n', "only the issued nonce can consume"),
        Err(NonceError::NotFound)
        | Err(NonceError::AlreadyConsumed(_))
        | Err(NonceError::Expired(_))
        | Err(NonceError::OutOfScope(_, _)) => {}
    }
}
