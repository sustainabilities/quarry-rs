//! The nonce law as a pure state machine — no I/O, machine-checkable.
//!
//! This is the trust core: the file-backed registry (`OverrideRegistry`)
//! is a thin persistence wrapper around [`NonceLedger`]. The ledger is what
//! Kani verifies; the wrapper is what the estate runs.
//!
//! Law (estate, 2026-11-16):
//! 1. A nonce is single-use — consumption is a one-way transition.
//! 2. A nonce is time-boxed — expired nonces never consume.
//! 3. A nonce is scope-bound — (rule, surface) must both cover.
//! 4. A nonce overrides *unavailability only* — it never flips a verdict;
//!    verdicts are facts, nonces are permissions to proceed without one.

use serde::{Deserialize, Serialize};

/// One nonce record. `consumed: Option<u64>` is the single-use state:
/// `None` = unconsumed, `Some(t)` = consumed at unix-time `t`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NonceRecord {
    pub nonce: String,
    /// `None` = covers every rule.
    pub rule: Option<String>,
    /// `None` = covers every surface.
    pub surface: Option<String>,
    pub issued: u64,
    pub expires: u64,
    pub purpose: String,
    pub consumed: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NonceError {
    NotFound,
    AlreadyConsumed(u64),
    Expired(u64),
    OutOfScope(String, String),
}

/// The pure ledger: ordered records, deterministic transitions.
#[derive(Debug, Clone, Default)]
pub struct NonceLedger {
    pub records: Vec<NonceRecord>,
}

impl NonceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue one nonce. `nonce_of` is the CSPRNG seam — the pure ledger is
    /// deterministic; randomness is injected.
    pub fn issue(
        &mut self,
        rule: Option<String>,
        surface: Option<String>,
        now: u64,
        ttl: u64,
        nonce_of: impl FnOnce() -> String,
        purpose: impl Into<String>,
    ) -> NonceRecord {
        let rec = NonceRecord {
            nonce: nonce_of(),
            rule,
            surface,
            issued: now,
            expires: now.saturating_add(ttl),
            purpose: purpose.into(),
            consumed: None,
        };
        self.records.push(rec.clone());
        rec
    }

    /// Check and consume — the single-use transition. Consumes iff the
    /// nonce exists, is unconsumed, unexpired (strictly), and in scope.
    pub fn check_and_consume(
        &mut self,
        nonce: &str,
        rule: &str,
        surface: &str,
        now: u64,
    ) -> Result<NonceRecord, NonceError> {
        let idx = self
            .records
            .iter()
            .position(|r| r.nonce == nonce)
            .ok_or(NonceError::NotFound)?;
        let rec = &mut self.records[idx];
        if let Some(t) = rec.consumed {
            return Err(NonceError::AlreadyConsumed(t));
        }
        if now >= rec.expires {
            return Err(NonceError::Expired(rec.expires));
        }
        if let Some(scope) = &rec.rule {
            if scope != rule {
                return Err(NonceError::OutOfScope(rule.into(), surface.into()));
            }
        }
        if let Some(scope) = &rec.surface {
            if scope != surface {
                return Err(NonceError::OutOfScope(rule.into(), surface.into()));
            }
        }
        rec.consumed = Some(now);
        Ok(rec.clone())
    }

    /// Every unconsumed, unexpired record — the shift-board view.
    pub fn outstanding(&self, now: u64) -> Vec<&NonceRecord> {
        self.records
            .iter()
            .filter(|r| r.consumed.is_none() && now < r.expires)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> String {
        "test-nonce-0001".into()
    }

    #[test]
    fn consume_twice_fails() {
        let mut l = NonceLedger::new();
        l.issue(Some("A".into()), None, 0, 100, rng, "t");
        assert!(l.check_and_consume("test-nonce-0001", "A", "surf", 50).is_ok());
        assert_eq!(
            l.check_and_consume("test-nonce-0001", "A", "surf", 60),
            Err(NonceError::AlreadyConsumed(50))
        );
    }

    #[test]
    fn expired_fails() {
        let mut l = NonceLedger::new();
        l.issue(None, None, 0, 10, rng, "t");
        assert_eq!(
            l.check_and_consume("test-nonce-0001", "A", "s", 11),
            Err(NonceError::Expired(10))
        );
    }

    #[test]
    fn scope_mismatch_fails() {
        let mut l = NonceLedger::new();
        l.issue(Some("A".into()), None, 0, 100, rng, "t");
        assert!(matches!(
            l.check_and_consume("test-nonce-0001", "B", "s", 50),
            Err(NonceError::OutOfScope(_, _))
        ));
    }

    #[test]
    fn unexpired_in_scope_succeeds() {
        let mut l = NonceLedger::new();
        l.issue(None, None, 0, 100, rng, "t");
        assert!(l.check_and_consume("test-nonce-0001", "A", "s", 99).is_ok());
    }
}
