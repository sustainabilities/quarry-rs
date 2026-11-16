//! Fail-closed override nonces — the controlled break-glass.
//!
//! Law (estate, 2026-11-16): enforcement surfaces are fail-closed — no
//! authoritative verdict ⇒ no bypass. A nonce is the *only* escape, and it
//! overrides **unavailability only**: an `Incomplete` scan may proceed under
//! a receipted override; a verdict (match/no-match) is never flipped.
//!
//! Registry: a JSONL ledger (one record per line, estate ledger pattern —
//! cf. estate-registry.jsonl, harbor-watch shift logs). Nonces are 256-bit
//! random from the OS CSPRNG (`/dev/urandom`), single-use, time-boxed, and
//! scope-bound to (rule, surface). Consumption is receipted in place; the
//! host should also mirror consumption events into Tymelyne.
//!
//! Trust note (honesty class): the registry file is a trusted application
//! input — it lives inside the estate's file-permission boundary, like the
//! rule config itself. A future PQ vector can replace file trust with signed
//! nonces (HMAC/estate key) without changing this API.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceRecord {
    pub nonce: String,
    /// `None` = covers every rule.
    pub rule: Option<String>,
    /// `None` = covers every surface (host-assigned surface id).
    pub surface: Option<String>,
    pub issued: u64,
    pub expires: u64,
    pub purpose: String,
    /// Consumption receipt: unix secs when spent. Single-use.
    pub consumed: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum OverrideError {
    #[error("nonce not found")]
    NotFound,
    #[error("nonce already consumed at {0}")]
    AlreadyConsumed(u64),
    #[error("nonce expired at {0}")]
    Expired(u64),
    #[error("nonce does not cover rule `{0}` / surface `{1}`")]
    OutOfScope(String, String),
    #[error("registry io: {0}")]
    Io(String),
}

pub struct OverrideRegistry {
    path: PathBuf,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 256 bits from the OS CSPRNG, hex-encoded.
fn fresh_nonce() -> Result<String, OverrideError> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| OverrideError::Io(format!("cannot open /dev/urandom: {e}")))?;
    f.read_exact(&mut buf)
        .map_err(|e| OverrideError::Io(format!("cannot read /dev/urandom: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

impl OverrideRegistry {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    fn read_all(&self) -> Result<Vec<NonceRecord>, OverrideError> {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(OverrideError::Io(e.to_string())),
        };
        Ok(data
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    fn write_all(&self, records: &[NonceRecord]) -> Result<(), OverrideError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| OverrideError::Io(e.to_string()))?;
        }
        let mut f = std::fs::File::create(&self.path)
            .map_err(|e| OverrideError::Io(e.to_string()))?;
        for r in records {
            let line = serde_json::to_string(r).map_err(|e| OverrideError::Io(e.to_string()))?;
            writeln!(f, "{line}").map_err(|e| OverrideError::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// Issue a nonce. Returns the record (with its nonce) for handoff.
    pub fn issue(
        &self,
        rule: Option<String>,
        surface: Option<String>,
        ttl_secs: u64,
        purpose: impl Into<String>,
    ) -> Result<NonceRecord, OverrideError> {
        let t = now();
        let record = NonceRecord {
            nonce: fresh_nonce()?,
            rule,
            surface,
            issued: t,
            expires: t + ttl_secs,
            purpose: purpose.into(),
            consumed: None,
        };
        let mut all = self.read_all()?;
        all.push(record.clone());
        self.write_all(&all)?;
        Ok(record)
    }

    /// Check a nonce against (rule, surface) and consume it — single use.
    /// On success returns the receipted record.
    pub fn check_and_consume(
        &self,
        nonce: &str,
        rule: &str,
        surface: &str,
    ) -> Result<NonceRecord, OverrideError> {
        let mut all = self.read_all()?;
        let t = now();
        let idx = all
            .iter()
            .position(|r| r.nonce == nonce)
            .ok_or(OverrideError::NotFound)?;
        let record = &all[idx];
        if let Some(c) = record.consumed {
            return Err(OverrideError::AlreadyConsumed(c));
        }
        if t >= record.expires {
            return Err(OverrideError::Expired(record.expires));
        }
        if let Some(scope) = &record.rule {
            if scope != rule {
                return Err(OverrideError::OutOfScope(rule.into(), surface.into()));
            }
        }
        if let Some(scope) = &record.surface {
            if scope != surface {
                return Err(OverrideError::OutOfScope(rule.into(), surface.into()));
            }
        }
        all[idx].consumed = Some(t);
        self.write_all(&all)?;
        Ok(all[idx].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_registry() -> OverrideRegistry {
        // Unique per call: tests run in parallel in one process.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "qrs-override-test-{}-{n}.jsonl",
            std::process::id()
        ));
        OverrideRegistry::new(path)
    }

    #[test]
    fn issue_consume_once() {
        let reg = tmp_registry();
        let rec = reg
            .issue(Some("Read then send".into()), None, 300, "maintenance window")
            .unwrap();
        // First use: valid.
        let spent = reg
            .check_and_consume(&rec.nonce, "Read then send", "helm")
            .unwrap();
        assert!(spent.consumed.is_some());
        // Second use: rejected — single use.
        assert!(matches!(
            reg.check_and_consume(&rec.nonce, "Read then send", "helm"),
            Err(OverrideError::AlreadyConsumed(_))
        ));
    }

    #[test]
    fn scope_is_enforced() {
        let reg = tmp_registry();
        let rec = reg
            .issue(Some("Rule A".into()), None, 300, "scoped")
            .unwrap();
        assert!(matches!(
            reg.check_and_consume(&rec.nonce, "Rule B", "helm"),
            Err(OverrideError::OutOfScope(_, _))
        ));
    }

    #[test]
    fn expiry_is_enforced() {
        let reg = tmp_registry();
        let rec = reg.issue(None, None, 0, "instant").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(matches!(
            reg.check_and_consume(&rec.nonce, "any", "any"),
            Err(OverrideError::Expired(_))
        ));
    }

    #[test]
    fn nonces_are_unique_and_unguessable() {
        let reg = tmp_registry();
        let a = reg.issue(None, None, 60, "a").unwrap();
        let b = reg.issue(None, None, 60, "b").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(a.nonce.len(), 64); // 256-bit hex
    }
}
