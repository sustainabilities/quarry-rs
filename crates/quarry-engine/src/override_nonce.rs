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

pub use crate::nonce_ledger::{NonceError, NonceLedger, NonceRecord};

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

/// A nonce may name files — it must be inert before it touches a path.
fn is_inert_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= 128
        && nonce
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
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
        let mut ledger = NonceLedger {
            records: self.read_all()?,
        };
        let rec = ledger.issue(rule, surface, now(), ttl_secs, || match fresh_nonce() {
            Ok(n) => n,
            Err(e) => {
                // The CSPRNG failed; the estate law is fail-closed.
                panic!("nonce source unavailable: {e}")
            }
        }, purpose);
        self.write_all(&ledger.records)?;
        Ok(rec)
    }

    /// Atomically claim a nonce on disk — the cross-process single-use
    /// arbiter. `create_new` (O_EXCL) is atomic on POSIX: exactly one
    /// process ever wins the claim, so the single-use law holds across
    /// processes, not just within one. The claim file doubles as the
    /// consumption receipt.
    fn claim(&self, nonce: &str, rule: &str, surface: &str) -> Result<(), OverrideError> {
        // Defense in depth: the nonce names a file — it must be inert.
        if !is_inert_nonce(nonce) {
            return Err(OverrideError::NotFound);
        }
        let claim_path = self.claim_dir().join(format!("{nonce}.claim"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&claim_path)
        {
            Ok(mut f) => {
                use std::io::Write;
                let t = now();
                writeln!(
                    f,
                    "{{\"nonce\":\"{nonce}\",\"rule\":\"{rule}\",\"surface\":\"{surface}\",\"consumed_at\":{t}}}"
                )
                .map_err(|e| OverrideError::Io(e.to_string()))?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(OverrideError::AlreadyConsumed(now()))
            }
            Err(e) => Err(OverrideError::Io(e.to_string())),
        }
    }

    fn claim_dir(&self) -> std::path::PathBuf {
        self.path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    }

    /// Check a nonce against (rule, surface) and consume it — single use,
    /// enforced ACROSS processes: the O_EXCL claim happens first; only the
    /// claim winner proceeds to the ledger transition.
    pub fn check_and_consume(
        &self,
        nonce: &str,
        rule: &str,
        surface: &str,
    ) -> Result<NonceRecord, OverrideError> {
        // The claim IS the consumption decision: lose the race, lose the
        // nonce — before any ledger state is read or written.
        self.claim(nonce, rule, surface)?;
        let mut ledger = NonceLedger {
            records: self.read_all()?,
        };
        let rec = ledger
            .check_and_consume(nonce, rule, surface, now())
            .map_err(|e| match e {
                crate::nonce_ledger::NonceError::NotFound => OverrideError::NotFound,
                crate::nonce_ledger::NonceError::AlreadyConsumed(t) => {
                    OverrideError::AlreadyConsumed(t)
                }
                crate::nonce_ledger::NonceError::Expired(t) => OverrideError::Expired(t),
                crate::nonce_ledger::NonceError::OutOfScope(r, s) => {
                    OverrideError::OutOfScope(r, s)
                }
            })?;
        self.write_all(&ledger.records)?;
        Ok(rec)
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

#[cfg(test)]
mod cross_process_tests {
    use super::*;

    /// The child: attempt the atomic claim on the store named by
    /// QRS_RACE_STORE; write WON/LOST to the file named by QRS_RACE_OUT.
    /// Runs as a separate OS process (the test binary re-executed with
    /// `--exact race_child_consumer`).
    #[test]
    fn race_child_consumer() {
        let Ok(store) = std::env::var("QRS_RACE_STORE") else {
            return; // not in child mode — no-op
        };
        let Ok(out) = std::env::var("QRS_RACE_OUT") else {
            return;
        };
        let reg = OverrideRegistry::new(&store);
        let nonce = std::env::var("QRS_NONCE").unwrap_or_default();
        let outcome = match reg.check_and_consume(&nonce, "r", "s") {
            Ok(_) => "WON",
            Err(OverrideError::AlreadyConsumed(_)) => "LOST",
            Err(_) => "ERROR",
        };
        std::fs::write(out, outcome).unwrap();
    }

    /// THE LAW, cross-process: two OS processes race to consume one nonce;
    /// the O_EXCL claim on disk decides; exactly one wins. This is the
    /// property the in-process Kani proof cannot see.
    #[test]
    fn single_use_holds_across_processes() {
        use std::process::Command;

        let dir = std::env::temp_dir().join(format!(
            "qrs-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("race.jsonl");
        let reg = OverrideRegistry::new(&store);
        // Issue exactly once (the parent process); the nonce value travels
        // to the children via env — they race for its single consumption.
        let rec = reg.issue(Some("r".into()), None, 3600, "race").unwrap();

        let exe = std::env::current_exe().unwrap();
        let mut outcomes = Vec::new();
        let mut children = Vec::new();
        for i in 0..2 {
            let out_path = dir.join(format!("out-{i}.txt"));
            let child = Command::new(&exe)
                .args(["--exact", "override_nonce::cross_process_tests::race_child_consumer", "--nocapture"])
                .env("QRS_RACE_STORE", &store)
                .env("QRS_NONCE", &rec.nonce)
                .env("QRS_RACE_OUT", &out_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn();
            if let Ok(c) = child {
                children.push((c, out_path));
            }
        }
        for (mut c, out_path) in children {
            c.wait().expect("child finishes");
            if let Ok(o) = std::fs::read_to_string(&out_path) {
                outcomes.push(o.trim().to_string());
            }
        }
        // THE ASSERTION: exactly one WON.
        outcomes.sort();
        assert_eq!(
            outcomes,
            vec!["LOST".to_string(), "WON".to_string()],
            "single-use violated across processes: outcomes were {outcomes:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
