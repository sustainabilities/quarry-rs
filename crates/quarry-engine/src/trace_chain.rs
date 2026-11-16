//! Trace provenance chain — the scan precondition for worry #5.
//!
//! "An agent that can edit or truncate its own traces defeats the detector
//! by construction." The defense: traces are captured at the interposer /
//! runtime boundary and appended to a **hash chain** (the harbor-watch
//! shift-log pattern). The scanner verifies the chain and the trace hash
//! BEFORE scanning, and refuses unverified traces (fail-closed).
//!
//! No datum is innocent, including the log — so the chain itself is
//! tamper-evident: each record commits to the previous record's hash, and
//! the trace's sha512. A capture point that is not the interposer is
//! honestly labeled in the record's `captured_by` and surfaced in receipts.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha512};

/// sha512 hex digest over bytes (the `sha2` crate — standard, audited).
fn sha512_hex(data: &[u8]) -> String {
    let mut h = Sha512::new();
    h.update(data);
    let out = h.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// Estate time laws (IGN v1.y and friends) live in the estate integration
/// layer, not in the public core. The core stamps unix nanoseconds.

/// One appended trace record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Session identity binding across trace chunks (worry #5: an attack
    /// split across two trace files must be linkable).
    pub session_id: String,
    /// Sequence of this chunk within the session.
    pub chunk: u64,
    /// sha512 of the exact trace bytes scanned.
    pub trace_sha512: String,
    /// Event-time of the newest message, as stamped by the capture point
    /// (unix ns). `None` when the capture point did not stamp it — never
    /// fabricated.
    pub event_time_unix_ns: Option<u128>,
    /// Append-time stamp (unix ns), honesty-classed.
    pub stamp_ns: u128,
    pub clock_honesty: String,
    /// What captured the trace — "interposer" is the trusted class;
    /// anything else is honestly labeled (e.g. "agent-self-report").
    pub captured_by: String,
    /// sha512 of the previous record's canonical line (chain linkage).
    pub prev_hash: String,
    /// sha512 of this record's canonical form (without `hash`).
    pub hash: String,
}

/// A JSONL hash chain of trace records.
pub struct TraceChain {
    path: PathBuf,
}

fn now_unix_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

impl TraceChain {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Canonical hashing form: the record with `hash` empty.
    fn canonical(rec: &TraceRecord) -> String {
        let mut c = rec.clone();
        c.hash = String::new();
        serde_json::to_string(&c).unwrap_or_default()
    }

    fn read_all(&self) -> Result<Vec<TraceRecord>, String> {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.to_string()),
        };
        Ok(data
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    /// Append one record, chained to the current head.
    pub fn append(
        &self,
        session_id: &str,
        chunk: u64,
        trace_bytes: &[u8],
        event_time_unix_ns: Option<u128>,
        captured_by: &str,
    ) -> Result<TraceRecord, String> {
        let all = self.read_all()?;
        let prev_hash = all
            .last()
            .map(|r| r.hash.clone())
            .unwrap_or_else(|| "0".repeat(128));
        let trace_sha512 = sha512_hex(trace_bytes);
        let mut rec = TraceRecord {
            session_id: session_id.to_string(),
            chunk,
            trace_sha512,
            event_time_unix_ns,
            stamp_ns: now_unix_ns(),
            clock_honesty: "unlocked".into(),
            captured_by: captured_by.to_string(),
            prev_hash,
            hash: String::new(),
        };
        rec.hash = sha512_hex(Self::canonical(&rec).as_bytes());
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        writeln!(f, "{}", serde_json::to_string(&rec).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(rec)
    }

    /// Verify the whole chain: linkage + per-record hashes.
    pub fn verify(&self) -> Result<(), String> {
        let all = self.read_all()?;
        let mut prev = "0".repeat(128);
        for (i, rec) in all.iter().enumerate() {
            if rec.prev_hash != prev {
                return Err(format!("record {i}: chain break (prev_hash mismatch)"));
            }
            let expect = sha512_hex(Self::canonical(rec).as_bytes());
            if rec.hash != expect {
                return Err(format!(
                    "record {i}: hash mismatch (record edited after append)"
                ));
            }
            prev = rec.hash.clone();
        }
        Ok(())
    }

    /// Verify a trace against the chain: the bytes must hash to a record
    /// that is chain-valid and session-bound. This is the scan precondition.
    pub fn verify_trace(
        &self,
        trace_bytes: &[u8],
        session_id: &str,
    ) -> Result<TraceRecord, String> {
        self.verify()?;
        let hash = sha512_hex(trace_bytes);
        self.read_all()?
            .into_iter()
            .find(|r| r.trace_sha512 == hash && r.session_id == session_id)
            .ok_or_else(|| {
                "trace not chain-verified: hash not found in session's chain (refusing to scan)"
                    .into()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_chain() -> TraceChain {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        TraceChain::new(
            std::env::temp_dir()
                .join(format!("qrs-chain-test-{}-{n}.jsonl", std::process::id())),
        )
    }

    #[test]
    fn chain_appends_and_verifies() {
        let chain = tmp_chain();
        let t1 = br#"{"messages":[]}"#;
        let t2 = br#"{"messages":[{"role":"user","content":"x"}]}"#;
        let r1 = chain.append("sess-1", 0, t1, Some(1_000), "interposer").unwrap();
        let r2 = chain.append("sess-1", 1, t2, Some(2_000), "interposer").unwrap();
        assert_eq!(r2.prev_hash, r1.hash);
        chain.verify().expect("chain intact");
        // Both traces verify against their session.
        chain.verify_trace(t1, "sess-1").expect("trace 1 verified");
        chain.verify_trace(t2, "sess-1").expect("trace 2 verified");
    }

    #[test]
    fn edited_trace_refuses() {
        let chain = tmp_chain();
        let t1 = br#"{"messages":[]}"#;
        chain.append("sess-2", 0, t1, None, "interposer").unwrap();
        // The agent edits its own trace after the fact.
        let edited = br#"{"messages":[{"role":"user","content":"nothing happened"}]}"#;
        assert!(chain.verify_trace(edited, "sess-2").is_err());
    }

    #[test]
    fn tampered_record_breaks_the_chain() {
        let chain = tmp_chain();
        chain.append("sess-3", 0, b"a", None, "interposer").unwrap();
        chain.append("sess-3", 1, b"b", None, "interposer").unwrap();
        // Tamper with record 0's captured_by in the file.
        let path = &chain.path;
        let data = std::fs::read_to_string(path).unwrap();
        let tampered = data.replace("interposer", "agent-self-report");
        std::fs::write(path, tampered).unwrap();
        assert!(chain.verify().is_err());
    }

    #[test]
    fn session_binding_is_enforced() {
        let chain = tmp_chain();
        let t1 = b"trace-bytes";
        chain.append("sess-A", 0, t1, None, "interposer").unwrap();
        // Same bytes claimed under a different session: refused.
        assert!(chain.verify_trace(t1, "sess-B").is_err());
    }

    #[test]
    fn sha512_known_vectors() {
        // The chain is only as good as the hash; the implementation must
        // pass the FIPS vectors.
        assert_eq!(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            sha512_hex(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }
}
