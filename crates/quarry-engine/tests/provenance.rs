//! Trace-provenance precondition: the scanner refuses unverified traces
//! (worry #5), and the refusal is NOT nonce-overridable.

use quarry_engine::{scan_source_with_options, ScanOptions};
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("qrs-prov-{}-{name}.jsonl", std::process::id()))
}

const RULE: &str = r#"rule "Any user text"
condition:
    any msg in user_messages where len(msg.content) > 0
"#;

const TRACE: &str = r#"{"messages":[{"role":"user","content":"hello"}]}"#;

#[test]
fn verified_trace_scans() {
    let chain_path = tmp("chain-ok");
    let chain = quarry_engine::trace_chain::TraceChain::new(&chain_path);
    chain.append("sess-ok", 0, TRACE.as_bytes(), Some(7_000), "interposer").unwrap();
    let conv: serde_json::Value = serde_json::from_str(TRACE).unwrap();
    let v = scan_source_with_options(
        RULE,
        &conv,
        &ScanOptions {
            trace_chain: Some(chain_path.clone()),
            session_id: Some("sess-ok".into()),
            trace_bytes: Some(TRACE.as_bytes().to_vec()),
            ..Default::default()
        },
    );
    assert!(matches!(v.status, quarry_core::ScanStatus::Complete));
    assert!(v.matched);
    // The capture point's event-time rode into the verdict.
    assert_eq!(v.timing.event_time_unix_ns, Some(7_000));
    std::fs::remove_file(chain_path).ok();
}

#[test]
fn unverified_trace_refuses_fail_closed() {
    let chain_path = tmp("chain-refuse");
    let conv: serde_json::Value = serde_json::from_str(TRACE).unwrap();
    // No chain record exists for these bytes.
    let v = scan_source_with_options(
        RULE,
        &conv,
        &ScanOptions {
            trace_chain: Some(chain_path.clone()),
            session_id: Some("sess-x".into()),
            trace_bytes: Some(TRACE.as_bytes().to_vec()),
            ..Default::default()
        },
    );
    assert!(matches!(v.status, quarry_core::ScanStatus::Invalid(_)));
    std::fs::remove_file(chain_path).ok();
}

#[test]
fn provenance_refusal_is_not_nonce_overridable() {
    let chain_path = tmp("chain-nonce");
    let store = tmp("store-nonce");
    let conv: serde_json::Value = serde_json::from_str(TRACE).unwrap();
    // Issue a nonce — it must NOT rescue an unproven trace.
    let reg = quarry_engine::override_nonce::OverrideRegistry::new(&store);
    let rec = reg.issue(None, None, 300, "should not apply").unwrap();
    let nonce = rec.nonce.clone();
    let v = scan_source_with_options(
        RULE,
        &conv,
        &ScanOptions {
            trace_chain: Some(chain_path.clone()),
            session_id: Some("sess-x".into()),
            trace_bytes: Some(TRACE.as_bytes().to_vec()),
            override_nonce: Some(nonce.clone()),
            override_store: Some(store.clone()),
            ..Default::default()
        },
    );
    assert!(matches!(v.status, quarry_core::ScanStatus::Invalid(_)));
    // The nonce was never spent.
    let spent = reg.check_and_consume(&nonce, "Any user text", "default");
    assert!(spent.is_ok(), "nonce must remain unconsumed");
    std::fs::remove_file(chain_path).ok();
    std::fs::remove_file(store).ok();
}
