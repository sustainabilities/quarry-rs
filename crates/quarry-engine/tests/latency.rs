//! Latency receipt: parse + compile + scan timings over the full corpus.
//! The estate way: receipts, not assertions.

use std::collections::BTreeMap;
use std::time::Instant;

use quarry_core::Conversation;
use quarry_engine::{compile, scan, EvalContext};

const RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/examples/rules/");

fn load_corpus_conv() -> (Conversation, serde_json::Value) {
    // A representative multi-turn conversation with tool calls.
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/examples/data/tool_calls.json"
    ))
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&src).unwrap();
    let conv: Conversation = serde_json::from_value(v.clone()).unwrap();
    (conv, v)
}

#[test]
fn latency_receipt() {
    let (conv, conv_json) = load_corpus_conv();

    // 1. Parse every corpus rule.
    let rule_files: Vec<_> = std::fs::read_dir(RULES_DIR)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "rule").unwrap_or(false))
        .collect();
    let t = Instant::now();
    let mut rules = Vec::new();
    for f in &rule_files {
        let src = std::fs::read_to_string(f.path()).unwrap();
        if let Ok(r) = quarry_dsl::parse_rule(&src) {
            rules.push(r);
        }
    }
    let parse_all = t.elapsed();

    // 2. Compile them all.
    let t = Instant::now();
    let compiled: Vec<_> = rules.iter().filter_map(|r| compile(r).ok()).collect();
    let compile_all = t.elapsed();

    // 3. Scan the conversation against every compiled rule.
    let t = Instant::now();
    let mut scans = 0usize;
    for _ in 0..100 {
        for rule in &compiled {
            let mut cx = EvalContext::new(&conv, BTreeMap::new());
            let trace = quarry_core::event_trace(&conv);
            let _ = quarry_engine::flow::eval_condition(&rule.condition, &trace, &mut cx);
            scans += 1;
        }
    }
    let scan_100 = t.elapsed();

    // 4. Single cold scan (parse + compile + scan one rule).
    let t = Instant::now();
    let src = std::fs::read_to_string(format!("{RULES_DIR}flow_after_within.rule")).unwrap();
    let _ = quarry_engine::scan_source(&src, &conv_json);
    let cold_single = t.elapsed();

    println!("=== quarry-rs latency receipt ===");
    println!(
        "parse  {} rules:        {:?}  ({:.1} µs/rule)",
        rules.len(),
        parse_all,
        parse_all.as_micros() as f64 / rules.len().max(1) as f64
    );
    println!(
        "compile {} rules:       {:?}  ({:.1} µs/rule)",
        compiled.len(),
        compile_all,
        compile_all.as_micros() as f64 / compiled.len().max(1) as f64
    );
    println!(
        "scan   {} rules ×100:   {:?}  ({:.2} µs/scan-all)",
        compiled.len(),
        scan_100,
        scan_100.as_micros() as f64 / 100.0
    );
    println!(
        "cold single rule (parse+compile+scan): {:?}",
        cold_single
    );
    println!("total scans executed: {scans}");
    let _ = conv_json;
}
