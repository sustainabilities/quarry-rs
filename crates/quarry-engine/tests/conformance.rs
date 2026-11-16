//! P2 conformance gate: run the upstream corpus and compare outcomes.
//!
//! Two sources:
//! 1. `spec.json` language examples (backend-free): rule + matching/
//!    non-matching JSON pairs under `conformance/language-examples/`.
//! 2. The rule corpus: `conformance/examples/rules/X.rule` paired with
//!    `conformance/examples/data/X.json` (expect match) and
//!    `X.negative.json` (expect no match).
//!
//! Backend-requiring rules surface `ScanStatus::Incomplete` and are skipped
//! — the gate prints them; everything else must match expected outcomes.

use std::collections::BTreeMap;

use quarry_engine::scan_source;

const LANG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/language-examples/");
const RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/examples/rules/");
const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/examples/data/");

#[test]
fn spec_language_examples_conform() {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/spec.json")).expect("spec.json");
    let v: serde_json::Value = serde_json::from_str(&spec).expect("spec parses");
    let examples = v["examples"].as_array().expect("examples array");

    let mut passed = 0usize;
    let mut skipped = Vec::new();
    let mut failures = Vec::new();

    for ex in examples {
        if ex["requires_backend"].as_bool().unwrap_or(false) {
            continue;
        }
        let rule_path = ex["rule_path"].as_str().unwrap().trim_start_matches("examples/");
        let rule_src = std::fs::read_to_string(format!("{LANG_DIR}{rule_path}"))
            .unwrap_or_else(|e| panic!("rule {rule_path}: {e}"));
        for check in ex["checks"].as_array().expect("checks") {
            let input_path = check["input_path"].as_str().unwrap().trim_start_matches("examples/");
            let expected = check["expected_match"].as_bool().unwrap();
            let input = std::fs::read_to_string(format!("{LANG_DIR}{input_path}"))
                .unwrap_or_else(|e| panic!("input {input_path}: {e}"));
            let conv: serde_json::Value = serde_json::from_str(&input).expect("input parses");
            let verdict = scan_source(&rule_src, &conv);
            match verdict.status {
                quarry_core::ScanStatus::Complete => {
                    if verdict.matched == expected {
                        passed += 1;
                    } else {
                        failures.push(format!(
                            "{rule_path} vs {input_path}: expected match={expected}, got {}",
                            verdict.matched
                        ));
                    }
                }
                quarry_core::ScanStatus::Incomplete(reason) => {
                    skipped.push(format!("{rule_path}: {reason}"));
                }
                quarry_core::ScanStatus::Invalid(e) => {
                    failures.push(format!("{rule_path} vs {input_path}: invalid: {e}"));
                }
                quarry_core::ScanStatus::Overridden { .. } => {
                    skipped.push(format!("{rule_path}: overridden"));
                }
            }
        }
    }

    println!("spec language examples: {passed} passed, {} skipped (backend)", skipped.len());
    for s in &skipped {
        println!("  SKIPPED {s}");
    }
    assert!(failures.is_empty(), "conformance failures:\n{}", failures.join("\n"));
}

#[test]
fn rule_corpus_conforms() {
    let mut passed = 0usize;
    let mut skipped = Vec::new();
    let mut failures = Vec::new();
    let mut checked_rules = 0usize;

    let entries = std::fs::read_dir(RULES_DIR).expect("rules dir");
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().map(|x| x != "rule").unwrap_or(true) {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        let rule_src = std::fs::read_to_string(&path).expect("rule reads");
        for (suffix, expected) in [("", true), (".negative", false)] {
            let data_path = format!("{DATA_DIR}{stem}{suffix}.json");
            let Ok(input) = std::fs::read_to_string(&data_path) else {
                continue;
            };
            checked_rules += 1;
            let conv: serde_json::Value = serde_json::from_str(&input).expect("input parses");
            let verdict = scan_source(&rule_src, &conv);
            match verdict.status {
                quarry_core::ScanStatus::Complete => {
                    if verdict.matched == expected {
                        passed += 1;
                    } else {
                        failures.push(format!(
                            "{stem}{suffix}.json: expected match={expected}, got {}",
                            verdict.matched
                        ));
                    }
                }
                quarry_core::ScanStatus::Incomplete(reason) => {
                    skipped.push(format!("{stem}{suffix}: {reason}"));
                }
                quarry_core::ScanStatus::Invalid(e) => {
                    failures.push(format!("{stem}{suffix}.json: invalid: {e}"));
                }
                quarry_core::ScanStatus::Overridden { .. } => {
                    skipped.push(format!("{stem}{suffix}: overridden"));
                }
            }
        }
    }

    println!(
        "rule corpus: {passed}/{checked_rules} checks passed, {} skipped (backend)",
        skipped.len()
    );
    for s in &skipped {
        println!("  SKIPPED {s}");
    }
    assert!(failures.is_empty(), "conformance failures:\n{}", failures.join("\n"));
}

#[test]
fn scan_api_smoke() {
    use quarry_core::Conversation;
    let rule = r#"rule "Shell call"
strings:
    $needle = "shell"
condition:
    any call in tool_calls where call.name == "shell"
"#;
    let conv = Conversation {
        messages: vec![quarry_core::Message {
            role: quarry_core::Role::Assistant,
            content: String::new(),
            tool_calls: vec![quarry_core::ToolCall {
                id: "c1".into(),
                name: "shell".into(),
                arguments: serde_json::json!({"cmd": "ls"}),
            }],
            tool_call_id: None,
        }],
        tool_definitions: vec![],
    };
    let conv_json = serde_json::to_value(&conv).unwrap();
    let v = scan_source(rule, &conv_json);
    assert!(matches!(v.status, quarry_core::ScanStatus::Complete));
    assert!(v.matched);
}
