//! Conformance tests: parse real rules from the upstream example corpus
//! (`conformance/examples/rules/`). These are the same fixtures Quarry's own
//! conformance suite scans with expected match/non-match outcomes — once the
//! DFA engine lands (P2/P3), the same fixtures drive behavioral conformance.

use quarry_dsl::parse_rule;

fn rule_src(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/examples/rules/");
    std::fs::read_to_string(format!("{path}{name}.rule"))
        .unwrap_or_else(|e| panic!("fixture {name}.rule: {e}"))
}

fn language_example_src(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/language-examples/");
    std::fs::read_to_string(format!("{path}{name}.rule"))
        .unwrap_or_else(|e| panic!("fixture {name}.rule: {e}"))
}

#[test]
fn parses_capture_rule() {
    let rule = parse_rule(&language_example_src("capture")).expect("capture.rule parses");
    assert!(!rule.name.is_empty());
}

#[test]
fn parses_flow_operator_family() {
    for name in [
        "flow_after",
        "flow_after_within",
        "flow_before",
        "flow_before_within",
        "flow_right_after",
        "flow_right_before",
        "flow_until",
    ] {
        let rule = parse_rule(&rule_src(name))
            .unwrap_or_else(|e| panic!("{name}.rule: {e}"));
        assert!(!rule.name.is_empty(), "{name}");
    }
}

#[test]
fn parses_comprehension_family() {
    for name in [
        "all_comprehension",
        "filter_comprehension",
        "filter_count",
        "tool_name_comprehension",
    ] {
        let rule = parse_rule(&rule_src(name))
            .unwrap_or_else(|e| panic!("{name}.rule: {e}"));
        assert!(!rule.name.is_empty(), "{name}");
    }
}

#[test]
fn parses_string_modifier_family() {
    for name in ["base64", "fullword", "case-insensitive-match", "regex-match"] {
        if rule_src_exists(name) {
            let rule = parse_rule(&rule_src(name))
                .unwrap_or_else(|e| panic!("{name}.rule: {e}"));
            assert!(!rule.name.is_empty(), "{name}");
        }
    }
}

#[test]
fn parses_tool_surface_family() {
    for name in [
        "call_sequence",
        "called_tools",
        "count_tool_calls",
        "get_tool_calls",
        "get_tool_responses",
        "has_tool",
        "has_tools",
        "has_sequence",
    ] {
        if rule_src_exists(name) {
            let rule = parse_rule(&rule_src(name))
                .unwrap_or_else(|e| panic!("{name}.rule: {e}"));
            assert!(!rule.name.is_empty(), "{name}");
        }
    }
}

#[test]
fn parses_model_inference_family() {
    for name in ["model-score", "model-classify", "model-complete", "text-ref"] {
        if rule_src_exists(name) {
            let rule = parse_rule(&rule_src(name))
                .unwrap_or_else(|e| panic!("{name}.rule: {e}"));
            assert!(!rule.name.is_empty(), "{name}");
        }
    }
}

/// Sweep: every rule in the corpus must parse. This is the P1 exit gate.
#[test]
fn parses_entire_conformance_corpus() {
    let dirs = [
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/examples/rules/"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/language-examples/"),
    ];
    let mut parsed = 0usize;
    let mut failures = Vec::new();
    for dir in dirs {
        let mut entries = std::fs::read_dir(dir)
            .expect("conformance rules dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "rule").unwrap_or(false));
        for entry in &mut entries {
            let src = std::fs::read_to_string(entry.path()).expect("read rule");
            let name = entry.file_name().to_string_lossy().into_owned();
            match parse_rule(&src) {
                Ok(_) => parsed += 1,
                Err(e) => failures.push(format!("{name}: {e}")),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{}/{} parsed; failures:\n{}",
        parsed,
        parsed + failures.len(),
        failures.join("\n")
    );
}

fn rule_src_exists(name: &str) -> bool {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/examples/rules/");
    std::path::Path::new(&format!("{path}{name}.rule")).exists()
}
