//! Rung-2 verification per the Foundry's ratified policy: the parser and
//! the evaluator eat untrusted content, so they get fuzzed. This is a
//! deterministic structure-aware fuzzer that runs on stable Rust (cargo-fuzz
//! + libFuzzer is the follow-on; harness semantics stay identical).
//!
//! Invariants under mutation:
//! 1. `parse_rule` never panics — only `ParseError`/`LexError`.
//! 2. Compilation never panics.
//! 3. Scanning never panics and always returns a verdict.
//! 4. Determinism: the same input produces the same verdict twice.

use quarry_engine::{scan_source, ScanOptions};

/// xorshift64* — deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next() % n as u64) as usize
    }
}

const SEEDS: [&str; 6] = [
    r#"rule "t"
condition:
    any msg in user_messages where msg.content contains "x"
"#,
    r#"rule "s"
strings:
    $a = "admin" nocase fullword
    $b = ["x", "y"] base64
condition:
    any msg in user_messages where $a in msg.content or 2 of ($b*) in msg.content
"#,
    r#"rule "f"
condition:
    called_tool("send") after(within: 3) called_tool("read")
"#,
    r#"rule "c"
parameters:
    threshold : number policy
condition:
    (len(messages) as n and n >= 3) and
    [m for m in messages if m.role == "user"]
"#,
    r#"rule "p"
condition:
    any tool in tools where tool matches { name == "read" or description contains "file" }
"#,
    r#"rule "w"
condition:
    user_said("wait") until assistant_said("done")
"#,
];

const MUTATORS: usize = 5;

fn mutate(rng: &mut Rng, src: &str) -> String {
    let mut bytes: Vec<u8> = src.bytes().collect();
    match rng.below(MUTATORS) {
        // delete a span
        0 => {
            if bytes.len() > 4 {
                let a = rng.below(bytes.len());
                let b = (a + 1 + rng.below(bytes.len() - a - 1)).min(bytes.len());
                bytes.drain(a..b);
            }
        }
        // duplicate a span
        1 => {
            if bytes.len() > 4 {
                let a = rng.below(bytes.len());
                let b = (a + 1 + rng.below(bytes.len() - a - 1)).min(bytes.len());
                let slice: Vec<u8> = bytes[a..b].to_vec();
                bytes.splice(a..a, slice);
            }
        }
        // substitute random bytes
        2 => {
            for _ in 0..1 + rng.below(8) {
                if !bytes.is_empty() {
                    let i = rng.below(bytes.len());
                    bytes[i] = (rng.next() % 256) as u8;
                }
            }
        }
        // splice in random bytes
        3 => {
            let i = rng.below(bytes.len() + 1);
            let n = rng.below(32);
            for k in 0..n {
                bytes.insert((i + k).min(bytes.len()), (rng.next() % 96) as u8 + 32);
            }
        }
        // truncate
        _ => {
            let keep = rng.below(bytes.len() + 1);
            bytes.truncate(keep);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn parser_fuzz_never_panics_and_is_deterministic() {
    let mut rng = Rng(0x5EED_2026_1116_0001);
    let conv: serde_json::Value = serde_json::from_str(
        r#"{"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"hi","tool_calls":[{"id":"c1","type":"function","function":{"name":"read","arguments":"{}"}}]}]}"#,
    )
    .unwrap();

    for round in 0..20_000 {
        let seed = SEEDS[round % SEEDS.len()];
        let mutated = mutate(&mut rng, seed);

        // 1+3: parse/compile/scan never panic; every outcome is a verdict.
        let v1 = scan_source(&mutated, &conv);
        // 4: determinism — same input, same verdict.
        let v2 = scan_source(&mutated, &conv);
        assert_eq!(
            v1.matched, v2.matched,
            "nondeterministic verdict at round {round}"
        );
        assert_eq!(format!("{:?}", v1.status), format!("{:?}", v2.status));
        let _ = ScanOptions::default();
    }
}

#[test]
fn evaluator_fuzz_never_panics_on_hostile_traces() {
    // Hostile conversations: deep nesting, huge strings, weird roles.
    let mut rng = Rng(0xBEEF_2026_1116_0002);
    let rules: Vec<String> = SEEDS.iter().map(|s| s.to_string()).collect();
    for round in 0..5_000 {
        let depth = 1 + rng.below(8);
        let mut conv = String::from("{\"messages\":[");
        for i in 0..depth {
            let role = ["user", "assistant", "system", "tool", "developer"][rng.below(5)];
            let len = rng.below(2_000);
            let content: String = (0..len).map(|_| (rng.next() % 96) as u8 as char).collect();
            conv.push_str(&format!(
                "{{\"role\":\"{role}\",\"content\":\"{}\"{}",
                content.replace('\\', "").replace('"', "'"),
                if role == "tool" { ",\"tool_call_id\":\"c1\"}" } else { "}" }
            ));
            if i + 1 < depth {
                conv.push(',');
            }
        }
        conv.push_str("]}");
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&conv) else {
            continue;
        };
        for rule in &rules {
            let _ = scan_source(rule, &v);
        }
    }
}
