# Quarry DSL guide (quarry-rs)

Adapted from Cisco's Project Quarry `docs/dsl.md` (Apache-2.0) — see
[NOTICE](../NOTICE). This version documents the Rust port: same language,
different packaging. Estate-specific laws (IGN time, disposition routing)
live in the `agent-safety` layer, not here.

## The language

A `.rule` file contains one named rule:

```text
rule "Suspicious request"
metadata:
    severity = "medium"
strings:
    $blocked = ["reveal a secret", "ignore the policy"] nocase
variables:
    has_blocked_text = any msg in user_messages where msg.content contains_any $blocked
condition:
    has_blocked_text
```

Optional blocks appear in this order: `metadata`, `strings`, `variables`,
`parameters`. Every rule needs `condition:`. Use `//` for line comments.

Use `=` to define values in `metadata:`, `strings:`, and `variables:`. Use
`==` to compare values in `condition:` expressions. String declarations
support `nocase`, `fullword`, `base64`, and `regex` modifiers. `#name` is
the occurrence-count operator; `@name` the first-match position.

## Data and expressions

Rules read canonical `messages`, role-filtered message collections,
`tool_calls`, `tool_responses`, and offered `tools`. The scan input is an
OpenAI-shaped object with a required `messages` array and optional `tools`
array.

Use `any` and `all` comprehensions to inspect collections. String
declarations support literal, whole-word, Base64, and RE2 matching.
Arithmetic, numeric comparison, field access, array indexing, and `as`
capture are available where the compiler can type and lower them.

```text
rule "Repeated shell requests"
condition:
    count([msg for msg in user_messages if msg.content contains "sudo"]) >= 2
```

An `as` capture name cannot also be declared in the same rule's
`variables:` block. Quarry rejects that ambiguity when the rule loads.

## Event flow

Flow operators read the finite conversation trace. `A after B` requires a
witness for `B` before a witness for `A`; `right_after` requires adjacent
relevant events; `until` sustains its left condition until the right
condition occurs. Bounded forms: `after(within: N)`, `before(within: N)`.
Use parentheses when combining flow and Boolean logic.

```text
rule "Read then send"
condition:
    called_tool("send") after called_tool("read")
```

The compiler rejects combinations it cannot represent faithfully. It also
limits automaton construction work, state growth, and capture complexity.
Split a large rule into smaller rules or shorten its flow window when it
hits a compile limit.

## Loading and scanning (Rust surface)

```rust
use quarry_engine::{scan_source, ScanOptions, ScanStatus};

let verdict = scan_source(rule_source, &conversation_json);
match verdict.status {
    ScanStatus::Complete => { /* verdict.matched is authoritative */ }
    ScanStatus::Invalid(_) => { /* input refused */ }
    ScanStatus::Incomplete(_) => { /* no verdict: limits, adapter, or unsupported construct */ }
    ScanStatus::Overridden { .. } => { /* fail-closed bypassed by a receipted nonce */ }
}
```

The scanner publishes a generation only after every selected rule passes
validation, resource admission, and compilation. There is no
tree-evaluation fallback at scan time.

## Fail-closed and the nonce escape

An `Incomplete` scan blocks. The only escape is a **single-use, time-boxed,
scope-bound override nonce** — issued explicitly, consumed on use, recorded
in the override ledger:

```bash
quarry-rs override issue --rule "Rule name" --ttl 300 --purpose "maintenance"
```

A nonce overrides *unavailability, never verdicts*. A matched rule still
matches under an override; the consumption is receipted.

## Trace provenance (optional, recommended)

When a trace chain is configured, the scanner refuses traces whose bytes do
not hash to a chain-verified record — the provenance precondition:

```rust
ScanOptions { trace_chain: Some(path.into()), session_id: Some("sess-1".into()), ..Default::default() }
```

The capture point (interposer, not the agent) appends records; the scanner
verifies before scanning. No datum is innocent, including the log.

## Model operations (P4 — planned)

`model("alias").score(...)`, `.classify(...)`, `.complete(...)`, `.spans(...)`
are recognized by the grammar and surface as `Incomplete` until the adapter
layer lands. Adapters are the host's job; the estate layer gates them on
Harbor Watch weight attestation.

## CLI

```bash
quarry-rs parse <rule-file>...                      # validate rules
quarry-rs scan <rule> <conversation.json>           # exit 1 = match, 0 = clean,
                                                    # 2 = invalid, 3 = fail-closed
quarry-rs override issue --rule N --ttl S --purpose P
quarry-rs chain append <chain.jsonl> <session> <chunk> <trace.json>
quarry-rs chain verify <chain.jsonl>
```
