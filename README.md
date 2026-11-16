# quarry-rs

A Rust port of [Project Quarry](https://github.com/cisco-ai-defense/project-quarry)
(Cisco AI Defense, Apache-2.0) — the detection DSL and engine for AI agent
behavior. YARA/Snort for agents: rules over messages, tool calls, tool
results, and event order, compiled to a finite automaton at load time and
executed over the conversation trace.

**Why Rust:** one statically-linked crate, any surface — no interpreter, no
IPC. Full-rule-set scans run in ~1.6 ms (75 rules against a multi-turn
conversation, measured; see `crates/quarry-engine/tests/latency.rs`).

## Status

Conformance-gated port of upstream `compiler-7`:

- **Parser/AST**: the full DSL (YARA-style rules; `strings:` with
  `nocase`/`fullword`/`base64`/`regex` modifiers; flow operators
  `before`/`after`/`right_before`/`right_after`/`until` with `within:N`;
  `any`/`all`/filter/map comprehensions; captures; string sets with
  `$prefix*` expansion; RE2 matching).
- **Engine**: symbolic guard automaton over the normalized event trace;
  backend-free rules scan locally. Model-backed constructs (score/classify/
  complete/spans) surface as `Incomplete` — adapters are the host's job.
- **Conformance**: upstream's own corpus is the exit gate — **24/24 spec
  language examples, 95/95 non-backend corpus checks** (37 model/prober
  checks are reported as skipped, never silently dropped).
- **Fail-closed**: the three-way upstream distinction is preserved and
  extended — `clean` / `match` / `no-verdict`; an absent verdict never
  counts as safety. Optional single-use override nonces cover *scanner
  unavailability only*, never verdicts.
- **Trace provenance**: optional hash-chained trace records (sha512) verify
  that the bytes scanned are the bytes the capture point witnessed, bound to
  a session id. Unverified traces are refused — and that refusal is not
  nonce-overridable.

## Usage

```bash
cargo run -p quarry-cli -- parse rules/...            # validate rule files
cargo run -p quarry-cli -- scan <rule> <trace.json>   # exit 1 = match, 0 = clean,
                                                      # 2 = invalid, 3 = fail-closed
```

As a library:

```rust
use quarry_engine::scan_source;

let verdict = scan_source(rule_source, &conversation_json);
match verdict.status {
    quarry_core::ScanStatus::Complete => { /* authoritative: use verdict.matched */ }
    quarry_core::ScanStatus::Incomplete(_) => { /* fail-closed: no verdict */ }
    quarry_core::ScanStatus::Invalid(_) => { /* input refused */ }
    quarry_core::ScanStatus::Overridden { .. } => { /* receipted unavailability escape */ }
}
```

## Crates

| Crate | What |
|---|---|
| `quarry-dsl` | lexer, AST, recursive-descent parser (the DSL is the asset — ported from upstream's 365-line Lark grammar) |
| `quarry-core` | canonical event model, conversation shape, scan limits |
| `quarry-engine` | compiler, guard automaton, executor, string matchers, override nonces, trace chains |
| `quarry-cli` | `parse` / `scan` / `chain` / `override` commands |

## Verification (shifted left)

- **Rung 0 — rules**: every rule parses, compiles, and matches planted
  positive/negative traces before it is trusted (see the estate pack
  pattern in `PORT-SPEC.md`).
- **Rung 2 — tool**: deterministic fuzzing (25k+ mutated rules/traces per
  run: no panics, verdicts deterministic) and Kani proof harnesses
  (`crates/quarry-dsl/src/proofs.rs`) for lexer/parser panic-freedom.
- **Rung 3 — load time**: rules that cannot compile fail at load; a
  generation publishes only when every rule in it is good (upstream's own
  contract, kept).
- **Rung 5 — proofs (planned)**: Verus contracts on the DFA core; Lean4 for
  flow-operator semantics.

The point of the ladder: **verification is what buys the right to
optimize.** Proven bounds delete runtime defensive checks; proven
determinism enables single-pass rule fusion; receipted precompiled
generations move work off the hot path.

## Documentation

- [docs/dsl.md](docs/dsl.md) — the detection DSL: rules, strings, flow operators, captures, the fail-closed law (**start here**)
- [docs/architecture.md](docs/architecture.md) — how the engine works
- [PORT-SPEC.md](PORT-SPEC.md) — the full port specification and verification ladder
- [docs/upstream-apache2/](docs/upstream-apache2/) — Cisco's original docs, kept verbatim as reference

## Provenance & license

Ported from Cisco's open-source Project Quarry (Apache-2.0, `compiler-7` @
2026-11-15). The DSL grammar, semantics, and conformance corpus derive from
the upstream repository — see [NOTICE](NOTICE). This port is MIT-licensed;
upstream remains Apache-2.0. Upstream is in alpha and its DSL may change
before v1.0.0 — pin the engine, and treat upstream pulls as revalidation
events (`scripts/spec-diff.sh` automates the drift check).

Not affiliated with or endorsed by Cisco.
