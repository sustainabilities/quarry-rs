# Contributing to quarry-rs

## The verification ladder (the law of this repo)

1. **Rung 0 — rules**: every rule parses, compiles, and matches its planted
   positive/negative traces before it is trusted.
2. **Rung 2 — tool**: deterministic fuzzing (no panics on arbitrary input),
   property tests (determinism, boundedness), conformance corpus green.
3. **Rung 3 — load time**: a rule that cannot compile fails at load; a
   generation publishes only when every rule in it is good.
4. **Rung 5 — proofs**: Verus contracts and Lean4 semantics land on the
   trust core when stable.

No change lands with a red gate. `./verify.sh` is the gate.

## Provenance discipline

- Adapted from Cisco's Project Quarry (Apache-2.0) — see [NOTICE](NOTICE).
- Preserve upstream attribution in every adapted file.
- The DSL grammar, semantics, and conformance corpus derive from upstream;
  Rust-specific code is ours. Know which is which when you edit.

## Pull requests

1. Branch from `main`, keep changes focused.
2. `cargo test --workspace` green, `./verify.sh` green.
3. New language constructs need: grammar change, AST type, compiler
   lowering, conformance examples, docs update — all five, or it doesn't
   land.
4. New behavioral tests live in `crates/*/tests/`; corpus additions go in
   `conformance/` with both positive and negative traces.

## Honesty class

Every claim in docs and comments carries its honesty class. "Verified"
means a test or proof gates it. "Planned" means it doesn't exist yet. Never
blur the two — this is a security tool; the docs are part of the security
argument.
