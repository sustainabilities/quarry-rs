# quarry-rs documentation

## Reading order

1. [dsl.md](dsl.md) — the detection DSL: rules, strings, comprehensions,
   flow operators, captures, the fail-closed law, the nonce escape, trace
   provenance. **Start here.**
2. [architecture.md](architecture.md) — how the engine works: crates, the
   load-time contract, the four-way verdict, the provenance chain.
3. [../PORT-SPEC.md](../PORT-SPEC.md) — the port specification: what was
   ported from upstream and how, the verification ladder, phase plan.

## Provenance

- `dsl.md` and `architecture.md` are **adapted** from Cisco's Project
  Quarry docs (Apache-2.0) — rewritten for the Rust crate layout and the
  port's current state. See [../NOTICE](../NOTICE).
- `upstream-apache2/` holds **verbatim copies** of upstream docs kept as
  reference (rule-writing, configuration, testing, how-quarry-works,
  messages, string-matching, parameters, integration), each headed with its
  source and license. They describe the upstream Python implementation;
  where they mention Python APIs, read them as language/semantics reference,
  not as this port's API.

## Status honesty

- Parser + engine + CLI: **live** (conformance-gated, see README).
- Model operations (score/classify/complete/spans): recognized by the
  grammar, surface as `Incomplete` — the adapter layer is P4 (planned).
- MCP server: P5 (planned).
- Estate integration (IGN time law, disposition routing, weight gating):
  lives in the `agent-safety` repository, not here.
