# Architecture (quarry-rs)

Adapted from Cisco's Project Quarry `docs/architecture.md` (Apache-2.0) —
see [NOTICE](../NOTICE), rewritten for the Rust crate layout.

## The core path

```text
configuration + rule source
          |
  parse -> validate -> link calls -> prepare resources
          |
  lower expressions -> build symbolic DFA -> publish rule generation
          |
    execute automaton over the normalized event trace
          |
    ScanResult: verdict + witness evidence + timing
```

A scanner publishes a new generation only after every selected rule passes
validation, resource admission, and compilation. Unsupported constructs and
compiler complexity limits reject the rule at load time. There is no
tree-evaluation fallback at scan time.

## Crate layout

| Crate | Role |
|---|---|
| `quarry-core` | Canonical conversation, event trace, scan limits, verdict status types |
| `quarry-dsl` | Lexer, AST, recursive-descent parser (the DSL grammar, compiler-7) |
| `quarry-adapters` | Model-adapter trait surface (score / classify / complete / input_tokens / spans) |
| `quarry-engine` | Compiler, guard automaton, executor, strings, override nonces, trace chains |
| `quarry-cli` | `parse`, `scan`, `chain`, `override` commands |

## The event trace

The conversation normalizes into a finite event trace: message events,
tool-call events, tool-result events, in conversation order. Flow operators
(`before`, `after`, `right_before`, `right_after`, `until`, `within: N`)
compile to state transitions over this trace. Guards are predicates over
one event: role, tool name, content match, string position/count.

## Verdicts: the four-way distinction

| Status | Meaning | Disposition |
|---|---|---|
| `Complete` | Authoritative verdict (matched true/false) | Act on it |
| `Invalid` | Input refused before execution | Fix the input |
| `Incomplete` | No verdict: limits, adapter failure, unsupported construct | **Fail-closed: block** |
| `Overridden` | Incomplete, bypassed by a receipted nonce | Proceed, receipt on record |

The classic integration bug is treating an incomplete scan as a clean scan.
The estate law: an absent verdict never counts as safety.

## Provenance chain

Trace records are hash-chained (`sha512`): each record commits to the
previous record's hash plus the trace bytes. The scanner verifies the chain
and the trace hash as a scan precondition when configured. The capture
point is the interposer — the runtime boundary, not the agent's own
reporting. An agent that can edit or truncate its own traces defeats the
detector by construction; the chain is the defense.

## Override nonces

Fail-closed is the law; availability is an explicit, receipted decision.
Nonces are 256-bit OS-CSPRNG values, single-use, time-boxed, scope-bound to
(rule, surface), recorded in a JSONL ledger. Consumption is a receipt; the
ledger is append-only by convention. A nonce overrides unavailability,
never verdicts.

## Model operations

Model-backed checks execute through adapters registered by the host. The
engine validates required aliases and operations at rule-preparation time;
an adapter failure surfaces as `Incomplete` (fail-closed), never as a
silent pass. Adapter implementations are the host's responsibility; the
estate layer gates them on weight attestation (Harbor Watch).

## Limits

Every scan carries explicit limits: input size, event count, deadline,
compile work, model-call budget. Limits surface as `Incomplete`, never as
unbounded work.
