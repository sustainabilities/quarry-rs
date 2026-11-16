# quarry-rs — Rust Port Specification

**Status:** P1 scaffold (parser live, engine typed skeleton)
**Source of truth:** `cisco-ai-defense/project-quarry` @ 2026-11-15 HEAD
(`compiler-7`), Apache 2.0. Upstream clone: `~/Projects/project-quarry` (kimmie),
`~/Projects/project-quarry` (workstation-primary).
**Build law:** builds happen off-mount (the tiptoe-v2 rule). Canonical source
home once green: `Registry/proa-coe/tools/quarry-rs/`.

---

## 1. What Quarry is

A *neurosymbolic detection DSL* for agent behavior — YARA/Snort for agent
conversations. Rules are written over messages, tool calls, tool results, and
event order; Quarry parses and validates them at load, compiles each rule to a
**symbolic finite-state automaton**, and executes the automaton over a
normalized event trace. When local checks are not enough, rules call
configured models (score / classify / complete / spans / split) through
adapters. Findings carry witness evidence with secret masking.

Load-time contract: a rule that cannot parse, validate, admit resources, or
compile **fails at load**. There is no tree-evaluation fallback at scan time.
This makes the engine small, fast, and auditable — the properties that make a
Rust port both feasible and worth doing.

## 2. Upstream inventory (port scope)

| Upstream module | Lines | Role | Rust home |
|---|---|---|---|
| `dsl/grammar.py` | 365 | Lark grammar + precedence table | `quarry-dsl` (hand-written lexer/parser, **live**) |
| `dsl/{parser,transformer,syntax,functions}.py` | ~1.5k | parse → AST, sugar inlining | `quarry-dsl` |
| `engine/compiler.py` | 4,293 | validate, link, admit, lower, build DFA | `quarry-engine` |
| `engine/lower.py` | 1,681 | expression lowering | `quarry-engine` |
| `engine/desugar.py` | 1,223 | comprehension/string-set desugaring | `quarry-engine` |
| `engine/executor.py` | 2,001 | DFA execution, deadlines, cache | `quarry-engine` |
| `engine/{symbolic_dfa,temporal,atoms,matchers,captures,witness,oracle,budget,pacing}.py` | ~5k | DFA core, flow semantics, evidence, model-ops | `quarry-engine` |
| `language/spec.json` | 3,981 | machine-readable DSL spec (compiler-7) | `conformance/spec.json` |
| `language/reference.md` | 1,328 | generated language reference | `conformance/reference.md` |
| `examples/` | 75 rules + matching/non-matching JSON | conformance corpus | `conformance/examples/` |
| `cli.py`, `sdk.py`, `plugin/server.py` | ~2k | CLI, Python SDK, MCP server | `quarry-cli` (+ MCP later) |
| model-inference extra | litellm adapter | provider calls | estate adapters (HELM-owned) |

Python dependency mapping:

| Python | Rust | Note |
|---|---|---|
| `lark` 1.3.1 | hand-written recursive descent | grammar is 365 lines; contextual keywords handled at parser level |
| `google-re2` | `regex` crate | both guarantee linear time; RE2 deltas documented in §5 |
| `pydantic` 2.14 | `serde` + explicit validation | validation is load-time and explicit upstream |
| `orjson` | `serde_json` | |
| `cachetools` | `std` HashMap, scan-local | cache is per-scan, bounded |
| `loguru` | `tracing` (later) | |
| `rich`/`pygments` | CLI-only, deferred | |

## 3. The DSL (extracted, compiler-7)

```
rule "NAME"
metadata:   KEY = "STR" ...            # ≥1 item
strings:    $NAME = "STR"|["STR",...] (nocase|fullword|base64|regex)*
variables:  NAME = expr ...            # authoring sugar, inlined pre-compile
parameters: NAME : number|text [policy] ...
condition:  expr
collect:    [ item for var in iter if cond ]
```

Precedence (loosest→tightest): `or` < `and` < `not` < flow < comparison <
membership < `+ -` < `*` < postfix. Flow (`before`, `after`, `right_before`,
`right_after`, `until`, `within:N`) and comparison are **non-associative**.

Key constructs: `any/all x in y where c` · `[x for x in y if c]` ·
`N of ($a, $b*)` · `@$s` / `#$s` positions/counts · `contains`,
`contains_any`, `~` (RE2), `matches { … }` pattern blocks · `in … as capture`
· slices, indexes, `.*` expansion · ~35 built-in functions over the
conversation surface (`user_messages`, `tool_calls`, `called_tool`,
`call_sequence`, `model("alias").score(...)`, …).

## 4. Port phases (Foundry build plan)

- **P0 — scaffold** ✅ workspace, crate seams, event model, adapter trait,
  conformance corpus vendored, compiler-version pin.
- **P1 — parser conformance** ✅ lexer + parser + AST; **exit gate: all 96
  corpus rules parse** (`parses_entire_conformance_corpus`).
- **P2 — local-rule engine** ✅ **complete**: desugar (variable inlining),
  symbolic guard automaton over the normalized event trace (flow operators
  with exact `within`/adjacency/`until` semantics), strings with all four
  modifiers, comprehensions, captures, the backend-free function surface,
  and the corpus conformance runner. **Exit gate green: 24/24 spec language
  examples; 95/95 non-backend corpus checks** (37 model/prober checks defer
  to P4 and are reported as skipped, never silently). CLI gained `scan`
  with upstream exit codes (1 = match).
- **P3 — hardening**: parse-diff vs Python on exotic rules, fuzz the parser,
  Kani panic-freedom on the DFA core (Foundry policy).
- **P4 — model adapters**: the `ModelAdapter` trait is already shaped; add
  the HELM adapter registry + scan-scoped budget enforcement. Harbor Watch
  gates adapter startup (see §6).
- **P5 — surfaces**: `quarry-rs scan` CLI parity (JSON/CSV out), MCP server
  (replacing `quarry-mcp`; `scan` already shipped), Proa integration crate
  for HELM.
- **P6 — verification per Foundry policy**: fuzz the parser (untrusted rule
  text), Kani panic-freedom on DFA core, property tests (compile ⇒
  executable ⇒ bounded), Verus contracts on the DFA/hash core when stable.
  Receipts on every build.

## 5. Semantic deltas to watch (RE2 / regex crate)

- The `regex` crate, like RE2, guarantees linear time and forbids
  backreferences/lookaround. Upstream chose RE2 for exactly this; deltas are
  expected to be empty-to-minor. **Verify per-rule during P3** with the
  corpus regex cases (`regex-match.rule` et al.).
- `base64` string modifier: upstream matches the base64 *encoding* of the
  keyword; port must reproduce its exact padding/alignment behavior
  (`strings/modifiers` tests in upstream `tests/`).
- `nocase` uses Unicode case folding upstream — use
  `regex` + `caseless`-equivalent folding, not ASCII lowering.
- Number semantics: upstream NUMBER is Lark's DECIMAL|INT; JSON numbers
  round-trip through serde — keep f64 determinism (no fast-math).

## 6. Estate integration (the reason this port exists)

```
Tymelyne / estate-memory (sessions.redb)          Harbor Watch (CoE #2)
   agent-action event stream                        weights fit/unfit per shift
        │                                                │
        ▼                                                ▼
   quarry-rs scan (in-process crate, no Python) ── model adapters refused
        │                                           unless weights are FIT
        ▼
   findings + witness evidence
        │
        ▼
   Proa surfaces (HELM first) ── HTML + md twins, llms.txt discovery
        │
        ▼
   Maddie reticulum mesh (estate-only) + Iroh perimeter ── rule + finding
   distribution across 10.99.0.0/24, minimum configuration
```

- **One Rust crate, any surface**: no Python interpreter on any node. The
  same compiled rules run on kimmie, workstation-primary, server-16, the NAS,
  and inside HELM.
- **Tymelyne wiring — INLINE primary, snapshot backstop** (decided
  2026-11-16): scan at the harness before/after each tool call — the only
  mode that *prevents* rather than documents, and sub-millisecond here
  because quarry-rs is in-process Rust. Snapshot scanning of sessions.redb
  is retained deliberately: it covers unhooked surfaces retroactively, it is
  upstream's incident-response mode (new pattern against old traces), and
  new rules should be canaried against history before going inline.
  Findings write to a dedicated findings store, NOT sessions.redb — the
  redb store is single-writer (the capture agent holds the lock). Fail-closed
  is the law on enforcement surfaces: no authoritative verdict ⇒ no bypass.
- **Harbor Watch as the weight gate**: `harbor-watch check` gates every
  model-backed rule (P4). A rule requiring an alias whose weights are UNFIT
  for duty refuses to admit — the attestation becomes a load-time property.
- **Proa shift-board** (CoE roadmap "Product" row): quarry findings join the
  shift logs on the same zero-JS Proa dashboard discipline.
- **Canonical home**: `Registry/proa-coe/tools/quarry-rs/` (P1 green on both
  machines); builds always off-mount via the Foundry.

### The override law (fail-closed with a controlled escape)

- Enforcement surfaces are **fail-closed**: no authoritative verdict ⇒ the
  action does not proceed.
- Escape is by **nonce only**: `quarry-rs override issue --rule NAME --ttl
  SECS --purpose TEXT` writes a single-use, time-boxed, scope-bound nonce to
  the registry ledger; the scan presents it (`scan --override-nonce HEX
  --override-store PATH --surface ID`).
- **A nonce overrides unavailability, never verdicts.** A matched rule still
  matches under an override; the receipt names the nonce, purpose, rule,
  surface, and consumption time — and flows to Tymelyne like any other
  estate event.
- Nonces are 256 bits of OS CSPRNG, single-use (consumption recorded in the
  ledger), time-boxed (expiry checked at use), and scope-bound to
  (rule, surface).
- Trust note: the registry file is a trusted application input on the same
  boundary as rule config. A signed-nonce upgrade (estate key, PQ-ready)
  slots into the same API when the CoE wants it.

## 7. Licensing

**Public core (`sustainabilities/quarry-rs`)**: MIT, with `NOTICE` carrying
the Apache-2.0 attribution to Cisco's Project Quarry (the DSL grammar,
engine semantics, and the conformance corpus derive from upstream). The
copied harbor-watch sha512 was **removed** from the public tree — the core
uses the standard `sha2` crate; the estate's verified implementation stays
in estate code only.

**Estate layer (`sustainabilities/agent-safety`)**: LicenseRef-Proprietary —
the SafeHarbors enforcement customization (IGN law, disposition routing,
estate rule pack, Harbor Watch gating, sink seams), published for review
and use by arrangement. The Apache core is cleanly separable from the
proprietary estate layer by construction.
