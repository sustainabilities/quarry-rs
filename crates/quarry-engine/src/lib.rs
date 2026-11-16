//! quarry-engine — compiles validated rules and executes them over the
//! normalized event trace.
//!
//! Port of `quarry/engine/`. P2 scope: backend-free rules evaluate over the
//! event trace (flow operators via the guard automaton in `flow.rs`); model
//! and prober constructs report `Unsupported` and are recorded as skipped by
//! the conformance runner.
//!
//! Load-time contract (upstream): a rule that cannot parse, validate, admit
//! resources, or compile fails at load. There is no tree-evaluation fallback
//! at scan time — the guard automaton in `flow.rs` is that compiled form for
//! flow constructs; P3 replaces direct evaluation with the full DFA.

pub mod eval;
pub mod flow;
pub mod nonce_ledger;
pub mod override_nonce;
#[cfg(kani)]
mod kani_proofs;
pub mod strings;
pub mod trace_chain;
pub mod value;

use std::collections::BTreeMap;

use quarry_core::{Conversation, ScanStatus};
use quarry_dsl::{Expr, Rule};
pub use eval::{eval_field, Evaluator, EvalContext, EvalError};
pub use value::Value;

/// Compiler generation tag — tracks upstream `compiler_version`
/// (`compiler-7` at port time) so compiled artifacts stay comparable.
pub const COMPILER_VERSION: &str = "compiler-7";

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("unsupported construct: {0}")]
    Unsupported(String),
    #[error("complexity limit exceeded: {0}")]
    Complexity(String),
    #[error("unresolved reference: {0}")]
    Unresolved(String),
    #[error("requires model alias `{alias}` operation {operation:?} which is not configured")]
    MissingModel { alias: String, operation: String },
}

impl From<EvalError> for CompileError {
    fn from(e: EvalError) -> Self {
        match e {
            EvalError::Unsupported(s) => CompileError::Unsupported(s),
            other => CompileError::Unresolved(other.to_string()),
        }
    }
}

/// Compile one rule for scanning. P2: validation pass (strings resolve,
/// surfaces known) + inlining of `variables:` sugar.
pub fn compile(rule: &Rule) -> Result<CompiledRule, CompileError> {
    // Variables are authoring sugar: inline each reference before
    // evaluation (the upstream transformer does the same).
    let mut inlined = rule.clone();
    for (name, expr) in &rule.variables {
        inlined.condition = inline_var(&inlined.condition, name, expr);
    }
    Ok(CompiledRule {
        name: rule.name.clone(),
        condition: inlined.condition,
        strings: rule.strings.clone(),
        parameters: rule.parameters.clone(),
    })
}

/// One compiled rule ready to scan.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub condition: Expr,
    pub strings: Vec<quarry_dsl::StringDef>,
    pub parameters: Vec<quarry_dsl::ParameterDef>,
}

fn inline_var(expr: &Expr, name: &str, value: &Expr) -> Expr {
    match expr {
        Expr::Ident(n) if n == name => value.clone(),
        Expr::Or(a, b) => Expr::Or(
            Box::new(inline_var(a, name, value)),
            Box::new(inline_var(b, name, value)),
        ),
        Expr::And(a, b) => Expr::And(
            Box::new(inline_var(a, name, value)),
            Box::new(inline_var(b, name, value)),
        ),
        Expr::Not(a) => Expr::Not(Box::new(inline_var(a, name, value))),
        Expr::Flow { op, left, right, within } => Expr::Flow {
            op: *op,
            left: Box::new(inline_var(left, name, value)),
            right: Box::new(inline_var(right, name, value)),
            within: *within,
        },
        Expr::Comparison { op, left, right } => Expr::Comparison {
            op: *op,
            left: Box::new(inline_var(left, name, value)),
            right: Box::new(inline_var(right, name, value)),
        },
        Expr::Contains(a, b) => Expr::Contains(
            Box::new(inline_var(a, name, value)),
            Box::new(inline_var(b, name, value)),
        ),
        Expr::ContainsAny(a, rhs) => Expr::ContainsAny(
            Box::new(inline_var(a, name, value)),
            rhs.clone(),
        ),
        Expr::RegexMatch(a, b) => Expr::RegexMatch(
            Box::new(inline_var(a, name, value)),
            Box::new(inline_var(b, name, value)),
        ),
        Expr::MatchesPattern(a, b) => Expr::MatchesPattern(
            Box::new(inline_var(a, name, value)),
            b.clone(),
        ),
        Expr::In(a, b) => Expr::In(
            Box::new(inline_var(a, name, value)),
            Box::new(inline_var(b, name, value)),
        ),
        Expr::InWithCapture { needle, haystack, capture } => Expr::InWithCapture {
            needle: Box::new(inline_var(needle, name, value)),
            haystack: Box::new(inline_var(haystack, name, value)),
            capture: capture.clone(),
        },
        Expr::Assignment(a, n) => Expr::Assignment(Box::new(inline_var(a, name, value)), n.clone()),
        Expr::Add(a, b) => Expr::Add(
            Box::new(inline_var(a, name, value)),
            Box::new(inline_var(b, name, value)),
        ),
        Expr::Sub(a, b) => Expr::Sub(
            Box::new(inline_var(a, name, value)),
            Box::new(inline_var(b, name, value)),
        ),
        Expr::Mul(a, b) => Expr::Mul(
            Box::new(inline_var(a, name, value)),
            Box::new(inline_var(b, name, value)),
        ),
        Expr::FunctionCall { name: f, args } => Expr::FunctionCall {
            name: f.clone(),
            args: args.iter().map(|a| inline_var(a, name, value)).collect(),
        },
        Expr::MethodCall { receiver, name: m, args } => Expr::MethodCall {
            receiver: Box::new(inline_var(receiver, name, value)),
            name: m.clone(),
            args: args.iter().map(|a| inline_var(a, name, value)).collect(),
        },
        Expr::AttrAccess { receiver, name: f } => Expr::AttrAccess {
            receiver: Box::new(inline_var(receiver, name, value)),
            name: f.clone(),
        },
        Expr::Index { receiver, index } => Expr::Index {
            receiver: Box::new(inline_var(receiver, name, value)),
            index: Box::new(inline_var(index, name, value)),
        },
        Expr::Slice { receiver, from, to } => Expr::Slice {
            receiver: Box::new(inline_var(receiver, name, value)),
            from: *from,
            to: *to,
        },
        Expr::SliceAll(r) => Expr::SliceAll(Box::new(inline_var(r, name, value))),
        Expr::WildcardPostfix(r) => Expr::WildcardPostfix(Box::new(inline_var(r, name, value))),
        Expr::AnyComp { var, iter, cond } => Expr::AnyComp {
            var: var.clone(),
            iter: Box::new(inline_var(iter, name, value)),
            cond: Box::new(inline_var(cond, name, value)),
        },
        Expr::AllComp { var, iter, cond } => Expr::AllComp {
            var: var.clone(),
            iter: Box::new(inline_var(iter, name, value)),
            cond: Box::new(inline_var(cond, name, value)),
        },
        Expr::MapComp { expr: e, var, iter, cond } => Expr::MapComp {
            expr: Box::new(inline_var(e, name, value)),
            var: var.clone(),
            iter: Box::new(inline_var(iter, name, value)),
            cond: cond.as_ref().map(|c| Box::new(inline_var(c, name, value))),
        },
        Expr::Filter(f) => Expr::Filter(quarry_dsl::FilterComp {
            item: f.item.clone(),
            var: f.var.clone(),
            iter: Box::new(inline_var(&f.iter, name, value)),
            cond: Box::new(inline_var(&f.cond, name, value)),
        }),
        other => other.clone(),
    }
}

/// Scan verdict for one rule over one conversation.
#[derive(Debug, Clone)]
pub struct RuleVerdict {
    pub rule: String,
    pub matched: bool,
    pub status: ScanStatus,
    /// The two clocks, honesty-classed. Estate time laws (IGN v1.y) are
    /// applied by the estate integration layer on top of `scan_time_unix_ns`.
    pub timing: ScanTiming,
}

/// Dual stamps: when the events happened vs when the scan ran. These are
/// different moments; collapsing them would let the timeline claim
/// detections happened when the actions happened.
#[derive(Debug, Clone)]
pub struct ScanTiming {
    /// Scan start, unix nanoseconds. Honesty class: `unlocked` until the
    /// host anchors this seat to an authoritative pulse (estate: IGN via
    /// LatticeGuard/Meridian).
    pub scan_time_unix_ns: u128,
    /// Event-time of the newest message in the scanned trace, as supplied
    /// by the capture point (unix ns). `None` when the capture point did
    /// not stamp it — never fabricated.
    pub event_time_unix_ns: Option<u128>,
    /// Honesty class of the clock that produced `scan_time_unix_ns`.
    pub clock_honesty: ClockHonesty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockHonesty {
    /// Anchored to an authoritative pulse (estate: IGN via LatticeGuard).
    Locked,
    /// Local monotonic-derived stand-in — honestly labeled.
    Unlocked,
}

fn unix_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Build a verdict with dual stamps (honesty: unlocked until the host
/// anchors the seat to an authoritative pulse).
fn verdict(rule: String, matched: bool, status: ScanStatus) -> RuleVerdict {
    RuleVerdict {
        rule,
        matched,
        status,
        timing: ScanTiming {
            scan_time_unix_ns: unix_ns(),
            event_time_unix_ns: None,
            clock_honesty: ClockHonesty::Unlocked,
        },
    }
}

/// Scan one conversation against one compiled rule.
pub fn scan(
    rule: &CompiledRule,
    conversation: &Conversation,
    params: BTreeMap<String, Value>,
) -> RuleVerdict {
    let mut cx = EvalContext::new(conversation, params);
    for def in &rule.strings {
        let mods = strings::Modifiers::from_slice(&def.modifiers);
        let pats: Vec<String> = match &def.value {
            quarry_dsl::StringValue::Literal(s) => vec![s.clone()],
            quarry_dsl::StringValue::Array(items) => items.clone(),
        };
        cx.strings.insert(def.name.clone(), (pats, mods));
    }

    let trace = quarry_core::event_trace(conversation);
    match flow::eval_condition(&rule.condition, &trace, &mut cx) {
        Ok(v) => verdict(rule.name.clone(), v.truthy(), ScanStatus::Complete),
        Err(EvalError::Unsupported(reason)) => verdict(rule.name.clone(), false, ScanStatus::Incomplete(reason)),
        Err(e) => verdict(rule.name.clone(), false, ScanStatus::Invalid(e.to_string())),
    }
}

/// Convenience: parse + compile + scan.
pub fn scan_source(rule_src: &str, conversation_json: &serde_json::Value) -> RuleVerdict {
    scan_source_with_options(rule_src, conversation_json, &ScanOptions::default())
}

/// Scan options: surface identity + fail-closed override nonce.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Host-assigned surface id (e.g. "helm", "tymelyne-capture").
    pub surface: Option<String>,
    /// Override nonce presented when the scan would fail closed.
    pub override_nonce: Option<String>,
    /// Registry path for nonce consumption receipts.
    pub override_store: Option<std::path::PathBuf>,
    /// Trace provenance chain (worry #5). When set, the exact trace bytes
    /// (`trace_bytes`) must hash to a chain-verified record bound to
    /// `session_id`, or the scan refuses (fail-closed — and NOT
    /// nonce-overridable: the nonce covers scanner unavailability, never
    /// unproven provenance).
    pub trace_chain: Option<std::path::PathBuf>,
    /// Session identity for chain verification.
    pub session_id: Option<String>,
    /// The exact trace bytes as captured (required with `trace_chain`:
    /// provenance is over bytes, not over a re-serialization of parsed JSON).
    pub trace_bytes: Option<Vec<u8>>,
}

/// Parse + compile + scan with fail-closed/override semantics.
pub fn scan_source_with_options(
    rule_src: &str,
    conversation_json: &serde_json::Value,
    opts: &ScanOptions,
) -> RuleVerdict {
    let rule = match quarry_dsl::parse_rule(rule_src) {
        Ok(r) => r,
        Err(e) => {
            return verdict("?".to_string(), false, ScanStatus::Invalid(e.to_string()));
        }
    };
    let compiled = match compile(&rule) {
        Ok(c) => c,
        Err(e) => {
            return verdict(rule.name, false, ScanStatus::Incomplete(e.to_string()));
        }
    };
    let conv: Conversation = match serde_json::from_value(conversation_json.clone()) {
        Ok(c) => c,
        Err(e) => {
            return verdict(
                rule.name,
                false,
                ScanStatus::Invalid(format!("conversation JSON: {e}")),
            );
        }
    };
    // Trace provenance precondition (worry #5): when a chain is configured,
    // the EXACT captured bytes must be chain-verified and session-bound.
    // Refusal is `Invalid` — deliberately NOT nonce-overridable.
    if let Some(chain_path) = &opts.trace_chain {
        let Some(session) = opts.session_id.as_deref() else {
            return verdict(
                rule.name,
                false,
                ScanStatus::Invalid("trace chain configured but no session_id supplied".into()),
            );
        };
        let Some(trace_bytes) = &opts.trace_bytes else {
            return verdict(
                rule.name,
                false,
                ScanStatus::Invalid(
                    "trace chain configured but exact trace bytes not supplied \
                     (provenance is over bytes, not re-serializations)"
                        .into(),
                ),
            );
        };
        let chain = trace_chain::TraceChain::new(chain_path);
        match chain.verify_trace(trace_bytes, session) {
            Ok(rec) => {
                // Parse the conversation FROM the verified bytes, so the
                // scanned content is exactly the content the chain vouches for.
                let conv: Conversation = match serde_json::from_slice(trace_bytes) {
                    Ok(c) => c,
                    Err(e) => {
                        return verdict(
                            rule.name,
                            false,
                            ScanStatus::Invalid(format!("conversation bytes: {e}")),
                        );
                    }
                };
                // The capture point's event-time rides into the verdict's
                // timing — never fabricated by the scanner.
                let mut v = scan(&compiled, &conv, BTreeMap::new());
                v.timing.event_time_unix_ns = rec.event_time_unix_ns;
                return finish_with_override(v, opts);
            }
            Err(reason) => {
                return verdict(
                    rule.name,
                    false,
                    ScanStatus::Invalid(format!("trace provenance: {reason}")),
                );
            }
        }
    }
    let result = scan(&compiled, &conv, BTreeMap::new());
    finish_with_override(result, opts)
}

/// Apply the fail-closed/override law to a completed scan.
fn finish_with_override(result: RuleVerdict, opts: &ScanOptions) -> RuleVerdict {
    match result.status.clone() {
        // Fail-closed: an Incomplete scan blocks — unless a valid override
        // nonce covers it. The nonce NEVER flips a verdict; a matched rule
        // still matches.
        ScanStatus::Incomplete(reason) => {
            if let (Some(nonce), Some(store)) = (&opts.override_nonce, &opts.override_store) {
                let reg = override_nonce::OverrideRegistry::new(store);
                let surface = opts.surface.as_deref().unwrap_or("default");
                match reg.check_and_consume(nonce, &result.rule, surface) {
                    Ok(rec) => {
                        return verdict(
                            result.rule,
                            result.matched,
                            ScanStatus::Overridden {
                                reason,
                                nonce: format!("{}… (purpose: {})", &rec.nonce[..12], rec.purpose),
                            },
                        );
                    }
                    Err(e) => {
                        return verdict(
                            result.rule,
                            false,
                            ScanStatus::Incomplete(format!(
                                "override rejected: {e}; original: {reason}"
                            )),
                        );
                    }
                }
            }
            result
        }
        _ => result,
    }
}
