//! Flow operators — event-guard compilation and trace evaluation.
//!
//! Port of the flow semantics of `quarry/engine/{lower,temporal}.py` and the
//! language reference §flow-*: guards match events in the normalized trace;
//!
//! - `A after B`            — ∃ A-event after a B-event
//! - `A after(within:N) B`  — ∃ A-event 0 < Δsteps ≤ N after a B-event
//! - `A before B` / within  — mirror image
//! - `A right_after B`      — an A-event with no guard-relevant event between
//!                            it and a B-event ("adjacent relevant events")
//! - `A until B`            — B occurs, and A holds at every event of A's
//!                            own kind before the first B-event
//!
//! The guard model is kept automaton-shaped (`Guard` over events) so the DFA
//! compiler can replace direct evaluation in P3 without a semantic change.

use quarry_core::{Conversation, Event, EventKind};
use quarry_dsl::Expr;

use crate::eval::{EvalContext, EvalError};
use crate::value::Value;

/// What kinds of events a guard can match — the guard's "own kind" domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// Any message event (optionally role-restricted).
    Message(Option<&'static str>),
    /// Tool-call events.
    ToolCall,
    /// Tool-result events.
    ToolResult,
    /// Unknown / mixed — used by composite guards until refined.
    Mixed,
}

/// A compiled event guard: a predicate over one event.
#[derive(Debug, Clone)]
pub enum Guard {
    True,
    /// Role-restricted message whose content contains the text.
    Said { role: &'static str, text: String, case_sensitive: bool },
    /// Tool-call event with this exact name.
    ToolNamed(String),
    /// Tool-result event answering a call with this exact name.
    ResultNamed(String),
    /// Comprehension over a surface, bound to the event's item.
    ItemTest {
        domain: Domain,
        var: String,
        cond: Box<Expr>,
    },
    Or(Vec<Guard>),
    And(Vec<Guard>),
    Not(Box<Guard>),
    False(String),
}

impl Guard {
    pub fn domain(&self) -> Domain {
        match self {
            Guard::Said { role, .. } => Domain::Message(Some(role)),
            Guard::ToolNamed(_) => Domain::ToolCall,
            Guard::ResultNamed(_) => Domain::ToolResult,
            Guard::ItemTest { domain, .. } => *domain,
            Guard::Or(parts) => parts.first().map(|p| p.domain()).unwrap_or(Domain::Mixed),
            Guard::And(parts) => parts.first().map(|p| p.domain()).unwrap_or(Domain::Mixed),
            Guard::Not(inner) => inner.domain(),
            Guard::True | Guard::False(_) => Domain::Mixed,
        }
    }

    /// Does this guard match the given event?
    pub fn matches(&self, event: &Event, cx: &mut EvalContext) -> Result<bool, EvalError> {
        match self {
            Guard::True => Ok(true),
            Guard::False(reason) => Err(EvalError::Unsupported(reason.clone())),
            Guard::Said { role, text, case_sensitive } => {
                if !matches!(event.kind, EventKind::Message) {
                    return Ok(false);
                }
                let msg = &cx.messages[event.message_index];
                let r = crate::eval_field(msg, "role");
                if r.as_deref() != Some(*role) {
                    return Ok(false);
                }
                let content = crate::eval_field(msg, "content").unwrap_or_default();
                Ok(if *case_sensitive {
                    content.contains(text.as_str())
                } else {
                    content.to_lowercase().contains(&text.to_lowercase())
                })
            }
            Guard::ToolNamed(name) => {
                if !matches!(event.kind, EventKind::ToolCall) {
                    return Ok(false);
                }
                // Find which call index this event corresponds to: calls are
                // chronological; count preceding call events.
                let call_idx = event.ordinal;
                Ok(cx
                    .tool_calls
                    .get(call_idx)
                    .and_then(|c| crate::eval_field(c, "name"))
                    .map(|n| n == name.as_str())
                    .unwrap_or(false))
            }
            Guard::ResultNamed(name) => {
                if !matches!(event.kind, EventKind::ToolResult) {
                    return Ok(false);
                }
                Ok(cx
                    .tool_responses
                    .get(event.ordinal)
                    .and_then(|r| crate::eval_field(r, "name"))
                    .map(|n| n == name.as_str())
                    .unwrap_or(false))
            }
            Guard::ItemTest { domain, var, cond } => {
                if !domain_matches(*domain, event) {
                    return Ok(false);
                }
                let item = event_item(event, cx);
                let Some(item) = item else { return Ok(false) };
                let saved = cx.captures.insert(var.clone(), item);
                let hit = crate::Evaluator::eval(cond, cx).map(|v| v.truthy());
                match saved {
                    Some(v) => {
                        cx.captures.insert(var.clone(), v);
                    }
                    None => {
                        cx.captures.remove(var.as_str());
                    }
                }
                hit
            }
            Guard::Or(parts) => {
                for p in parts {
                    if p.matches(event, cx)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Guard::And(parts) => {
                for p in parts {
                    if !p.matches(event, cx)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Guard::Not(inner) => Ok(!inner.matches(event, cx)?),
        }
    }
}

fn domain_matches(d: Domain, event: &Event) -> bool {
    match d {
        Domain::Message(None) => matches!(event.kind, EventKind::Message),
        Domain::Message(Some(role)) => {
            matches!(event.kind, EventKind::Message) && event.role_hint == Some(role)
        }
        Domain::ToolCall => matches!(event.kind, EventKind::ToolCall),
        Domain::ToolResult => matches!(event.kind, EventKind::ToolResult),
        Domain::Mixed => true,
    }
}

fn event_item<'cx>(event: &Event, cx: &'cx mut EvalContext) -> Option<Value> {
    match event.kind {
        EventKind::Message => cx.messages.get(event.message_index).cloned(),
        EventKind::ToolCall => cx.tool_calls.get(event.ordinal).cloned(),
        EventKind::ToolResult => cx.tool_responses.get(event.ordinal).cloned(),
    }
}

/// Compile a flow operand into an event guard.
pub fn compile_guard(expr: &Expr) -> Guard {
    match expr {
        Expr::FunctionCall { name, args } if name == "called_tool" => {
            if let Some(quarry_dsl::Expr::StringLit(n)) = args.first() {
                Guard::ToolNamed(n.clone())
            } else {
                Guard::False("flow operand called_tool requires a literal name (P2)".into())
            }
        }
        Expr::FunctionCall { name, args } if name == "user_said" || name == "assistant_said" => {
            let role: &'static str = if name == "user_said" { "user" } else { "assistant" };
            match args.first() {
                Some(quarry_dsl::Expr::StringLit(t)) => Guard::Said {
                    role,
                    text: t.clone(),
                    case_sensitive: false,
                },
                _ => Guard::False(format!("flow operand {name} requires a literal text (P2)")),
            }
        }
        Expr::FunctionCall { name, args } if name == "called_tools" || name == "has_tools" || name == "has_sequence" => {
            // Conjunction of per-name guards for called_tools; the others are
            // conversation-wide and have no event shape.
            let mut parts = Vec::new();
            for a in args {
                if let quarry_dsl::Expr::StringLit(n) = a {
                    if name == "called_tools" {
                        parts.push(Guard::ToolNamed(n.clone()));
                    }
                }
            }
            if name == "called_tools" && !parts.is_empty() {
                Guard::And(parts)
            } else {
                Guard::False(format!("flow operand {name} is not event-shaped (P2)"))
            }
        }
        Expr::AnyComp { var, iter, cond } => {
            // `any x in get_tool_calls("name") where P` — name-filtered calls.
            if let Expr::FunctionCall { name: f, args } = iter.as_ref() {
                if f == "get_tool_calls" {
                    if let Some(quarry_dsl::Expr::StringLit(n)) = args.first() {
                        return Guard::And(vec![
                            Guard::ToolNamed(n.clone()),
                            Guard::ItemTest {
                                domain: Domain::ToolCall,
                                var: var.clone(),
                                cond: cond.clone(),
                            },
                        ]);
                    }
                }
                if f == "get_tool_responses" {
                    if let Some(quarry_dsl::Expr::StringLit(n)) = args.first() {
                        return Guard::And(vec![
                            Guard::ResultNamed(n.clone()),
                            Guard::ItemTest {
                                domain: Domain::ToolResult,
                                var: var.clone(),
                                cond: cond.clone(),
                            },
                        ]);
                    }
                }
            }
            match surface_domain(iter) {
                Some(domain) => Guard::ItemTest {
                    domain,
                    var: var.clone(),
                    cond: cond.clone(),
                },
                None => Guard::False("flow operand comprehension must iterate a surface (P2)".into()),
            }
        },
        Expr::Or(a, b) => Guard::Or(vec![compile_guard(a), compile_guard(b)]),
        Expr::And(a, b) => Guard::And(vec![compile_guard(a), compile_guard(b)]),
        Expr::Not(a) => Guard::Not(Box::new(compile_guard(a))),
        Expr::StringVar(_) | Expr::Ident(_) => {
            Guard::False("flow operand must be event-shaped (P2)".into())
        }
        other => Guard::False(format!(
            "flow operand {other:?} is not event-shaped (P2)"
        )),
    }
}

fn surface_domain(iter: &Expr) -> Option<Domain> {
    match iter {
        Expr::Ident(name) => match name.as_str() {
            "messages" => Some(Domain::Message(None)),
            "user_messages" => Some(Domain::Message(Some("user"))),
            "assistant_messages" => Some(Domain::Message(Some("assistant"))),
            "system_messages" => Some(Domain::Message(Some("system"))),
            "developer_messages" => Some(Domain::Message(Some("developer"))),
            "tool_calls" => Some(Domain::ToolCall),
            "tool_responses" => Some(Domain::ToolResult),
            _ => None,
        },
        _ => None,
    }
}

/// Evaluate one flow expression over the event trace.
pub fn eval_flow(
    op: quarry_dsl::FlowOp,
    within: Option<f64>,
    left: &Expr,
    right: &Expr,
    trace: &[Event],
    cx: &mut EvalContext,
) -> Result<bool, EvalError> {
    let lg = compile_guard(left);
    let rg = compile_guard(right);
    eval_flow_guards(op, within, &lg, &rg, trace, cx)
}

/// Evaluate a flow over pre-compiled guards.
pub fn eval_flow_guards(
    op: quarry_dsl::FlowOp,
    within: Option<f64>,
    lg: &Guard,
    rg: &Guard,
    trace: &[Event],
    cx: &mut EvalContext,
) -> Result<bool, EvalError> {
    let lpos = guard_positions(lg, trace, cx)?;
    let rpos = guard_positions(rg, trace, cx)?;

    use quarry_dsl::FlowOp::*;
    match op {
        After | Before => {
            let want_l_after_r = op == After;
            for &a in &lpos {
                for &b in &rpos {
                    let delta = if want_l_after_r {
                        a as i64 - b as i64
                    } else {
                        b as i64 - a as i64
                    };
                    let in_window = match within {
                        Some(n) => 0 < delta && delta <= n as i64,
                        None => delta > 0,
                    };
                    if in_window {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        RightAfter | RightBefore => {
            // "Immediately follows/precedes": distance 1 in the raw trace
            // (upstream metadata: "A immediately precedes B, distance = 1").
            let want_l_after_r = op == RightAfter;
            for &a in &lpos {
                for &b in &rpos {
                    let adjacent = if want_l_after_r {
                        a == b + 1
                    } else {
                        b == a + 1
                    };
                    if adjacent {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        Until => {
            // B must occur; A holds at every event of A's own kind strictly
            // before the first B event.
            let Some(&first_b) = rpos.iter().min() else {
                return Ok(false);
            };
            let domain = lg.domain();
            for e in trace.iter().take(first_b) {
                if !domain_matches(domain, e) {
                    continue;
                }
                if !lg.matches(e, cx)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

/// A comprehension whose `where`-clause is a flow — the comprehension is
/// itself a flow operand ("the item's own condition next to other
/// alternatives"). `any http in CALLS where P(http) after GUARD` compiles to
/// `ItemTest(P) flow GUARD`, with any `get_tool_calls(name)` pre-filter
/// conjoined.
pub fn eval_comprehension_flow(
    var: &str,
    iter: &Expr,
    flow: &quarry_dsl::Expr,
    trace: &[Event],
    cx: &mut EvalContext,
) -> Result<bool, EvalError> {
    let Expr::Flow { op, left, right, within } = flow else {
        return Err(EvalError::Unsupported("not a flow condition".into()));
    };
    let lg = match iter {
        Expr::Ident(_) => {
            let Some(domain) = surface_domain(iter) else {
                return Err(EvalError::Unsupported(
                    "flow comprehension must iterate a surface".into(),
                ));
            };
            Guard::ItemTest {
                domain,
                var: var.to_string(),
                cond: Box::new((**left).clone()),
            }
        }
        Expr::FunctionCall { name: f, args } if f == "get_tool_calls" => {
            let Some(quarry_dsl::Expr::StringLit(n)) = args.first() else {
                return Err(EvalError::Unsupported("get_tool_calls requires a literal name".into()));
            };
            Guard::And(vec![
                Guard::ToolNamed(n.clone()),
                Guard::ItemTest {
                    domain: Domain::ToolCall,
                    var: var.to_string(),
                    cond: Box::new((**left).clone()),
                },
            ])
        }
        Expr::FunctionCall { name: f, args } if f == "get_tool_responses" => {
            let Some(quarry_dsl::Expr::StringLit(n)) = args.first() else {
                return Err(EvalError::Unsupported(
                    "get_tool_responses requires a literal name".into(),
                ));
            };
            Guard::And(vec![
                Guard::ResultNamed(n.clone()),
                Guard::ItemTest {
                    domain: Domain::ToolResult,
                    var: var.to_string(),
                    cond: Box::new((**left).clone()),
                },
            ])
        }
        _ => {
            return Err(EvalError::Unsupported(
                "flow comprehension must iterate a surface or tool accessor".into(),
            ))
        }
    };
    let rg = compile_guard(right);
    eval_flow_guards(*op, *within, &lg, &rg, trace, cx)
}

fn guard_positions(
    g: &Guard,
    trace: &[Event],
    cx: &mut EvalContext,
) -> Result<Vec<usize>, EvalError> {
    let mut out = Vec::new();
    for e in trace {
        if g.matches(e, cx)? {
            out.push(e.index);
        }
    }
    Ok(out)
}

/// Compile + evaluate a full condition: flow subexpressions delegate to
/// [`eval_flow`]; everything else evaluates directly.
pub fn eval_condition(
    expr: &Expr,
    trace: &[Event],
    cx: &mut EvalContext,
) -> Result<Value, EvalError> {
    match expr {
        Expr::Flow { op, left, right, within } => Ok(Value::Bool(eval_flow(
            *op,
            *within,
            left,
            right,
            trace,
            cx,
        )?)),
        // A comprehension whose where-clause is a flow: the comprehension is
        // itself a flow operand (upstream "flow_operand" shape).
        Expr::AnyComp { var, iter, cond }
            if matches!(cond.as_ref(), Expr::Flow { .. }) =>
        {
            Ok(Value::Bool(eval_comprehension_flow(
                var,
                iter,
                cond,
                trace,
                cx,
            )?))
        }
        Expr::Or(a, b) => {
            let av = eval_condition(a, trace, cx)?.truthy();
            Ok(Value::Bool(if av {
                true
            } else {
                eval_condition(b, trace, cx)?.truthy()
            }))
        }
        Expr::And(a, b) => {
            let av = eval_condition(a, trace, cx)?.truthy();
            Ok(Value::Bool(if av {
                eval_condition(b, trace, cx)?.truthy()
            } else {
                false
            }))
        }
        Expr::Not(a) => Ok(Value::Bool(!eval_condition(a, trace, cx)?.truthy())),
        other => crate::Evaluator::eval(other, cx),
    }
}

/// Convenience: build the trace for a conversation.
pub fn trace_of(conversation: &Conversation) -> Vec<Event> {
    quarry_core::event_trace(conversation)
}
