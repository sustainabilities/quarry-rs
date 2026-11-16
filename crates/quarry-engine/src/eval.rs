//! Tree-walking evaluator for non-flow expressions.
//! Port of the local (backend-free) evaluation paths of
//! `quarry/engine/{compiler,executor,matchers}.py`, guided by
//! `quarry/language/reference.md` semantics.

use std::collections::BTreeMap;

use quarry_core::Conversation;
use quarry_dsl::{Expr, FilterComp, Quantifier};

use crate::strings::{self, Modifiers};
use crate::value::{message_value, tool_call_value, Value};

/// Evaluation failure modes. `Unsupported` covers backend-backed constructs
/// (model ops, probers) — the caller records them as skipped, not failed.
#[derive(Debug, Clone, PartialEq)]
pub enum EvalError {
    Unsupported(String),
    TypeError(String),
    Unknown(String),
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalError::Unsupported(s) => write!(f, "unsupported: {s}"),
            EvalError::TypeError(s) => write!(f, "type error: {s}"),
            EvalError::Unknown(s) => write!(f, "unknown: {s}"),
        }
    }
}

pub type EvalResult = Result<Value, EvalError>;

impl From<String> for EvalError {
    fn from(s: String) -> Self {
        EvalError::TypeError(s)
    }
}

/// One scan's evaluation context: surfaces, strings, captures, parameters.
pub struct EvalContext<'a> {
    pub conversation: &'a Conversation,
    /// Canonical message maps (the `messages` surface).
    pub messages: Vec<Value>,
    /// Canonical tool-call maps, chronological, with `response` linked.
    pub tool_calls: Vec<Value>,
    /// Canonical tool-response maps, chronological.
    pub tool_responses: Vec<Value>,
    /// Offered tool definitions.
    pub tools: Vec<Value>,
    /// Declared strings: `$name` → (patterns, modifiers). Array defs hold
    /// every member; position/count/set semantics span all of them.
    pub strings: BTreeMap<String, (Vec<String>, Modifiers)>,
    /// Capture bindings (`x as name`).
    pub captures: BTreeMap<String, Value>,
    /// Declared parameters (scan-bound values).
    pub params: BTreeMap<String, Value>,
}

impl<'a> EvalContext<'a> {
    pub fn new(conversation: &'a Conversation, params: BTreeMap<String, Value>) -> Self {
        let messages = conversation
            .messages
            .iter()
            .map(|m| {
                let json = serde_json::to_value(m).expect("message serializes");
                message_value(&json)
            })
            .collect();
        let mut tool_calls = Vec::new();
        for m in &conversation.messages {
            for call in &m.tool_calls {
                let json = serde_json::to_value(call).expect("call serializes");
                tool_calls.push(tool_call_value(&json));
            }
        }
        // Canonical tool-response maps, linked to calls by id.
        let mut tool_responses: Vec<Value> = Vec::new();
        for m in &conversation.messages {
            let Some(cid) = &m.tool_call_id else { continue };
            let json = serde_json::to_value(m).expect("message serializes");
            let mut resp = BTreeMap::new();
            resp.insert(
                "content".into(),
                Value::Str(crate::value::flatten_content(json.get("content"))),
            );
            let content = resp.get("content").cloned().unwrap_or(Value::Null);
            resp.insert("result".into(), content);
            resp.insert("role".into(), Value::Str("tool".into()));
            resp.insert("tool_call_id".into(), Value::Str(cid.clone()));
            resp.insert("id".into(), Value::Str(cid.clone()));
            resp.insert("name".into(), Value::Null);
            resp.insert("call".into(), Value::Null);
            tool_responses.push(Value::Map(resp));
        }
        // Link: call.response = response; response.name/call = the call.
        for call in &mut tool_calls {
            let cid = match call {
                Value::Map(cm) => cm.get("id").and_then(|v| v.as_str()).map(String::from),
                _ => None,
            };
            let Some(cid) = cid else { continue };
            let matching = tool_responses
                .iter_mut()
                .find(|r| matches!(r, Value::Map(rm) if rm.get("tool_call_id").and_then(|v| v.as_str()) == Some(cid.as_str())));
            if let Some(Value::Map(rm)) = matching {
                let call_snapshot = call.clone();
                if let Value::Map(cm) = call {
                    rm.insert("name".into(), cm.get("name").cloned().unwrap_or(Value::Null));
                    rm.insert("call".into(), call_snapshot.clone());
                    cm.insert("response".into(), Value::Map(rm.clone()));
                }
            }
        }
        let tools = conversation
            .tool_definitions
            .iter()
            .map(|t| {
                let mut m = BTreeMap::new();
                m.insert("name".into(), Value::Str(t.name.clone()));
                m.insert("description".into(), Value::Str(t.description.clone()));
                m.insert("parameters".into(), Value::from_json(&t.parameters));
                m.insert("type".into(), Value::Str("function".into()));
                Value::Map(m)
            })
            .collect();
        Self {
            conversation,
            messages,
            tool_calls,
            tool_responses,
            tools,
            strings: BTreeMap::new(),
            captures: BTreeMap::new(),
            params,
        }
    }

    fn surface(&self, name: &str) -> EvalResult {
        Ok(match name {
            "messages" => Value::Array(self.messages.clone()),
            "user_messages" => Value::Array(self.filter_role("user")),
            "assistant_messages" => Value::Array(self.filter_role("assistant")),
            "system_messages" => Value::Array(self.filter_role("system")),
            "developer_messages" => Value::Array(self.filter_role("developer")),
            "system_prompt" => Value::Str(
                self.messages
                    .iter()
                    .find(|m| m_field(m, "role") == Some("system"))
                    .and_then(|m| match m {
                        Value::Map(mm) => mm.get("content").cloned(),
                        _ => None,
                    })
                    .map(|v| v.text_form().unwrap_or_default())
                    .unwrap_or_default(),
            ),
            "tool_calls" => Value::Array(self.tool_calls.clone()),
            "tool_responses" => Value::Array(self.tool_responses.clone()),
            "tools" => Value::Array(self.tools.clone()),
            other => {
                if let Some(v) = self.captures.get(other) {
                    return Ok(v.clone());
                }
                if let Some(v) = self.params.get(other) {
                    return Ok(v.clone());
                }
                return Err(EvalError::Unknown(format!("unknown surface or name `{other}`")));
            }
        })
    }

    fn filter_role(&self, role: &str) -> Vec<Value> {
        self.messages
            .iter()
            .filter(|m| m_field(m, "role") == Some(role))
            .cloned()
            .collect()
    }
}

fn m_field<'v>(m: &'v Value, field: &str) -> Option<&'v str> {
    match m {
        Value::Map(mm) => mm.get(field).and_then(|v| v.as_str()),
        _ => None,
    }
}

/// Field lookup as text — used by the flow guards.
pub fn eval_field(v: &Value, field: &str) -> Option<String> {
    match v {
        Value::Map(m) => m.get(field).and_then(|x| x.text_form()),
        _ => None,
    }
}

/// The evaluator. `variables:` are inlined by the caller before evaluation
/// (authoring sugar, mirroring the upstream transformer).
pub struct Evaluator;

impl Evaluator {
    pub fn eval(expr: &Expr, cx: &mut EvalContext) -> EvalResult {
        match expr {
            Expr::Or(a, b) => {
                let av = Self::eval(a, cx)?.truthy();
                Ok(Value::Bool(if av { true } else { Self::eval(b, cx)?.truthy() }))
            }
            Expr::And(a, b) => {
                let av = Self::eval(a, cx)?.truthy();
                Ok(Value::Bool(if av { Self::eval(b, cx)?.truthy() } else { false }))
            }
            Expr::Not(a) => Ok(Value::Bool(!Self::eval(a, cx)?.truthy())),

            Expr::Comparison { op, left, right } => {
                let l = Self::eval(left, cx)?;
                let r = Self::eval(right, cx)?;
                compare(op, &l, &r)
            }

            Expr::Contains(l, r) => {
                let lv = Self::eval(l, cx)?;
                // Declared strings carry their modifiers (nocase etc.).
                let mods = match r.as_ref() {
                    Expr::StringVar(name) => string_def(cx, name)?.1,
                    _ => Modifiers::default(),
                };
                let rv = Self::eval(r, cx)?;
                contains(&lv, &rv, &mods)
            }
            Expr::ContainsAny(l, rhs) => {
                let lv = Self::eval(l, cx)?;
                let patterns = match rhs {
                    quarry_dsl::ContainsAnyRhs::Array(items) => {
                        let mut pats = Vec::new();
                        for i in items {
                            let v = Self::eval(i, cx)?;
                            pats.push(v.text_form().ok_or_else(|| {
                                EvalError::TypeError("contains_any expects text values".into())
                            })?);
                        }
                        pats
                    }
                    quarry_dsl::ContainsAnyRhs::StringVar(name) => {
                        let (pats, mods) = string_def(cx, name)?;
                        // An array string def expands to its members.
                        return contains_any(&lv, &pats, &mods);
                    }
                };
                contains_any(&lv, &patterns, &Modifiers::default())
            }
            Expr::RegexMatch(l, r) => {
                let lv = Self::eval(l, cx)?;
                let rv = Self::eval(r, cx)?;
                let text = lv
                    .text_form()
                    .ok_or_else(|| EvalError::TypeError("`~` expects text".into()))?;
                let pat = rv
                    .text_form()
                    .ok_or_else(|| EvalError::TypeError("`~` expects a text pattern".into()))?;
                Ok(Value::Bool(strings::match_regex(&text, &pat, false)?))
            }
            Expr::MatchesPattern(l, block) => {
                let lv = Self::eval(l, cx)?;
                Ok(Value::Bool(eval_pattern_block(&lv, block, cx)?))
            }
            Expr::In(l, r) => {
                // Position / count / set / declared-string LHS bind to the
                // text RHS before general evaluation.
                match l.as_ref() {
                    Expr::StringPosition { name, .. } => {
                        let rv = Self::eval(r, cx)?;
                        let text = rv.text_form().ok_or_else(|| {
                            EvalError::TypeError("`@name in` expects text".into())
                        })?;
                        let (pats, mods) = string_def(cx, name)?;
                        let mut best: Option<usize> = None;
                        for p in &pats {
                            if let Some(pos) = strings::find_position(&text, p, &mods)? {
                                best = Some(match best {
                                    Some(b) => b.min(pos),
                                    None => pos,
                                });
                            }
                        }
                        return Ok(match best {
                            Some(p) => Value::Num(p as f64),
                            None => Value::Null,
                        });
                    }
                    Expr::StringCount { name, .. } => {
                        let rv = Self::eval(r, cx)?;
                        let text = rv.text_form().ok_or_else(|| {
                            EvalError::TypeError("`#name in` expects text".into())
                        })?;
                        let (pats, mods) = string_def(cx, name)?;
                        let mut n = 0usize;
                        for p in &pats {
                            n += strings::count_occurrences(&text, p, &mods)?;
                        }
                        return Ok(Value::Num(n as f64));
                    }
                    Expr::StringSet { quantifier, list } => {
                        let rv = Self::eval(r, cx)?;
                        let text = rv.text_form().ok_or_else(|| {
                            EvalError::TypeError("string set `in` expects text".into())
                        })?;
                        // Expand wildcard entries: every declared string
                        // whose name starts with the prefix.
                        let mut names: Vec<(String, bool)> = Vec::new();
                        for (name, wild) in list {
                            if *wild {
                                for key in cx.strings.keys() {
                                    if key.starts_with(name.as_str()) && !key.contains('#') {
                                        names.push((key.clone(), false));
                                    }
                                }
                            } else {
                                names.push((name.clone(), false));
                            }
                        }
                        let mut hits = 0usize;
                        for (name, _wild) in &names {
                            let (pats, mods) = string_def(cx, name)?;
                            for p in &pats {
                                if strings::match_contains(&text, p, &mods)? {
                                    hits += 1;
                                    break;
                                }
                            }
                        }
                        return Ok(Value::Bool(match quantifier {
                            Quantifier::Any => hits > 0,
                            Quantifier::All => hits == names.len(),
                            Quantifier::Count(n) => hits as f64 >= *n,
                        }));
                    }
                    _ => {}
                }
                let lv = Self::eval(l, cx)?;
                let rv = Self::eval(r, cx)?;
                eval_in(&lv, &rv, cx)
            }
            Expr::InWithCapture { needle, haystack, capture } => {
                let nv = Self::eval(needle, cx)?;
                let hv = Self::eval(haystack, cx)?;
                // Capture the matched occurrence (or the needle itself for
                // non-text membership) and require every later use to agree.
                let bound = capture_value(&nv, &hv, cx)?;
                cx.captures.insert(capture.clone(), bound.clone());
                Ok(Value::Bool(true))
            }
            Expr::Assignment(l, name) => {
                let v = Self::eval(l, cx)?;
                cx.captures.insert(name.clone(), v.clone());
                Ok(v)
            }

            Expr::Add(a, b) => arith(a, b, cx, |x, y| x + y),
            Expr::Sub(a, b) => arith(a, b, cx, |x, y| x - y),
            Expr::Mul(a, b) => arith(a, b, cx, |x, y| x * y),

            Expr::FunctionCall { name, args } => eval_function(name, args, cx),
            Expr::MethodCall { receiver, name, args } => {
                // Collection methods: `messages.called_tool("send")` — any
                // message in the collection issued this tool call.
                if name == "called_tool" {
                    let rv = Self::eval(receiver, cx)?;
                    let target = match args.first() {
                        Some(a) => Self::eval(a, cx)?
                            .text_form()
                            .ok_or_else(|| EvalError::TypeError("called_tool expects text".into()))?,
                        None => return Err(EvalError::TypeError("called_tool expects a name".into())),
                    };
                    let Value::Array(items) = rv else {
                        return Err(EvalError::TypeError("method receiver must be a collection".into()));
                    };
                    let hit = items.iter().any(|item| match item {
                        Value::Map(m) => matches!(
                            m.get("tool_calls"),
                            Some(Value::Array(calls)) if calls.iter().any(|c| {
                                crate::eval_field(c, "name").as_deref() == Some(target.as_str())
                            })
                        ),
                        _ => false,
                    });
                    return Ok(Value::Bool(hit));
                }
                Err(EvalError::Unsupported(format!("method `.{name}(...)` requires a model backend")))
            }
            Expr::AttrAccess { receiver, name } => {
                let rv = Self::eval(receiver, cx)?;
                match &rv {
                    Value::Map(m) => Ok(m.get(name).cloned().unwrap_or(Value::Null)),
                    _ => Err(EvalError::TypeError(format!(
                        "field access `.{name}` on non-object"
                    ))),
                }
            }
            Expr::Index { receiver, index } => {
                let rv = Self::eval(receiver, cx)?;
                let iv = Self::eval(index, cx)?;
                let idx = iv
                    .as_num()
                    .ok_or_else(|| EvalError::TypeError("index must be a number".into()))?;
                index_value(&rv, idx as i64)
            }
            Expr::Slice { receiver, from, to } => {
                let rv = Self::eval(receiver, cx)?;
                slice_value(&rv, *from, *to)
            }
            Expr::SliceAll(receiver) => {
                let rv = Self::eval(receiver, cx)?;
                slice_value(&rv, None, None)
            }
            Expr::WildcardPostfix(receiver) => {
                // `.*` — expand object values into an array.
                let rv = Self::eval(receiver, cx)?;
                match rv {
                    Value::Map(m) => Ok(Value::Array(m.into_values().collect())),
                    Value::Array(a) => Ok(Value::Array(a)),
                    _ => Err(EvalError::TypeError("`.*` expects an object".into())),
                }
            }

            Expr::StringPosition { name, .. } => {
                // Bare `@name` (no `in`) is not in the P2 surface.
                let _ = name;
                Err(EvalError::Unsupported("`@name` requires an `in text` context".into()))
            }
            Expr::StringCount { name, .. } => {
                let _ = name;
                Err(EvalError::Unsupported("`#name` requires an `in text` context".into()))
            }
            Expr::StringSet { .. } => Err(EvalError::Unsupported(
                "string sets require an `in text` context".into(),
            )),
            Expr::StringVar(name) => {
                let (pats, _mods) = string_def(cx, name)?;
                Ok(Value::Str(pats.first().cloned().unwrap_or_default()))
            }

            Expr::Ident(name) => cx.surface(name),
            Expr::StringLit(s) => Ok(Value::Str(s.clone())),
            Expr::Number(n) => Ok(Value::Num(*n)),
            Expr::Bool(b) => Ok(Value::Bool(*b)),
            Expr::Null => Ok(Value::Null),
            Expr::Array(items) => {
                let mut out = Vec::new();
                for i in items {
                    out.push(Self::eval(i, cx)?);
                }
                Ok(Value::Array(out))
            }

            Expr::AnyComp { var, iter, cond } => {
                let items = Self::eval(iter, cx)?;
                let Value::Array(list) = items else {
                    return Err(EvalError::TypeError("`any` iterates a collection".into()));
                };
                if list.is_empty() {
                    return Ok(Value::Bool(false));
                }
                for item in &list {
                    let saved = cx.captures.insert(var.clone(), item.clone());
                    let hit = Self::eval(cond, cx)?.truthy();
                    if saved.is_some() { cx.captures.insert(var.clone(), saved.unwrap()); } else { cx.captures.remove(&var.clone()); }
                    if hit {
                        return Ok(Value::Bool(true));
                    }
                }
                Ok(Value::Bool(false))
            }
            Expr::AllComp { var, iter, cond } => {
                let items = Self::eval(iter, cx)?;
                let Value::Array(list) = items else {
                    return Err(EvalError::TypeError("`all` iterates a collection".into()));
                };
                if list.is_empty() {
                    return Ok(Value::Bool(true));
                }
                for item in &list {
                    let saved = cx.captures.insert(var.clone(), item.clone());
                    let hit = Self::eval(cond, cx)?.truthy();
                    if saved.is_some() { cx.captures.insert(var.clone(), saved.unwrap()); } else { cx.captures.remove(&var.clone()); }
                    if !hit {
                        return Ok(Value::Bool(false));
                    }
                }
                Ok(Value::Bool(true))
            }
            Expr::MapComp { expr, var, iter, cond } => {
                let items = Self::eval(iter, cx)?;
                let Value::Array(list) = items else {
                    return Err(EvalError::TypeError("map comprehension iterates a collection".into()));
                };
                let mut out = Vec::new();
                for item in &list {
                    let saved = cx.captures.insert(var.clone(), item.clone());
                    let keep = match &cond {
                        Some(c) => Self::eval(c, cx)?.truthy(),
                        None => true,
                    };
                    if keep {
                        out.push(Self::eval(expr, cx)?);
                    }
                    if saved.is_some() { cx.captures.insert(var.clone(), saved.unwrap()); } else { cx.captures.remove(&var.clone()); }
                }
                Ok(Value::Array(out))
            }
            Expr::Filter(FilterComp { item: _item, var, iter, cond }) => {
                let items = Self::eval(iter, cx)?;
                let Value::Array(list) = items else {
                    return Err(EvalError::TypeError("filter comprehension iterates a collection".into()));
                };
                let mut out = Vec::new();
                for e in &list {
                    let saved = cx.captures.insert(var.clone(), e.clone());
                    let keep = Self::eval(cond, cx)?.truthy();
                    if saved.is_some() { cx.captures.insert(var.clone(), saved.unwrap()); } else { cx.captures.remove(&var.clone()); }
                    if keep {
                        // The item name is the loop variable: the kept
                        // element itself is the projected value.
                        out.push(e.clone());
                    }
                }
                Ok(Value::Array(out))
            }

            Expr::Flow { .. } => Err(EvalError::Unsupported(
                "flow operators are compiled to the automaton, not evaluated here".into(),
            )),
        }
    }
}

fn arith(a: &Expr, b: &Expr, cx: &mut EvalContext, f: fn(f64, f64) -> f64) -> EvalResult {
    let av = Evaluator::eval(a, cx)?;
    let bv = Evaluator::eval(b, cx)?;
    // Null operands (e.g. a string position that found nothing) propagate:
    // comparisons against Null are false, not errors.
    if matches!(av, Value::Null) || matches!(bv, Value::Null) {
        return Ok(Value::Null);
    }
    let x = av.as_num().ok_or_else(|| EvalError::TypeError("arithmetic expects numbers".into()))?;
    let y = bv.as_num().ok_or_else(|| EvalError::TypeError("arithmetic expects numbers".into()))?;
    Ok(Value::Num(f(x, y)))
}

fn compare(op: &quarry_dsl::CmpOp, l: &Value, r: &Value) -> EvalResult {
    use quarry_dsl::CmpOp;
    // Null operands: only `!=` between distinct values is true; everything
    // else is false (upstream: a missing position/count never matches).
    if matches!(l, Value::Null) || matches!(r, Value::Null) {
        return Ok(Value::Bool(matches!(op, CmpOp::Neq) && l != r));
    }
    // Numeric comparison
    if let (Some(x), Some(y)) = (l.as_num(), r.as_num()) {
        return Ok(Value::Bool(match op {
            CmpOp::Eq => x == y,
            CmpOp::Neq => x != y,
            CmpOp::Gt => x > y,
            CmpOp::Lt => x < y,
            CmpOp::Gte => x >= y,
            CmpOp::Lte => x <= y,
        }));
    }
    // Text comparison
    if let (Some(x), Some(y)) = (l.text_form(), r.text_form()) {
        return Ok(Value::Bool(match op {
            CmpOp::Eq => x == y,
            CmpOp::Neq => x != y,
            CmpOp::Gt => x > y,
            CmpOp::Lt => x < y,
            CmpOp::Gte => x >= y,
            CmpOp::Lte => x <= y,
        }));
    }
    // Structural equality for maps/arrays/null
    match op {
        CmpOp::Eq => Ok(Value::Bool(l == r)),
        CmpOp::Neq => Ok(Value::Bool(l != r)),
        _ => Err(EvalError::TypeError(format!(
            "cannot order {l:?} and {r:?}"
        ))),
    }
}

fn contains(l: &Value, r: &Value, mods: &Modifiers) -> EvalResult {
    // A capture that bound no value makes every use of it false.
    let Some(pat) = r.text_form() else {
        return Ok(Value::Bool(false));
    };
    match l {
        Value::Str(s) => Ok(Value::Bool(strings::match_contains(s, &pat, mods)?)),
        Value::Array(items) => Ok(Value::Bool(items.iter().any(|i| {
            match i.text_form() {
                Some(t) => strings::match_contains(&t, &pat, mods).unwrap_or(false),
                None => *i == r.clone(),
            }
        }))),
        _ => Err(EvalError::TypeError("`contains` expects text or collection".into())),
    }
}

fn contains_any(l: &Value, patterns: &[String], mods: &Modifiers) -> EvalResult {
    match l {
        Value::Str(s) => {
            for p in patterns {
                if strings::match_contains(s, p, mods)? {
                    return Ok(Value::Bool(true));
                }
            }
            Ok(Value::Bool(false))
        }
        Value::Array(items) => {
            for i in items {
                if let Some(t) = i.text_form() {
                    for p in patterns {
                        if strings::match_contains(&t, p, mods)? {
                            return Ok(Value::Bool(true));
                        }
                    }
                }
            }
            Ok(Value::Bool(false))
        }
        _ => Err(EvalError::TypeError("`contains_any` expects text or collection".into())),
    }
}

fn string_def(cx: &EvalContext, name: &str) -> Result<(Vec<String>, Modifiers), EvalError> {
    cx.strings
        .get(name)
        .cloned()
        .ok_or_else(|| EvalError::Unknown(format!("undeclared string ${name}")))
}

/// `x in y` — the overloaded membership/position/count/set form.
fn eval_in(l: &Value, r: &Value, cx: &mut EvalContext) -> EvalResult {
    // Text RHS: string semantics (position, count, set, declared string).
    let rtext = r.text_form();
    if let Some(text) = rtext {
        // LHS may be a position/count/set/declared-string expression already
        // reduced to a marker value by the caller — handled via special
        // marker values inserted by Expression wrappers in flow.rs; here we
        // cover: declared string var, literal string, set via marker.
        match l {
            Value::Str(pat) => {
                let mods = cx
                    .strings
                    .iter()
                    .find(|(_, (pats, _))| pats.iter().any(|p| p == pat))
                    .map(|(_, (_, m))| *m)
                    .unwrap_or_default();
                return Ok(Value::Bool(strings::match_contains(&text, pat, &mods)?));
            }
            _ => {
                return Err(EvalError::TypeError("`in` expects a string pattern LHS here".into()))
            }
        }
    }
    // Collection RHS: membership.
    if let Value::Array(items) = r {
        return Ok(Value::Bool(items.contains(l)));
    }
    Err(EvalError::TypeError("`in` expects text or collection RHS".into()))
}

/// `x in y as capture` — capture the matched occurrence (text) or the value.
fn capture_value(nv: &Value, hv: &Value, cx: &mut EvalContext) -> Result<Value, EvalError> {
    let text = hv.text_form().ok_or_else(|| {
        EvalError::TypeError("capture `in` expects text RHS".into())
    })?;
    match nv {
        Value::Str(pat) => {
            let mods = cx
                .strings
                .iter()
                .find(|(_, (pats, _))| pats.iter().any(|p| p == pat))
                .map(|(_, (_, m))| *m)
                .unwrap_or_default();
            // The matched substring (original casing on the literal path).
            match strings::find_position(&text, pat, &mods)? {
                Some(pos) => {
                    let (eff, use_regex) = strings::apply_modifiers(pat, &mods);
                    let len = if use_regex {
                        strings::compile_regex(&eff, mods.nocase)?
                            .find(&text)
                            .map(|m| m.as_str().len())
                            .unwrap_or(0)
                    } else {
                        eff.chars().count().min(text.chars().count() - pos)
                    };
                    let matched: String = text
                        .char_indices()
                        .skip_while(|(i, _)| *i < pos)
                        .take(len)
                        .map(|(_, c)| c)
                        .collect();
                    if matched.is_empty() {
                        Ok(Value::Str(pat.clone()))
                    } else {
                        Ok(Value::Str(matched))
                    }
                }
                None => Ok(Value::Null),
            }
        }
        other => Ok(other.clone()),
    }
}

fn eval_pattern_block(
    lv: &Value,
    block: &quarry_dsl::PatternBlock,
    cx: &mut EvalContext,
) -> Result<bool, EvalError> {
    let Value::Map(m) = lv else {
        return Err(EvalError::TypeError("`matches` expects an object".into()));
    };
    'alts: for alt in &block.alternatives {
        // Field name relative to the matched value.
        let field = match &alt.lhs {
            Expr::Ident(name) => name.clone(),
            other => {
                let v = Evaluator::eval(other, cx)?;
                v.text_form().unwrap_or_default()
            }
        };
        let actual = m.get(&field).cloned().unwrap_or(Value::Null);
        let expected = Evaluator::eval(&alt.rhs, cx)?;
        let ok = if alt.contains {
            match (&actual.text_form(), &expected.text_form()) {
                (Some(a), Some(e)) => a.contains(e.as_str()),
                _ => false,
            }
        } else {
            compare(&alt.op, &actual, &expected)?.truthy()
        };
        if !ok {
            continue 'alts;
        }
        return Ok(true);
    }
    Ok(false)
}

fn index_value(v: &Value, idx: i64) -> EvalResult {
    match v {
        Value::Array(items) => {
            let n = items.len() as i64;
            let i = if idx < 0 { n + idx } else { idx };
            if i < 0 || i >= n {
                Ok(Value::Null)
            } else {
                Ok(items[i as usize].clone())
            }
        }
        Value::Map(m) => {
            // String index into map — not supported in P2.
            let _ = m;
            Err(EvalError::TypeError("index expects a collection".into()))
        }
        _ => Err(EvalError::TypeError("index expects a collection".into())),
    }
}

fn slice_value(v: &Value, from: Option<i64>, to: Option<i64>) -> EvalResult {
    let Value::Array(items) = v else {
        return Err(EvalError::TypeError("slice expects a collection".into()));
    };
    let n = items.len() as i64;
    let norm = |x: i64| -> i64 {
        if x < 0 { (n + x).max(0) } else { x.min(n) }
    };
    let start = from.map(norm).unwrap_or(0);
    let end = to.map(norm).unwrap_or(n);
    if start >= end {
        return Ok(Value::Array(vec![]));
    }
    Ok(Value::Array(items[start as usize..end as usize].to_vec()))
}

/// Built-in functions (backend-free subset; model/prober functions report
/// `Unsupported` so the conformance runner records them as backend-skipped).
fn eval_function(name: &str, args: &[Expr], cx: &mut EvalContext) -> EvalResult {
    match name {
        "len" => {
            expect_arity(name, args, 1)?;
            let v = Evaluator::eval(&args[0], cx)?;
            Ok(Value::Num(len_of(&v)? as f64))
        }
        "count" => {
            expect_arity(name, args, 1)?;
            let v = Evaluator::eval(&args[0], cx)?;
            if args.len() == 2 {
                let pat = Evaluator::eval(&args[1], cx)?;
                let p = pat
                    .text_form()
                    .ok_or_else(|| EvalError::TypeError("count pattern must be text".into()))?;
                Ok(Value::Num(count_pattern_in(&v, &p, cx)? as f64))
            } else {
                Ok(Value::Num(len_of(&v)? as f64))
            }
        }
        "user_said" | "assistant_said" => {
            expect_arity(name, args, 1)?;
            let text = Evaluator::eval(&args[0], cx)?;
            let t = text
                .text_form()
                .ok_or_else(|| EvalError::TypeError(format!("{name} expects text")))?;
            let role = if name == "user_said" { "user" } else { "assistant" };
            Ok(Value::Bool(
                cx.messages
                    .iter()
                    .filter(|m| m_field(m, "role") == Some(role))
                    .any(|m| {
                        let content = m_field(m, "content").unwrap_or("");
                        content.contains(&t)
                    }),
            ))
        }
        "called_tool" => {
            expect_arity(name, args, 1)?;
            let n = Evaluator::eval(&args[0], cx)?;
            let n = n
                .text_form()
                .ok_or_else(|| EvalError::TypeError("called_tool expects text".into()))?;
            Ok(Value::Bool(
                cx.tool_calls
                    .iter()
                    .any(|c| m_field(c, "name") == Some(n.as_str())),
            ))
        }
        "called_tools" => {
            let mut names = Vec::new();
            for a in args {
                let v = Evaluator::eval(a, cx)?;
                names.push(v.text_form().ok_or_else(|| {
                    EvalError::TypeError("called_tools expects text names".into())
                })?);
            }
            Ok(Value::Bool(names.iter().all(|n| {
                cx.tool_calls.iter().any(|c| m_field(c, "name") == Some(n.as_str()))
            })))
        }
        "count_tool_calls" => {
            expect_arity(name, args, 1)?;
            let n = Evaluator::eval(&args[0], cx)?;
            let n = n
                .text_form()
                .ok_or_else(|| EvalError::TypeError("count_tool_calls expects text".into()))?;
            Ok(Value::Num(
                cx.tool_calls
                    .iter()
                    .filter(|c| m_field(c, "name") == Some(n.as_str()))
                    .count() as f64,
            ))
        }
        "call_sequence" => Ok(Value::Array(
            cx.tool_calls
                .iter()
                .map(|c| Value::Str(m_field(c, "name").unwrap_or("").to_string()))
                .collect(),
        )),
        "has_tool" => {
            expect_arity(name, args, 1)?;
            let n = Evaluator::eval(&args[0], cx)?;
            let n = n.text_form().ok_or_else(|| EvalError::TypeError("has_tool expects text".into()))?;
            Ok(Value::Bool(
                cx.tools.iter().any(|t| m_field(t, "name") == Some(n.as_str())),
            ))
        }
        "has_tools" => {
            let mut names = Vec::new();
            for a in args {
                let v = Evaluator::eval(a, cx)?;
                names.push(v.text_form().ok_or_else(|| {
                    EvalError::TypeError("has_tools expects text names".into())
                })?);
            }
            Ok(Value::Bool(names.iter().all(|n| {
                cx.tools.iter().any(|t| m_field(t, "name") == Some(n.as_str()))
            })))
        }
        "has_sequence" => {
            let mut names = Vec::new();
            for a in args {
                let v = Evaluator::eval(a, cx)?;
                names.push(v.text_form().ok_or_else(|| {
                    EvalError::TypeError("has_sequence expects text names".into())
                })?);
            }
            let seq: Vec<&str> = cx
                .tool_calls
                .iter()
                .map(|c| m_field(c, "name").unwrap_or(""))
                .collect();
            'outer: for start in 0..seq.len() {
                if start + names.len() > seq.len() {
                    break;
                }
                for (i, n) in names.iter().enumerate() {
                    if seq[start + i] != n.as_str() {
                        continue 'outer;
                    }
                }
                return Ok(Value::Bool(true));
            }
            Ok(Value::Bool(false))
        }
        "get_tool_calls" => {
            expect_arity(name, args, 1)?;
            let n = Evaluator::eval(&args[0], cx)?;
            let n = n.text_form().ok_or_else(|| EvalError::TypeError("get_tool_calls expects text".into()))?;
            Ok(Value::Array(
                cx.tool_calls
                    .iter()
                    .filter(|c| m_field(c, "name") == Some(n.as_str()))
                    .cloned()
                    .collect(),
            ))
        }
        "get_tool_responses" => {
            expect_arity(name, args, 1)?;
            let n = Evaluator::eval(&args[0], cx)?;
            let n = n.text_form().ok_or_else(|| EvalError::TypeError("get_tool_responses expects text".into()))?;
            Ok(Value::Array(
                cx.tool_responses
                    .iter()
                    .filter(|r| match r {
                        Value::Map(rm) => rm
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(|x| x == n)
                            .unwrap_or(false),
                        _ => false,
                    })
                    .cloned()
                    .collect(),
            ))
        }
        "join" => {
            expect_arity(name, args, 2)?;
            let v = Evaluator::eval(&args[0], cx)?;
            let sep = Evaluator::eval(&args[1], cx)?;
            let sep = sep.text_form().unwrap_or_default();
            let Value::Array(items) = v else {
                return Err(EvalError::TypeError("join expects a collection".into()));
            };
            let parts: Vec<String> = items
                .iter()
                .filter_map(|i| i.text_form())
                .collect();
            Ok(Value::Str(parts.join(&sep)))
        }
        "message" | "add_message" | "conversation" | "text_ref" | "if_refused" | "refused" => {
            Err(EvalError::Unsupported(format!(
                "function `{name}` is model-input/backend surface (P4)"
            )))
        }
        "capability_tags" | "off_topic" | "topic_drift" | "unrequested_action" => {
            Err(EvalError::Unsupported(format!("prober `{name}` requires a backend")))
        }
        "llm_score" | "llm_complete" | "llm_input_tokens" | "llm_split_conversation"
        | "model_score" | "model_scan" | "model_split" => Err(EvalError::Unsupported(format!(
            "function `{name}` requires a model backend"
        ))),
        other => Err(EvalError::Unknown(format!("unknown function `{other}`"))),
    }
}

fn expect_arity(name: &str, args: &[Expr], n: usize) -> Result<(), EvalError> {
    if args.len() < n {
        Err(EvalError::TypeError(format!(
            "`{name}` expects at least {n} argument(s), got {}",
            args.len()
        )))
    } else {
        Ok(())
    }
}

fn len_of(v: &Value) -> Result<usize, EvalError> {
    match v {
        Value::Str(s) => Ok(s.chars().count()),
        Value::Array(a) => Ok(a.len()),
        Value::Map(m) => Ok(m.len()),
        Value::Null => Ok(0),
        _ => Err(EvalError::TypeError("len expects a collection or text".into())),
    }
}

fn count_pattern_in(v: &Value, pat: &str, cx: &EvalContext) -> Result<usize, EvalError> {
    match v {
        Value::Str(s) => Ok(strings::count_occurrences(s, pat, &Modifiers::default())?),
        Value::Array(items) => {
            let mut total = 0;
            for i in items {
                total += count_pattern_in(i, pat, cx)?;
            }
            Ok(total)
        }
        Value::Map(m) => {
            let mut total = 0;
            for (_, val) in m {
                total += count_pattern_in(val, pat, cx)?;
            }
            Ok(total)
        }
        Value::Null => Ok(0),
        other => {
            let t = other.text_form().unwrap_or_default();
            Ok(strings::count_occurrences(&t, pat, &Modifiers::default())?)
        }
    }
}
