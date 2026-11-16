//! Value model — the typed values rules read and produce.
//! Port of the value layer of `quarry/types/` + `core/conversation.py`.
//! Messages, tool calls, and tool responses surface as maps with exactly
//! the documented fields (language/reference.md "Data surfaces").

use std::collections::BTreeMap;

use serde_json::Value as Json;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Num(n) => *n != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Array(_) | Value::Map(_) => true,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_num(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            _ => None,
        }
    }

    /// Text projection used when a value feeds a text operator.
    pub fn text_form(&self) -> Option<String> {
        match self {
            Value::Str(s) => Some(s.clone()),
            Value::Num(n) => Some(fmt_num(*n)),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn from_json(v: &Json) -> Self {
        match v {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(*b),
            Json::Number(n) => Value::Num(n.as_f64().unwrap_or(0.0)),
            Json::String(s) => Value::Str(s.clone()),
            Json::Array(a) => Value::Array(a.iter().map(Value::from_json).collect()),
            Json::Object(o) => {
                let mut m = BTreeMap::new();
                for (k, v) in o {
                    m.insert(k.clone(), Value::from_json(v));
                }
                Value::Map(m)
            }
        }
    }

    pub fn to_json(&self) -> Json {
        match self {
            Value::Null => Json::Null,
            Value::Bool(b) => Json::Bool(*b),
            Value::Num(n) => serde_json::Number::from_f64(*n)
                .map(Json::Number)
                .unwrap_or(Json::Null),
            Value::Str(s) => Json::String(s.clone()),
            Value::Array(a) => Json::Array(a.iter().map(Value::to_json).collect()),
            Value::Map(m) => {
                let mut o = serde_json::Map::new();
                for (k, v) in m {
                    o.insert(k.clone(), v.to_json());
                }
                Json::Object(o)
            }
        }
    }
}

/// Stable number formatting for text projection and equality display.
pub fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Normalize one OpenAI-shaped message JSON into the canonical map form.
pub fn message_value(msg: &Json) -> Value {
    let mut m = BTreeMap::new();
    let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("").to_string();
    m.insert("role".into(), Value::Str(role));
    m.insert("content".into(), Value::Str(flatten_content(msg.get("content"))));
    if let Some(r) = msg.get("refusal") {
        m.insert("refusal".into(), Value::from_json(r));
    }
    // Assistant tool calls, canonicalized.
    let calls: Vec<Value> = msg
        .get("tool_calls")
        .and_then(|t| t.as_array())
        .map(|a| a.iter().map(tool_call_value).collect())
        .unwrap_or_default();
    m.insert("tool_calls".into(), Value::Array(calls));
    if let Some(id) = msg.get("tool_call_id") {
        m.insert("tool_call_id".into(), Value::from_json(id));
    }
    Value::Map(m)
}

/// Decode OpenAI `arguments`: a JSON string on the wire, an object already
/// canonicalized, or null.
fn decode_arguments(v: Option<&Json>) -> Json {
    match v {
        Some(Json::String(s)) => serde_json::from_str::<Json>(s).unwrap_or(Json::Null),
        Some(other) => other.clone(),
        None => Json::Null,
    }
}

/// Canonical tool call: `{id, name, arguments, raw_arguments, type}`.
pub fn tool_call_value(call: &Json) -> Value {
    let mut m = BTreeMap::new();
    m.insert(
        "id".into(),
        Value::from_json(call.get("id").unwrap_or(&Json::Null)),
    );
    let (name, raw_args, args) = match call.get("function") {
        Some(f) => (
            f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
            f.get("arguments").cloned().unwrap_or(Json::String("{}".into())),
            decode_arguments(f.get("arguments")),
        ),
        None => (
            call.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
            call.get("arguments").cloned().unwrap_or(Json::String("{}".into())),
            decode_arguments(call.get("arguments")),
        ),
    };
    m.insert("name".into(), Value::Str(name));
    m.insert("raw_arguments".into(), Value::from_json(&raw_args));
    m.insert("arguments".into(), Value::from_json(&args));
    m.insert("type".into(), Value::from_json(call.get("type").unwrap_or(&Json::String("function".into()))));
    // `response` is linked later (tool_responses surface); null until then.
    m.insert("response".into(), Value::Null);
    Value::Map(m)
}

/// Flatten OpenAI content: string as-is; part arrays keep text parts only.
pub fn flatten_content(content: Option<&Json>) -> String {
    match content {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Array(parts)) => parts
            .iter()
            .filter_map(|p| {
                if p.get("type").and_then(|t| t.as_str()) == Some("text") {
                    p.get("text").and_then(|t| t.as_str()).map(String::from)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(""),
        Some(other) => other.to_string(),
    }
}
