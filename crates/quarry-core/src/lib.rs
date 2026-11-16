//! quarry-core — the canonical event model and limits.
//!
//! Rust port of `quarry/core/conversation.py` + the event layer of
//! `quarry/engine/events.py`. The engine executes compiled rules over a
//! finite event trace derived from an OpenAI-shaped conversation.

use serde::{Deserialize, Serialize};

/// Message role. Unknown roles are preserved verbatim (forward compatibility).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RoleRepr", into = "RoleRepr")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
    Developer,
    Other(String),
}

#[derive(Serialize, Deserialize)]
enum RoleRepr {
    #[serde(rename = "system")]
    System,
    #[serde(rename = "user")]
    User,
    #[serde(rename = "assistant")]
    Assistant,
    #[serde(rename = "tool")]
    Tool,
    #[serde(rename = "developer")]
    Developer,
    #[serde(untagged)]
    Other(String),
}

impl From<RoleRepr> for Role {
    fn from(r: RoleRepr) -> Self {
        match r {
            RoleRepr::System => Role::System,
            RoleRepr::User => Role::User,
            RoleRepr::Assistant => Role::Assistant,
            RoleRepr::Tool => Role::Tool,
            RoleRepr::Developer => Role::Developer,
            RoleRepr::Other(s) => Role::Other(s),
        }
    }
}

impl From<Role> for RoleRepr {
    fn from(r: Role) -> Self {
        match r {
            Role::System => RoleRepr::System,
            Role::User => RoleRepr::User,
            Role::Assistant => RoleRepr::Assistant,
            Role::Tool => RoleRepr::Tool,
            Role::Developer => RoleRepr::Developer,
            Role::Other(s) => RoleRepr::Other(s),
        }
    }
}

impl Role {
    pub fn parse(s: &str) -> Self {
        match s {
            "system" => Role::System,
            "user" => Role::User,
            "assistant" => Role::Assistant,
            "tool" => Role::Tool,
            "developer" => Role::Developer,
            other => Role::Other(other.to_string()),
        }
    }
}

/// One conversation message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    /// Text content. Non-text parts are normalized by the host before scanning.
    pub content: String,
    /// Tool calls issued by this (assistant) message, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// For role=Tool: the id of the call this result answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// A tool call issued by the assistant. Accepts both the OpenAI wire shape
/// (`function: {name, arguments}`) and the canonical flat shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "ToolCallRepr", into = "ToolCallRepr")]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// Arguments as received; validated lazily by rules that index into them.
    pub arguments: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct ToolCallRepr {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    function: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    arguments: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,
}

impl From<ToolCallRepr> for ToolCall {
    fn from(r: ToolCallRepr) -> Self {
        let (name, arguments) = match r.function {
            Some(f) => (
                f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                f.get("arguments").cloned().unwrap_or(serde_json::Value::Null),
            ),
            None => (
                r.name.unwrap_or_default(),
                r.arguments.unwrap_or(serde_json::Value::Null),
            ),
        };
        // OpenAI transmits arguments as a JSON string; decode when possible.
        let arguments = match &arguments {
            serde_json::Value::String(s) => {
                serde_json::from_str::<serde_json::Value>(s).unwrap_or_else(|_| arguments.clone())
            }
            other => other.clone(),
        };
        ToolCall { id: r.id, name, arguments }
    }
}

impl From<ToolCall> for ToolCallRepr {
    fn from(c: ToolCall) -> Self {
        ToolCallRepr {
            id: c.id,
            function: None,
            name: Some(c.name),
            arguments: Some(c.arguments),
            r#type: Some("function".into()),
        }
    }
}

/// A tool definition offered to the model. Accepts both the OpenAI wire
/// shape (`function: {name, description, parameters}`) and the flat shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "ToolDefRepr", into = "ToolDefRepr")]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct ToolDefRepr {
    #[serde(default)]
    function: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Option<serde_json::Value>,
    #[serde(default)]
    r#type: Option<String>,
}

impl From<ToolDefRepr> for ToolDefinition {
    fn from(r: ToolDefRepr) -> Self {
        match r.function {
            Some(f) => ToolDefinition {
                name: f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                description: f.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string(),
                parameters: f.get("parameters").cloned().unwrap_or(serde_json::Value::Null),
            },
            None => ToolDefinition {
                name: r.name.unwrap_or_default(),
                description: r.description.unwrap_or_default(),
                parameters: r.parameters.unwrap_or(serde_json::Value::Null),
            },
        }
    }
}

impl From<ToolDefinition> for ToolDefRepr {
    fn from(t: ToolDefinition) -> Self {
        ToolDefRepr {
            function: None,
            name: Some(t.name),
            description: Some(t.description),
            parameters: Some(t.parameters),
            r#type: Some("function".into()),
        }
    }
}

/// The canonical conversation input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub messages: Vec<Message>,
    #[serde(default, rename = "tools", skip_serializing_if = "Vec::is_empty")]
    pub tool_definitions: Vec<ToolDefinition>,
}

/// The kind of a normalized event in the execution trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    Message,
    ToolCall,
    ToolResult,
}

/// One event in the finite trace the DFA executes over.
/// Events are in conversation order; tool calls and results are separate
/// events so flow operators (`before`, `after`, `right_after`, `until`)
/// can relate them.
#[derive(Debug, Clone)]
pub struct Event {
    pub index: usize,
    pub kind: EventKind,
    pub message_index: usize,
    /// Ordinal of this event within its kind (call #0, call #1, … for
    /// ToolCall; result #0, … for ToolResult; message index for Message).
    pub ordinal: usize,
    /// Role of the source message for Message events.
    pub role_hint: Option<&'static str>,
}

fn role_hint(role: &Role) -> Option<&'static str> {
    match role {
        Role::System => Some("system"),
        Role::User => Some("user"),
        Role::Assistant => Some("assistant"),
        Role::Tool => Some("tool"),
        Role::Developer => Some("developer"),
        Role::Other(_) => None,
    }
}

/// Normalize a conversation into an event trace.
pub fn event_trace(conversation: &Conversation) -> Vec<Event> {
    let mut events = Vec::new();
    let mut call_ord = 0usize;
    let mut result_ord = 0usize;
    for (i, msg) in conversation.messages.iter().enumerate() {
        events.push(Event {
            index: events.len(),
            kind: EventKind::Message,
            message_index: i,
            ordinal: i,
            role_hint: role_hint(&msg.role),
        });
        for _ in &msg.tool_calls {
            events.push(Event {
                index: events.len(),
                kind: EventKind::ToolCall,
                message_index: i,
                ordinal: call_ord,
                role_hint: role_hint(&msg.role),
            });
            call_ord += 1;
        }
        if msg.role == Role::Tool {
            events.push(Event {
                index: events.len(),
                kind: EventKind::ToolResult,
                message_index: i,
                ordinal: result_ord,
                role_hint: role_hint(&msg.role),
            });
            result_ord += 1;
        }
    }
    events
}

/// Explicit input and resource limits. Quarry refuses unbounded work.
#[derive(Debug, Clone)]
pub struct ScanLimits {
    /// Maximum serialized conversation size accepted for a scan.
    pub max_input_bytes: usize,
    /// Maximum number of events in the normalized trace.
    pub max_events: usize,
    /// Scan deadline, in milliseconds from scan start.
    pub deadline_ms: u64,
    /// Maximum model-adapter calls for one scan.
    pub max_model_calls: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 8 * 1024 * 1024,
            max_events: 4_096,
            deadline_ms: 30_000,
            max_model_calls: 32,
        }
    }
}

/// Scan outcome status, mirroring `ScanResult` semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    /// Authoritative result: every rule reported a verdict.
    Complete,
    /// Input failed validation before execution.
    Invalid(String),
    /// Limits, deadline, or adapter failure stopped execution early.
    Incomplete(String),
    /// Fail-closed was bypassed by an authorized override nonce. The
    /// override covers *unavailability only* — it never flips a verdict:
    /// a rule that matched still matched.
    Overridden { reason: String, nonce: String },
}
