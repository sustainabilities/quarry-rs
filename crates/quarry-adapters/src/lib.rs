//! quarry-adapters — the model-adapter boundary.
//!
//! Port of `quarry/engine/oracle.py` + the model-inference contract in
//! `docs/model-inference.md`. Rules reference models by *alias*; the host
//! application registers adapters that implement the operations an alias
//! supports. Quarry validates required aliases/operations at rule
//! preparation time — never mid-scan.
//!
//! Estate note: adapters are where Harbor Watch attaches — a model that is
//! not `fit` on its current shift must not serve a scan. See PORT-SPEC.md §6.

use quarry_core::Conversation;
use serde::{Deserialize, Serialize};

/// Which operations an alias exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Score,
    Classify,
    Complete,
    InputTokens,
    Spans,
    Split,
}

/// A configured model alias, resolved by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAlias {
    pub name: String,
    pub adapter: String,
    pub operations: Vec<Operation>,
}

/// Request for a scored judgment of messages against policy text.
#[derive(Debug, Clone)]
pub struct ScoreRequest {
    pub alias: String,
    pub messages: Conversation,
    /// The trusted criteria text (inline policy or `text_ref` resource).
    pub constitution: String,
}

/// Request for a classifier probability.
#[derive(Debug, Clone)]
pub struct ClassifyRequest {
    pub alias: String,
    pub messages: Conversation,
}

/// Request for one assistant completion.
#[derive(Debug, Clone)]
pub struct CompleteRequest {
    pub alias: String,
    pub messages: Conversation,
}

/// A span returned by a span-capable model, in original-conversation coordinates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub message_index: usize,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}

/// Errors adapters must surface; the engine maps these to `Incomplete`.
#[derive(Debug, Clone)]
pub enum AdapterError {
    /// Alias not configured, or operation unsupported by its adapter.
    NotConfigured { alias: String, operation: Operation },
    /// The call was refused (safety or policy) — surfaced to rules via `refused()`.
    Refused(String),
    /// Transport/timeout/cancellation failure.
    Failed(String),
}

/// The adapter surface. Async by nature (model calls); cancellation and
/// timeout behavior is the adapter's own responsibility, per the upstream
/// integration contract.
///
/// Object safety: use enum dispatch (`AdapterHandle`) for heterogeneous
/// registries rather than `dyn` — async fn in traits is not dyn-compatible.
#[allow(async_fn_in_trait)]
pub trait ModelAdapter {
    fn operations(&self) -> Vec<Operation>;

    async fn score(&self, req: ScoreRequest) -> Result<f64, AdapterError>;
    async fn classify(&self, req: ClassifyRequest) -> Result<f64, AdapterError>;
    async fn complete(&self, req: CompleteRequest) -> Result<String, AdapterError>;
    async fn input_tokens(&self, req: CompleteRequest) -> Result<u64, AdapterError>;
    async fn spans(&self, req: CompleteRequest, threshold: f64) -> Result<Vec<Span>, AdapterError>;
}

/// The scan-scoped model-call budget. Every adapter call must pass through
/// this gate; exhaustion maps to `ScanStatus::Incomplete`.
#[derive(Debug)]
pub struct ModelCallBudget {
    pub remaining: usize,
}

impl ModelCallBudget {
    pub fn new(max_calls: usize) -> Self {
        Self { remaining: max_calls }
    }

    pub fn spend(&mut self) -> Result<(), AdapterError> {
        if self.remaining == 0 {
            return Err(AdapterError::Failed("model-call budget exhausted".into()));
        }
        self.remaining -= 1;
        Ok(())
    }
}
