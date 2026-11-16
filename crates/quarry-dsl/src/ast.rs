//! Abstract syntax tree for the Quarry DSL. Shape follows the Lark grammar
//! in `quarry/dsl/grammar.py`; operator precedence follows
//! `OPERATOR_PRECEDENCE` (levels 1–9).

/// A complete rule: `rule "name" ... condition: ... [collect: ...]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub name: String,
    pub metadata: Vec<(String, String)>,
    pub strings: Vec<StringDef>,
    pub variables: Vec<(String, Expr)>,
    pub parameters: Vec<ParameterDef>,
    pub condition: Expr,
    pub collect: Option<FilterComp>,
}

/// `strings:` entry. `$name = "literal" modifiers?` or an array of literals.
#[derive(Debug, Clone, PartialEq)]
pub struct StringDef {
    pub name: String,
    pub value: StringValue,
    pub modifiers: Vec<StringModifier>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StringValue {
    Literal(String),
    Array(Vec<String>),
}

/// String modifiers (`MODIFIER` in the grammar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringModifier {
    NoCase,
    FullWord,
    Base64,
    Regex,
}

impl StringModifier {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "nocase" => Some(StringModifier::NoCase),
            "fullword" => Some(StringModifier::FullWord),
            "base64" => Some(StringModifier::Base64),
            "regex" => Some(StringModifier::Regex),
            _ => None,
        }
    }
}

/// `parameters:` entry — a typed policy parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterDef {
    pub name: String,
    pub kind: ParamType,
    pub policy_bound: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    Number,
    Text,
}

/// Flow operators (precedence 4, non-associative — chain only with parens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOp {
    Before,
    RightBefore,
    After,
    RightAfter,
    Until,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Neq,
    Gt,
    Lt,
    Gte,
    Lte,
}

impl CmpOp {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "==" => Some(CmpOp::Eq),
            "!=" => Some(CmpOp::Neq),
            ">" => Some(CmpOp::Gt),
            "<" => Some(CmpOp::Lt),
            ">=" => Some(CmpOp::Gte),
            "<=" => Some(CmpOp::Lte),
            _ => None,
        }
    }
}

/// The expression tree. Variants follow the grammar productions; the
/// transformer inlining (`variables:` sugar) happens before compilation,
/// mirroring `quarry/dsl/transformer.py`.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),

    /// `left before/after/right_before/right_after/until right`
    /// with optional `within: N` (only on `before`/`after`).
    Flow {
        op: FlowOp,
        left: Box<Expr>,
        right: Box<Expr>,
        within: Option<f64>,
    },

    Comparison {
        op: CmpOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },

    Contains(Box<Expr>, Box<Expr>),
    /// `contains_any` over an array literal or a `$string_var`.
    ContainsAny(Box<Expr>, ContainsAnyRhs),
    /// `~` — RE2 regex match.
    RegexMatch(Box<Expr>, Box<Expr>),
    /// `matches { pattern or ... }`
    MatchesPattern(Box<Expr>, PatternBlock),
    /// `x in y`
    In(Box<Expr>, Box<Expr>),
    /// `x in y as capture`
    InWithCapture {
        needle: Box<Expr>,
        haystack: Box<Expr>,
        capture: String,
    },
    /// `x as capture` — binds a value for a later reference.
    Assignment(Box<Expr>, String),

    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),

    FunctionCall { name: String, args: Vec<Expr> },
    MethodCall {
        receiver: Box<Expr>,
        name: String,
        args: Vec<Expr>,
    },
    AttrAccess { receiver: Box<Expr>, name: String },
    Index { receiver: Box<Expr>, index: Box<Expr> },
    Slice {
        receiver: Box<Expr>,
        from: Option<i64>,
        to: Option<i64>,
    },
    SliceAll(Box<Expr>),
    /// `.*` — expand object values.
    WildcardPostfix(Box<Expr>),

    /// `@$name` / `@$name*` — a string's matched position.
    StringPosition { name: String, wildcard: bool },
    /// `#$name` / `#$name*` — a string's match count.
    StringCount { name: String, wildcard: bool },
    /// `N of ($a, $b*)` / `any of (...)` / `all of (...)`.
    StringSet {
        quantifier: Quantifier,
        list: Vec<(String, bool)>,
    },
    StringVar(String),

    Ident(String),
    StringLit(String),
    Number(f64),
    Bool(bool),
    Null,
    Array(Vec<Expr>),

    AnyComp {
        var: String,
        iter: Box<Expr>,
        cond: Box<Expr>,
    },
    AllComp {
        var: String,
        iter: Box<Expr>,
        cond: Box<Expr>,
    },
    MapComp {
        expr: Box<Expr>,
        var: String,
        iter: Box<Expr>,
        cond: Option<Box<Expr>>,
    },
    Filter(FilterComp),
}

/// `[ item for var in iter if cond ]` — also the `collect:` block form.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterComp {
    pub item: String,
    pub var: String,
    pub iter: Box<Expr>,
    pub cond: Box<Expr>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Quantifier {
    Count(f64),
    Any,
    All,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PatternBlock {
    pub alternatives: Vec<PatternExpr>,
}

/// One `matches` pattern alternative: `atom OP value`.
#[derive(Debug, Clone, PartialEq)]
pub struct PatternExpr {
    pub lhs: Expr,
    pub op: CmpOp,
    pub contains: bool,
    pub rhs: Expr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContainsAnyRhs {
    Array(Vec<Expr>),
    StringVar(String),
}
