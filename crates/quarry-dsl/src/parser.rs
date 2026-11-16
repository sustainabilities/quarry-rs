//! Recursive-descent parser for the Quarry DSL. Production order mirrors
//! `DSL_GRAMMAR`; operator precedence follows `OPERATOR_PRECEDENCE`:
//! or(1) < and(2) < not(3) < flow(4, non-assoc) < comparison(5, non-assoc)
//! < membership(6, non-assoc) < add(7) < mul(8) < postfix(9).

use crate::ast::*;
use crate::lexer::{lex, Spanned, Token};

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "parse error at {}:{}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for ParseError {}

pub struct Parser {
    tokens: Vec<Spanned>,
    pos: usize,
}

/// Block headers that terminate optional blocks before `condition:`.
const BLOCK_HEADERS: [&str; 5] = ["metadata", "strings", "variables", "parameters", "condition"];

impl Parser {
    pub fn new(src: &str) -> Self {
        let tokens = lex(src).unwrap_or_default();
        Self { tokens, pos: 0 }
    }

    // ---- token helpers ----

    fn peek(&self) -> Option<&Spanned> {
        self.tokens.get(self.pos)
    }

    fn peek2(&self) -> Option<&Spanned> {
        self.tokens.get(self.pos + 1)
    }

    fn bump(&mut self) -> Option<Spanned> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn error(&self, message: impl Into<String>) -> ParseError {
        match self.peek() {
            Some(t) => ParseError {
                message: message.into(),
                line: t.line,
                col: t.col,
            },
            None => ParseError {
                message: message.into(),
                line: 0,
                col: 0,
            },
        }
    }

    fn at_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Spanned { token: Token::Ident(s), .. }) if s == kw)
    }

    fn at_tok(&self, t: &Token) -> bool {
        matches!(self.peek(), Some(Spanned { token: kind, .. }) if kind == t)
    }

    fn expect_tok(&mut self, t: Token, what: &str) -> Result<(), ParseError> {
        if self.at_tok(&t) {
            self.bump();
            Ok(())
        } else {
            Err(self.error(format!("expected {what}, found {}", self.peek().map(|s| s.token.describe()).unwrap_or_else(|| "end of input".into()))))
        }
    }

    fn expect_kw(&mut self, kw: &str) -> Result<(), ParseError> {
        if self.at_kw(kw) {
            self.bump();
            Ok(())
        } else {
            Err(self.error(format!("expected `{kw}`")))
        }
    }

    fn expect_ident(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some(Spanned { token: Token::Ident(s), .. }) => {
                let s = s.clone();
                self.bump();
                Ok(s)
            }
            _ => Err(self.error("expected identifier")),
        }
    }

    fn expect_string(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some(Spanned { token: Token::StringLit(s), .. }) => {
                let s = s.clone();
                self.bump();
                Ok(s)
            }
            _ => Err(self.error("expected string literal")),
        }
    }

    fn expect_number(&mut self) -> Result<f64, ParseError> {
        match self.peek() {
            Some(Spanned { token: Token::Number(n), .. }) => {
                let n = *n;
                self.bump();
                Ok(n)
            }
            _ => Err(self.error("expected number")),
        }
    }

    // ---- entry point: rule ----

    pub fn parse_rule(&mut self) -> Result<Rule, ParseError> {
        self.expect_kw("rule")?;
        let name = self.expect_string()?;

        let mut metadata = Vec::new();
        let mut strings = Vec::new();
        let mut variables = Vec::new();
        let mut parameters = Vec::new();

        loop {
            let is_header = matches!(
                self.peek(),
                Some(Spanned { token: Token::Ident(s), .. }) if BLOCK_HEADERS.contains(&s.as_str())
            ) && matches!(self.peek2(), Some(Spanned { token: Token::Colon, .. }));
            if !is_header {
                break;
            }
            match self.peek().map(|s| match &s.token {
                Token::Ident(name) => name.as_str(),
                _ => unreachable!(),
            }) {
                Some("metadata") => {
                    self.bump();
                    self.bump();
                    metadata = self.parse_metadata_items()?;
                }
                Some("strings") => {
                    self.bump();
                    self.bump();
                    strings = self.parse_string_defs()?;
                }
                Some("variables") => {
                    self.bump();
                    self.bump();
                    variables = self.parse_variable_defs()?;
                }
                Some("parameters") => {
                    self.bump();
                    self.bump();
                    parameters = self.parse_parameter_defs()?;
                }
                Some("condition") => break,
                _ => break,
            }
        }

        self.expect_kw("condition")?;
        self.expect_tok(Token::Colon, "`:` after `condition`")?;
        let condition = self.parse_expr()?;

        let collect = if self.at_kw("collect") {
            self.bump();
            self.expect_tok(Token::Colon, "`:` after `collect`")?;
            Some(self.parse_filter_comp()?)
        } else {
            None
        };

        if let Some(t) = self.peek() {
            return Err(ParseError {
                message: format!("unexpected trailing {}", t.token.describe()),
                line: t.line,
                col: t.col,
            });
        }

        Ok(Rule {
            name,
            metadata,
            strings,
            variables,
            parameters,
            condition,
            collect,
        })
    }

    // ---- blocks ----

    fn parse_metadata_items(&mut self) -> Result<Vec<(String, String)>, ParseError> {
        let mut items = Vec::new();
        // metadata_item: METADATA_KEY "=" STRING — continue while an ident is
        // followed by `=` (block headers are followed by `:`).
        while matches!(self.peek(), Some(Spanned { token: Token::Ident(_), .. }))
            && matches!(self.peek2(), Some(Spanned { token: Token::Assign, .. }))
        {
            let key = self.expect_ident()?;
            self.bump(); // =
            let value = self.expect_string()?;
            items.push((key, value));
        }
        if items.is_empty() {
            return Err(self.error("metadata block requires at least one item"));
        }
        Ok(items)
    }

    fn parse_string_defs(&mut self) -> Result<Vec<StringDef>, ParseError> {
        let mut defs = Vec::new();
        while matches!(self.peek(), Some(Spanned { token: Token::StringVar(_), .. })) {
            let name = match self.bump() {
                Some(Spanned { token: Token::StringVar(n), .. }) => n,
                _ => unreachable!(),
            };
            self.expect_tok(Token::Assign, "`=` in strings block")?;
            let value = if self.at_tok(&Token::LBracket) {
                StringValue::Array(self.parse_string_array()?)
            } else {
                StringValue::Literal(self.expect_string()?)
            };
            let mut modifiers = Vec::new();
            while matches!(self.peek(), Some(Spanned { token: Token::Ident(s), .. })
                if matches!(s.as_str(), "nocase" | "fullword" | "base64" | "regex"))
            {
                if let Some(Spanned { token: Token::Ident(s), .. }) = self.bump() {
                    modifiers.push(StringModifier::parse(&s).expect("checked above"));
                }
            }
            defs.push(StringDef {
                name,
                value,
                modifiers,
            });
        }
        if defs.is_empty() {
            return Err(self.error("strings block requires at least one definition"));
        }
        Ok(defs)
    }

    fn parse_string_array(&mut self) -> Result<Vec<String>, ParseError> {
        self.expect_tok(Token::LBracket, "`[`")?;
        let mut out = Vec::new();
        if self.at_tok(&Token::RBracket) {
            self.bump();
            return Ok(out);
        }
        loop {
            out.push(self.expect_string()?);
            if self.at_tok(&Token::Comma) {
                self.bump();
            } else {
                break;
            }
        }
        self.expect_tok(Token::RBracket, "`]` closing string array")?;
        Ok(out)
    }

    fn parse_variable_defs(&mut self) -> Result<Vec<(String, Expr)>, ParseError> {
        let mut defs = Vec::new();
        // variable_def: VAR_NAME "=" expr — stop at `condition:`.
        while matches!(self.peek(), Some(Spanned { token: Token::Ident(s), .. })
            if s != "condition" && s != "collect")
            && matches!(self.peek2(), Some(Spanned { token: Token::Assign, .. }))
        {
            let name = self.expect_ident()?;
            self.bump(); // =
            let expr = self.parse_expr()?;
            defs.push((name, expr));
        }
        if defs.is_empty() {
            return Err(self.error("variables block requires at least one definition"));
        }
        Ok(defs)
    }

    fn parse_parameter_defs(&mut self) -> Result<Vec<ParameterDef>, ParseError> {
        let mut defs = Vec::new();
        while matches!(self.peek(), Some(Spanned { token: Token::Ident(s), .. })
            if s != "condition" && s != "collect")
            && matches!(self.peek2(), Some(Spanned { token: Token::Colon, .. }))
        {
            let name = self.expect_ident()?;
            self.bump(); // :
            let kind = if self.at_kw("number") {
                self.bump();
                ParamType::Number
            } else if self.at_kw("text") {
                self.bump();
                ParamType::Text
            } else {
                return Err(self.error("parameter type must be `number` or `text`"));
            };
            let policy_bound = if self.at_kw("policy") {
                self.bump();
                true
            } else {
                false
            };
            defs.push(ParameterDef {
                name,
                kind,
                policy_bound,
            });
        }
        if defs.is_empty() {
            return Err(self.error("parameters block requires at least one definition"));
        }
        Ok(defs)
    }

    // ---- expressions, precedence 1..9 ----

    /// Level 1: `or` (left-assoc).
    pub fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while self.at_kw("or") {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// Level 2: `and` (left-assoc).
    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_not()?;
        while self.at_kw("and") {
            self.bump();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// Level 3: `not` (prefix, right-assoc).
    fn parse_not(&mut self) -> Result<Expr, ParseError> {
        if self.at_kw("not") {
            self.bump();
            let inner = self.parse_not()?;
            Ok(Expr::Not(Box::new(inner)))
        } else {
            self.parse_flow()
        }
    }

    /// Level 4: flow operators (non-associative).
    fn parse_flow(&mut self) -> Result<Expr, ParseError> {
        let left = self.parse_comparison()?;
        let op = if self.at_kw("before") {
            Some(FlowOp::Before)
        } else if self.at_kw("right_before") {
            Some(FlowOp::RightBefore)
        } else if self.at_kw("after") {
            Some(FlowOp::After)
        } else if self.at_kw("right_after") {
            Some(FlowOp::RightAfter)
        } else if self.at_kw("until") {
            Some(FlowOp::Until)
        } else {
            None
        };
        let Some(op) = op else { return Ok(left) };
        self.bump();

        // Optional `within: N` — only for `before` / `after`.
        let mut within = None;
        if matches!(op, FlowOp::Before | FlowOp::After)
            && self.at_tok(&Token::LParen)
            && matches!(self.peek2(), Some(Spanned { token: Token::Ident(s), .. }) if s == "within")
        {
            self.bump(); // (
            self.bump(); // within
            self.expect_tok(Token::Colon, "`:` after `within`")?;
            within = Some(self.expect_number()?);
            self.expect_tok(Token::RParen, "`)` closing within")?;
        }

        let right = self.parse_comparison()?;
        Ok(Expr::Flow {
            op,
            left: Box::new(left),
            right: Box::new(right),
            within,
        })
    }

    /// Level 5: comparisons (non-associative).
    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let left = self.parse_in_expr()?;
        let op = match self.peek().map(|s| &s.token) {
            Some(Token::Eq) => Some(CmpOp::Eq),
            Some(Token::Neq) => Some(CmpOp::Neq),
            Some(Token::Gt) => Some(CmpOp::Gt),
            Some(Token::Lt) => Some(CmpOp::Lt),
            Some(Token::Gte) => Some(CmpOp::Gte),
            Some(Token::Lte) => Some(CmpOp::Lte),
            _ => None,
        };
        let Some(op) = op else { return Ok(left) };
        self.bump();
        let right = self.parse_in_expr()?;
        Ok(Expr::Comparison {
            op,
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    /// Level 6: membership / text operators / capture binding (non-associative).
    fn parse_in_expr(&mut self) -> Result<Expr, ParseError> {
        let left = self.parse_arith()?;

        if self.at_kw("contains") {
            self.bump();
            let right = self.parse_arith()?;
            return Ok(Expr::Contains(Box::new(left), Box::new(right)));
        }
        if self.at_kw("contains_any") {
            self.bump();
            let rhs = if self.at_tok(&Token::LBracket) {
                ContainsAnyRhs::Array(self.parse_value_array()?)
            } else if let Some(Spanned { token: Token::StringVar(n), .. }) = self.peek() {
                let n = n.clone();
                self.bump();
                ContainsAnyRhs::StringVar(n)
            } else {
                return Err(self.error("contains_any requires an array or $string_var"));
            };
            return Ok(Expr::ContainsAny(Box::new(left), rhs));
        }
        if self.at_tok(&Token::Tilde) {
            self.bump();
            let right = self.parse_arith()?;
            return Ok(Expr::RegexMatch(Box::new(left), Box::new(right)));
        }
        if self.at_kw("matches") {
            self.bump();
            let block = self.parse_pattern_block()?;
            return Ok(Expr::MatchesPattern(Box::new(left), block));
        }
        if self.at_kw("in") {
            self.bump();
            let haystack = self.parse_arith()?;
            if self.at_kw("as") {
                self.bump();
                let capture = self.expect_ident()?;
                return Ok(Expr::InWithCapture {
                    needle: Box::new(left),
                    haystack: Box::new(haystack),
                    capture,
                });
            }
            return Ok(Expr::In(Box::new(left), Box::new(haystack)));
        }
        if self.at_kw("as") {
            self.bump();
            let capture = self.expect_ident()?;
            return Ok(Expr::Assignment(Box::new(left), capture));
        }
        Ok(left)
    }

    /// Level 7: `+` `-` (left-assoc).
    fn parse_arith(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_product()?;
        loop {
            if self.at_tok(&Token::Plus) {
                self.bump();
                let right = self.parse_product()?;
                left = Expr::Add(Box::new(left), Box::new(right));
            } else if self.at_tok(&Token::Minus) {
                self.bump();
                let right = self.parse_product()?;
                left = Expr::Sub(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    /// Level 8: `*` (left-assoc). A `*` here is multiplication; the wildcard
    /// postfix form is only valid directly after `.` (handled in parse_atom).
    fn parse_product(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_atom()?;
        while self.at_tok(&Token::Star) {
            self.bump();
            let right = self.parse_atom()?;
            left = Expr::Mul(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// Level 9: postfix access (left-assoc), then optional `.*`.
    fn parse_atom(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary()?;
        loop {
            if self.at_tok(&Token::Dot) {
                // `.` IDENT (`(` args `)`)?  |  `.` `*`
                if matches!(self.peek2().map(|s| &s.token), Some(Token::Star)) {
                    self.bump(); // .
                    self.bump(); // *
                    expr = Expr::WildcardPostfix(Box::new(expr));
                    break; // wildcard_postfix is terminal
                }
                self.bump(); // .
                let name = self.expect_ident()?;
                if self.at_tok(&Token::LParen) {
                    self.bump();
                    let args = self.parse_arguments()?;
                    self.expect_tok(Token::RParen, "`)` closing method call")?;
                    expr = Expr::MethodCall {
                        receiver: Box::new(expr),
                        name,
                        args,
                    };
                } else {
                    expr = Expr::AttrAccess {
                        receiver: Box::new(expr),
                        name,
                    };
                }
            } else if self.at_tok(&Token::LBracket) {
                self.bump();
                expr = self.parse_subscript(expr)?;
            } else {
                break;
            }
        }
        Ok(expr)
    }

    /// Subscript after `[`: slices (`[:]`, `[a:]`, `[:b]`, `[a:b]`,
    /// signed indices) or a general `[expr]` index.
    fn parse_subscript(&mut self, receiver: Expr) -> Result<Expr, ParseError> {
        if self.at_tok(&Token::Colon) {
            // [:] or [:b]
            self.bump();
            if self.at_tok(&Token::RBracket) {
                self.bump();
                return Ok(Expr::SliceAll(Box::new(receiver)));
            }
            let to = self.parse_signed_int()?;
            self.expect_tok(Token::RBracket, "`]` closing slice")?;
            return Ok(Expr::Slice {
                receiver: Box::new(receiver),
                from: None,
                to: Some(to),
            });
        }
        // Optional leading `-` for SIGNED_INT.
        let from = self.parse_signed_index_start()?;
        if self.at_tok(&Token::Colon) {
            self.bump();
            let to = if self.at_tok(&Token::RBracket) {
                None
            } else {
                Some(self.parse_signed_int()?)
            };
            self.expect_tok(Token::RBracket, "`]` closing slice")?;
            return Ok(Expr::Slice {
                receiver: Box::new(receiver),
                from: Some(from),
                to,
            });
        }
        self.expect_tok(Token::RBracket, "`]` closing index")?;
        Ok(Expr::Index {
            receiver: Box::new(receiver),
            index: Box::new(Expr::Number(from as f64)),
        })
    }

    fn parse_signed_index_start(&mut self) -> Result<i64, ParseError> {
        let negative = if self.at_tok(&Token::Minus) {
            self.bump();
            true
        } else {
            false
        };
        let n = self.expect_number()?;
        if n.fract() != 0.0 {
            return Err(self.error("subscript bounds must be integers"));
        }
        Ok(if negative { -(n as i64) } else { n as i64 })
    }

    fn parse_signed_int(&mut self) -> Result<i64, ParseError> {
        self.parse_signed_index_start()
    }

    fn parse_arguments(&mut self) -> Result<Vec<Expr>, ParseError> {
        let mut args = Vec::new();
        if self.at_tok(&Token::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.parse_expr()?);
            if self.at_tok(&Token::Comma) {
                self.bump();
            } else {
                break;
            }
        }
        Ok(args)
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek().map(|s| s.token.clone()) {
            Some(Token::LParen) => {
                self.bump();
                let e = self.parse_expr()?;
                self.expect_tok(Token::RParen, "`)`")?;
                Ok(e)
            }
            Some(Token::At) => {
                self.bump();
                let name = self.expect_ident()?;
                let wildcard = self.eat_wildcard();
                Ok(Expr::StringPosition { name, wildcard })
            }
            Some(Token::Hash) => {
                self.bump();
                let name = self.expect_ident()?;
                let wildcard = self.eat_wildcard();
                Ok(Expr::StringCount { name, wildcard })
            }
            Some(Token::StringLit(s)) => {
                self.bump();
                Ok(Expr::StringLit(s))
            }
            Some(Token::StringVar(n)) => {
                self.bump();
                Ok(Expr::StringVar(n))
            }
            Some(Token::Number(n)) => {
                self.bump();
                // `N of ($a, $b)` — counted string set.
                if self.at_kw("of") {
                    self.bump();
                    return self.parse_string_set(Quantifier::Count(n));
                }
                Ok(Expr::Number(n))
            }
            Some(Token::LBracket) => self.parse_bracketed(),
            Some(Token::Ident(s)) => {
                self.bump();
                match s.as_str() {
                    "true" => Ok(Expr::Bool(true)),
                    "false" => Ok(Expr::Bool(false)),
                    "null" => Ok(Expr::Null),
                    "any" | "all" => {
                        // `any of (...)` / `all of (...)` — string set;
                        // otherwise the `any`/`all` comprehension.
                        if self.at_kw("of") {
                            self.bump();
                            let q = if s == "any" {
                                Quantifier::Any
                            } else {
                                Quantifier::All
                            };
                            self.parse_string_set(q)
                        } else if s == "any" {
                            self.parse_quantified_comp(Quantified::Any)
                        } else {
                            self.parse_quantified_comp(Quantified::All)
                        }
                    }
                    _ => {
                        if self.at_tok(&Token::LParen) {
                            self.bump();
                            let args = self.parse_arguments()?;
                            self.expect_tok(Token::RParen, "`)` closing function call")?;
                            Ok(Expr::FunctionCall { name: s, args })
                        } else {
                            Ok(Expr::Ident(s))
                        }
                    }
                }
            }
            other => Err(self.error(format!(
                "expected expression, found {}",
                other
                    .as_ref()
                    .map(|t| t.describe())
                    .unwrap_or_else(|| "end of input".into())
            ))),
        }
    }

    fn eat_wildcard(&mut self) -> bool {
        if self.at_tok(&Token::Star) {
            self.bump();
            true
        } else {
            false
        }
    }

    /// After `[`: an array of literal values, or a filter/map comprehension.
    fn parse_bracketed(&mut self) -> Result<Expr, ParseError> {
        self.bump(); // [
        if self.at_tok(&Token::RBracket) {
            self.bump();
            return Ok(Expr::Array(Vec::new()));
        }
        let first = self.parse_atom()?;
        if self.at_kw("for") {
            self.bump();
            let var = self.expect_ident()?;
            self.expect_kw("in")?;
            let iter = self.parse_expr()?;
            let mut cond = None;
            if self.at_kw("if") {
                self.bump();
                cond = Some(Box::new(self.parse_expr()?));
            }
            self.expect_tok(Token::RBracket, "`]` closing comprehension")?;
            return Ok(match first {
                Expr::Ident(item) if cond.is_some() => Expr::Filter(FilterComp {
                    item,
                    var,
                    iter: Box::new(iter),
                    cond: cond.expect("checked"),
                }),
                other => Expr::MapComp {
                    expr: Box::new(other),
                    var,
                    iter: Box::new(iter),
                    cond,
                },
            });
        }
        // Array of literal values (grammar: `value ("," value)*`).
        let mut items = vec![self.value_from_atom(first)?];
        while self.at_tok(&Token::Comma) {
            self.bump();
            let v = self.parse_atom()?;
            items.push(self.value_from_atom(v)?);
        }
        self.expect_tok(Token::RBracket, "`]` closing array")?;
        Ok(Expr::Array(items))
    }

    /// Grammar `value` production: literals, arrays, true/false/null only.
    fn value_from_atom(&self, e: Expr) -> Result<Expr, ParseError> {
        match e {
            Expr::StringLit(_)
            | Expr::Number(_)
            | Expr::Bool(_)
            | Expr::Null
            | Expr::Array(_) => Ok(e),
            other => Err(self.error(format!(
                "array elements must be literal values, found {other:?}"
            ))),
        }
    }

    fn parse_value_array(&mut self) -> Result<Vec<Expr>, ParseError> {
        self.expect_tok(Token::LBracket, "`[`")?;
        let mut out = Vec::new();
        if self.at_tok(&Token::RBracket) {
            self.bump();
            return Ok(out);
        }
        loop {
            let v = self.parse_atom()?;
            out.push(self.value_from_atom(v)?);
            if self.at_tok(&Token::Comma) {
                self.bump();
            } else {
                break;
            }
        }
        self.expect_tok(Token::RBracket, "`]` closing array")?;
        Ok(out)
    }

    /// `any`/`all` IDENT `in` expr `where` expr.
    fn parse_quantified_comp(&mut self, which: Quantified) -> Result<Expr, ParseError> {
        let var = self.expect_ident()?;
        self.expect_kw("in")?;
        let iter = self.parse_expr()?;
        self.expect_kw("where")?;
        let cond = self.parse_expr()?;
        Ok(match which {
            Quantified::Any => Expr::AnyComp {
                var,
                iter: Box::new(iter),
                cond: Box::new(cond),
            },
            Quantified::All => Expr::AllComp {
                var,
                iter: Box::new(iter),
                cond: Box::new(cond),
            },
        })
    }

    /// `"(" string_list ")"` after a quantifier: `($a, $b*)`.
    fn parse_string_set(&mut self, quantifier: Quantifier) -> Result<Expr, ParseError> {
        self.expect_tok(Token::LParen, "`(` opening string list")?;
        let mut list = Vec::new();
        loop {
            match self.peek() {
                Some(Spanned { token: Token::StringVar(n), .. }) => {
                    let n = n.clone();
                    self.bump();
                    let wildcard = self.eat_wildcard();
                    list.push((n, wildcard));
                }
                other => {
                    return Err(self.error(format!(
                        "expected $string in string list, found {}",
                        other
                            .map(|t| t.token.describe())
                            .unwrap_or_else(|| "end of input".into())
                    )))
                }
            }
            if self.at_tok(&Token::Comma) {
                self.bump();
            } else {
                break;
            }
        }
        self.expect_tok(Token::RParen, "`)` closing string list")?;
        Ok(Expr::StringSet { quantifier, list })
    }

    /// `[ item for var in iter if cond ]` — the `collect:` form.
    fn parse_filter_comp(&mut self) -> Result<FilterComp, ParseError> {
        self.expect_tok(Token::LBracket, "`[` opening collect comprehension")?;
        let item = self.expect_ident()?;
        self.expect_kw("for")?;
        let var = self.expect_ident()?;
        self.expect_kw("in")?;
        let iter = self.parse_expr()?;
        self.expect_kw("if")?;
        let cond = self.parse_expr()?;
        self.expect_tok(Token::RBracket, "`]` closing collect comprehension")?;
        Ok(FilterComp {
            item,
            var,
            iter: Box::new(iter),
            cond: Box::new(cond),
        })
    }

    /// `matches { atom OP value or ... }`.
    fn parse_pattern_block(&mut self) -> Result<PatternBlock, ParseError> {
        self.expect_tok(Token::LBrace, "`{` opening pattern block")?;
        let mut alternatives = Vec::new();
        loop {
            let lhs = self.parse_atom()?;
            let (op, contains) = match self.peek().map(|s| s.token.clone()) {
                Some(Token::Ident(s)) if s == "contains" => {
                    self.bump();
                    (CmpOp::Eq, true)
                }
                Some(Token::Eq) => {
                    self.bump();
                    (CmpOp::Eq, false)
                }
                Some(Token::Neq) => {
                    self.bump();
                    (CmpOp::Neq, false)
                }
                Some(Token::Gt) => {
                    self.bump();
                    (CmpOp::Gt, false)
                }
                Some(Token::Lt) => {
                    self.bump();
                    (CmpOp::Lt, false)
                }
                Some(Token::Gte) => {
                    self.bump();
                    (CmpOp::Gte, false)
                }
                Some(Token::Lte) => {
                    self.bump();
                    (CmpOp::Lte, false)
                }
                other => {
                    return Err(self.error(format!(
                        "expected pattern operator, found {}",
                        other
                            .map(|t| t.describe())
                            .unwrap_or_else(|| "end of input".into())
                    )))
                }
            };
            let rhs = self.parse_atom()?;
            alternatives.push(PatternExpr {
                lhs,
                op,
                contains,
                rhs,
            });
            if self.at_kw("or") {
                self.bump();
            } else {
                break;
            }
        }
        self.expect_tok(Token::RBrace, "`}` closing pattern block")?;
        Ok(PatternBlock { alternatives })
    }
}

enum Quantified {
    Any,
    All,
}
