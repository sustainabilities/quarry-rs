//! quarry-dsl — lexer, AST, and parser for the Quarry detection DSL.
//!
//! Ported from `quarry/dsl/grammar.py` (`DSL_GRAMMAR`, Lark, compiler-7).
//! The Lark contextual lexer is replaced by a token stream of raw
//! identifiers; keyword recognition is contextual in the parser, which
//! mirrors Lark's behavior for the grammar's lookahead-anchored tokens
//! (`SIGNED_INT`, `METADATA_KEY`, `VAR_NAME`).

mod ast;
mod lexer;
mod parser;

#[cfg(kani)]
mod proofs;

pub use ast::*;
pub use lexer::{LexError, Token};
pub use parser::{ParseError, Parser};

/// Parse one rule source string into a [`Rule`].
pub fn parse_rule(src: &str) -> Result<Rule, ParseError> {
    Parser::new(src).parse_rule()
}
