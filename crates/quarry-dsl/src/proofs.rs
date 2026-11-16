//! Kani proof harnesses — rung 2 of the verification ladder (Foundry
//! policy: "fuzz + Kani panic-freedom + property tests").
//!
//! Run: `kani --harness harness_name` (kani is in the CoE `#verify` shell).
//! Bounds are kept small: proofs, not tests — the corpus conformance suite
//! is the behavioral wall; Kani proves panic-freedom over ALL inputs in the
//! bound, including inputs the corpus never thought of.

#[cfg(kani)]
mod proofs {
    use crate::lexer::lex;

    /// Bounded symbolic string — `String` has no `Arbitrary` impl; build
    /// from a bounded char vector.
    fn any_string(max: usize) -> String {
        let chars: Vec<char> = kani::any();
        kani::assume(chars.len() < max);
        chars.into_iter().collect()
    }

    /// The lexer never panics on arbitrary bytes — only returns tokens or
    /// a LexError. Unwinding bound covers any string up to ~64 chars.
    #[kani::proof]
    #[kani::unwind(68)]
    fn lexer_never_panics() {
        let s = any_string(64);
        let _ = lex(&s);
    }

    /// The parser never panics on arbitrary token streams derived from
    /// arbitrary text (bounded).
    #[kani::proof]
    #[kani::unwind(80)]
    fn parser_never_panics() {
        let s = any_string(80);
        let _ = crate::parse_rule(&s);
    }

    /// Property: a successful parse of the same input is deterministic.
    #[kani::proof]
    #[kani::unwind(80)]
    fn parse_is_deterministic() {
        let s = any_string(80);
        let a = crate::parse_rule(&s);
        let b = crate::parse_rule(&s);
        match (&a, &b) {
            (Ok(x), Ok(y)) => assert!(x.name == y.name),
            (Err(_), Err(_)) => {}
            _ => panic!("parse nondeterminism"),
        }
    }
}
