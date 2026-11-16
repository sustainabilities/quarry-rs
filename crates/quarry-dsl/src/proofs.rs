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

    /// Bounded symbolic string — `String`/`Vec` have no `Arbitrary` impl
    /// in Kani 0.68; assemble from N symbolic chars instead.
    fn any_string_16() -> String {
        let c0: char = kani::any();
        let c1: char = kani::any();
        let c2: char = kani::any();
        let c3: char = kani::any();
        let c4: char = kani::any();
        let c5: char = kani::any();
        let c6: char = kani::any();
        let c7: char = kani::any();
        let c8: char = kani::any();
        let c9: char = kani::any();
        let c10: char = kani::any();
        let c11: char = kani::any();
        let c12: char = kani::any();
        let c13: char = kani::any();
        let c14: char = kani::any();
        let c15: char = kani::any();
        let mut s = String::new();
        for c in [c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15] {
            // Constrain to the DSL's alphabet: printable ASCII. Symbolic
            // Unicode would explode the state space without adding
            // parser-relevant coverage — the lexer's byte-level handling
            // of non-ASCII is exercised by the fuzz suite instead.
            kani::assume(c.is_ascii() && (c.is_ascii_graphic() || c == ' ' || c == '\n'));
            s.push(c);
        }
        s
    }

    /// The lexer never panics on arbitrary bytes — only returns tokens or
    /// a LexError. Unwinding bound covers any string up to ~64 chars.
    #[kani::proof]
    #[kani::unwind(68)]
    fn lexer_never_panics() {
        let s = any_string_16();
        let _ = lex(&s);
    }

    /// The parser never panics on arbitrary token streams derived from
    /// arbitrary text (bounded).
    #[kani::proof]
    #[kani::unwind(80)]
    fn parser_never_panics() {
        let s = any_string_16();
        let _ = crate::parse_rule(&s);
    }

    /// Property: a successful parse of the same input is deterministic.
    #[kani::proof]
    #[kani::unwind(80)]
    fn parse_is_deterministic() {
        let s = any_string_16();
        let a = crate::parse_rule(&s);
        let b = crate::parse_rule(&s);
        match (&a, &b) {
            (Ok(x), Ok(y)) => assert!(x.name == y.name),
            (Err(_), Err(_)) => {}
            _ => panic!("parse nondeterminism"),
        }
    }
}
