// quarry-rs — Verus-verified trust core.
//
// Rung 5 of the verification ladder (Foundry policy: "Verus contracts on
// the manifest/hash core when stable"). These are the contracts the engine's
// Rust implementation must honor; the harbor-watch pattern applies: the
// verified module is the spec, the engine is tested against it.
//
// Verify:  verus verification/verus/dfa_core.rs   (verus from ~/.cargo/bin)

use vstd::prelude::*;
use vstd::arithmetic::mul::{lemma_mul_inequality, lemma_mul_strict_inequality};

verus! {

/// A DFA transition table in row-major form: `trans[state * 256 + input]`.
/// The verified step function is the trust core of the guard automaton:
/// total, in-bounds by construction, terminating.
pub struct Dfa {
    pub states: usize,
    pub trans: Vec<usize>,
}

/// Well-formedness: every transition points to a valid state. This is the
/// data invariant the loader must establish (compile-time contract: a
/// generation publishes only when every compiled table is well-formed).
pub open spec fn wf(dfa: &Dfa) -> bool {
    forall|i: int| 0 <= i < dfa.trans.len() ==> dfa.trans[i] < dfa.states
}

/// One automaton step. Contract: given an in-bounds state, a well-formed
/// table, and any input, the next state is in-bounds. This is the invariant
/// the executor relies on: the scan path can carry no defensive re-checks,
/// because the step function cannot leave the state space.
pub fn step(dfa: &Dfa, s: usize, input: u8) -> (r: usize)
    requires
        dfa.states > 0,
        s < dfa.states,
        wf(dfa),
        dfa.trans.len() == dfa.states * 256,
    ensures
        r < dfa.states,
{
    let b: usize = input as usize;
    let idx = s * 256 + b;
    proof {
        // s < states, times a positive constant: strict inequality survives.
        lemma_mul_strict_inequality(s as int, dfa.states as int, 256);
        assert(s * 256 < dfa.states * 256);
        // The input byte adds less than one full row.
        assert(b < 256);
        assert(idx < s * 256 + 256);
        assert(s * 256 + 256 == (s + 1) * 256) by (nonlinear_arith) {};
        assert((s + 1) * 256 <= dfa.states * 256) by {
            lemma_mul_inequality((s + 1) as int, dfa.states as int, 256);
        }
        assert(idx < dfa.states * 256);
        assert(dfa.trans.len() == dfa.states * 256);
        assert(idx < dfa.trans.len());
        // Well-formedness: the transition target is a valid state.
        assert(dfa.trans[idx as int] < dfa.states);
    }
    dfa.trans[idx]
}

/// Run a trace of inputs from the start state. Contract: terminates, and
/// the final state is in-bounds — the scan path's boundedness property.
pub fn run(dfa: &Dfa, start: usize, input: &[u8]) -> (r: usize)
    requires
        dfa.states > 0,
        start < dfa.states,
        wf(dfa),
        dfa.trans.len() == dfa.states * 256,
    ensures
        r < dfa.states,
{
    let mut s = start;
    let mut i: usize = 0;
    while i < input.len()
        invariant
            s < dfa.states,
            i <= input.len(),
            dfa.states > 0,
            wf(dfa),
            dfa.trans.len() == dfa.states * 256,
        decreases input.len() - i,
    {
        s = step(dfa, s, input[i]);
        i += 1;
    }
    s
}

/// The nonce single-use transition, as a pure function with contracts.
/// Law: consume succeeds iff unconsumed and unexpired; on success the
/// record is consumed at `now`; a consumed record never reverts.
pub struct Rec {
    pub expires: u64,
    pub consumed: Option<u64>,
}

pub fn consume(rec: &Rec, now: u64) -> (r: Option<Rec>)
    ensures
        r is Some ==> r.unwrap().consumed == Some(now),
        r is Some ==> now < rec.expires,
        r is None ==> rec.consumed is Some || now >= rec.expires,
{
    if rec.consumed.is_none() && now < rec.expires {
        Some(Rec { expires: rec.expires, consumed: Some(now) })
    } else {
        None
    }
}

} // verus!

fn main() {
    // Verification target only — the engine's Rust implementation mirrors
    // these contracts; this binary exists so the verifier has an entry point.
}
