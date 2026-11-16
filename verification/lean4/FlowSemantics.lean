/-!
# FlowSemantics — the Quarry flow operators, as theorems

The language reference (quarry/language/reference.md, compiler-7) states
the flow-operator semantics as prose. This file states them as definitions
and proves the properties the prose claims. No Mathlib — kernel-checked
Nat/core only (the LEAN-001 / HarborWatchChain pattern).

Estate linkage note (WO-5): the mechanical link from these definitions to
the Rust implementation runs through charon → Aeneas (LLBC → Lean). Until
that extraction lands for `quarry-engine::flow`, this file is the
*normative spec*: any implementation divergence is a finding, honestly
classable as `linkage: transcribed` until then.

Semantics being captured (reference §flow-*):
- `A after B`            — ∃ A-event after a B-event
- `A after(within: N) B` — ∃ A-event 0 < Δsteps ≤ N after a B-event
- `A before B`           — mirror of after
- `A right_after B`      — distance exactly 1
- `A until B`            — B occurs, and A holds at every event before it
- `within: N` requires N ≥ 1 (reference: "must be at least 1")
-/

namespace Quarry.Flow

/-- A guard over event positions: does event `i` satisfy the operand? -/
def Guard := Nat → Prop

/-- `A` occurs somewhere in `[0, n)`. -/
def Occurs (A : Guard) (n : Nat) : Prop := ∃ i, i < n ∧ A i

/-- `A after B` over a trace of `n` events. -/
def After (A B : Guard) (n : Nat) : Prop :=
  ∃ a b, b < a ∧ a < n ∧ A a ∧ B b

/-- `A before B` — the mirror image. -/
def Before (A B : Guard) (n : Nat) : Prop := After B A n

/-- `A after(within: N) B` — the gap is at least 1 and at most N. -/
def AfterWithin (N : Nat) (A B : Guard) (n : Nat) : Prop :=
  ∃ a b, 0 < a - b ∧ a - b ≤ N ∧ a < n ∧ A a ∧ B b

/-- `A right_after B` — distance exactly 1 (upstream metadata: "distance = 1"). -/
def RightAfter (A B : Guard) (n : Nat) : Prop :=
  ∃ b, b + 1 < n ∧ A (b + 1) ∧ B b

/-- `A until B` — B occurs, and A holds at every event strictly before it.
The reference's "every event of its own kind" restriction is a compiler
domain-filter: the guard `A` passed here is already kind-restricted. -/
def Until (A B : Guard) (n : Nat) : Prop :=
  ∃ b, b < n ∧ B b ∧ ∀ i, i < b → A i

/-- The reference law: `within: N` requires N ≥ 1. A window of 0 is
rejected at load time; semantically it could never fire (the gap is ≥ 1). -/
def ValidWindow (N : Nat) : Prop := 1 ≤ N

/-! ### The theorems -/

/-- `right_after` implies `after` — adjacency is a special case. -/
theorem right_after_implies_after {A B : Guard} {n : Nat}
    (h : RightAfter A B n) : After A B n := by
  obtain ⟨b, hb, hA, hB⟩ := h
  exact ⟨b + 1, b, by omega, hb, hA, hB⟩

/-- `after(within: N)` implies `after` — the bounded window is a special case. -/
theorem within_implies_after {N : Nat} {A B : Guard} {n : Nat}
    (h : AfterWithin N A B n) : After A B n := by
  obtain ⟨a, b, _, _, ha, hA, hB⟩ := h
  refine ⟨a, b, ?_, ha, hA, hB⟩
  omega

/-- `before` and `after` are mirrors: `A before B ↔ B after A`. -/
theorem before_after_symmetry {A B : Guard} {n : Nat} :
    Before A B n ↔ After B A n := Iff.rfl

/-- `until` vacuity: if the release event is the very first event, the
sustained side need not hold anywhere (reference: "If the right event is
the first one, the left condition need not hold at all"). -/
theorem until_vacuous_at_first {A B : Guard} {n : Nat}
    (hB0 : B 0) (hn : 0 < n) : Until A B n := by
  refine ⟨0, hn, hB0, ?_⟩
  intro i hi
  omega

/-- `until` requires a release: if B never occurs, until never matches
(finite-trace semantics: "right must hold at some point"). -/
theorem until_requires_release {A B : Guard} {n : Nat}
    (h : Until A B n) : Occurs B n := by
  obtain ⟨b, hb, hB, _⟩ := h
  exact ⟨b, hb, hB⟩

/-- A window of 0 can never fire: the gap is at least 1. -/
theorem zero_window_never_fires {A B : Guard} {n : Nat}
    (h : AfterWithin 0 A B n) : False := by
  obtain ⟨a, b, hpos, _, _, _, _⟩ := h
  omega

/-- A valid window (N ≥ 1) with an adjacent pair always fires: distance-1
witnesses any `within: N` with N ≥ 1. -/
theorem right_after_satisfies_valid_window {A B : Guard} {n N : Nat}
    (h : RightAfter A B n) (hN : ValidWindow N) : AfterWithin N A B n := by
  obtain ⟨b, hb, hA, hB⟩ := h
  have hN' : 1 ≤ N := hN
  have h1 : 0 < (b + 1) - b := by omega
  have h2 : (b + 1) - b ≤ N := by omega
  exact ⟨b + 1, b, h1, h2, hb, hA, hB⟩

end Quarry.Flow
