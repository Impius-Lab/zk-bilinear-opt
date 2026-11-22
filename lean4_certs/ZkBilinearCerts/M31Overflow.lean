/-
  ZkBilinearCerts.M31Overflow
  Zero-`sorry`, zero-`axiom` Lean 4 formal proofs of:
  1. `UInt64` (`< 2^64`) non-overflow and modular soundness of delayed-`u64` `QM31`
     multiplication accumulators (`Plonky3#2600` `qm31_mul_u64_dot4`,
     `starkware-libs/proving#9` `stwo` `QM31::mul` outer Karatsuba, and
     `QM31_Rank7` 62-bit peak intermediate bounds), plus tightness showing `5+`
     unreduced `M31` products exceed `2^64`.
  2. Soundness, tight range bounds, and strict output canonicality (`< 2^31 - 1`)
     of the two-step Mersenne-31 bitwise fold `(x & 0x7fffffff) + (x >> 31)`
     followed by conditional subtraction (and `stwo`'s branchless `t + 1` variant)
     for all `x < 2^64`.
-/

import ZkBilinearCerts.Qm31Algebraic

namespace ZkBilinearCerts

/-- Mersenne-31 prime `P = 2^31 - 1 = 2147483647` as `Nat`. -/
def M31_P : Nat := 2 ^ 31 - 1

/-- Maximum canonical `M31` field element `P - 1 = 2^31 - 2 = 2147483646`. -/
def M31_CANON_MAX : Nat := 2 ^ 31 - 2

/-! ### Part 1: Two-Step Mersenne-31 Bitwise Fold Soundness & Canonicality -/

/-- Hardware bitwise Mersenne-31 fold step: `(x & 0x7fffffff) + (x >> 31)`. -/
def m31_fold_bitwise (x : Nat) : Nat :=
  (x &&& 0x7fffffff) + (x >>> 31)

/-- Arithmetic equivalent of the Mersenne-31 fold step: `x % 2^31 + x / 2^31`. -/
def m31_fold_arith (x : Nat) : Nat :=
  x % (2 ^ 31) + x / (2 ^ 31)

/-- Two-step Mersenne-31 fold for 64-bit accumulators. -/
def m31_fold2 (x : Nat) : Nat :=
  m31_fold_bitwise (m31_fold_bitwise x)

/-- Complete 64-bit Mersenne-31 reduction: two bitwise folds + single conditional subtract. -/
def m31_reduce64 (x : Nat) : Nat :=
  let t := m31_fold2 x
  if t >= 2 ^ 31 - 1 then t - (2 ^ 31 - 1) else t

/-- `stwo` branchless 64-bit Mersenne-31 reduction (`(((t + 1) >> 31) + t) & 0x7fffffff`). -/
def m31_reduce64_branchless (x : Nat) : Nat :=
  let t := m31_fold2 x
  (((t + 1) >>> 31) + t) &&& 0x7fffffff

/-- Bitwise `(x & 0x7fffffff) + (x >> 31)` equals `x % 2^31 + x / 2^31` for all `x : Nat`. -/
theorem m31_fold_bitwise_eq_arith (x : Nat) :
    m31_fold_bitwise x = m31_fold_arith x := by
  unfold m31_fold_bitwise m31_fold_arith
  have hmask : (0x7fffffff : Nat) = 2 ^ 31 - 1 := rfl
  rw [hmask, Nat.and_two_pow_sub_one_eq_mod x 31, Nat.shiftRight_eq_div_pow x 31]

/-- Universal congruence of the Mersenne-31 fold for ALL `x : Nat`:
    `(x % 2^31 + x / 2^31) % (2^31 - 1) = x % (2^31 - 1)`. -/
theorem m31_fold_mod_eq (x : Nat) :
    (x % (2 ^ 31) + x / (2 ^ 31)) % (2 ^ 31 - 1) = x % (2 ^ 31 - 1) := by
  have hdecomp : x = (2 ^ 31 - 1) * (x / (2 ^ 31)) + (x % (2 ^ 31) + x / (2 ^ 31)) := by
    omega
  conv => rhs; rw [hdecomp]
  rw [Nat.mul_add_mod]

theorem m31_fold_bitwise_mod_eq (x : Nat) :
    m31_fold_bitwise x % (2 ^ 31 - 1) = x % (2 ^ 31 - 1) := by
  rw [m31_fold_bitwise_eq_arith, m31_fold_arith, m31_fold_mod_eq]

theorem m31_fold2_mod_eq (x : Nat) :
    m31_fold2 x % (2 ^ 31 - 1) = x % (2 ^ 31 - 1) := by
  unfold m31_fold2
  rw [m31_fold_bitwise_mod_eq, m31_fold_bitwise_mod_eq]

/-- Tight range bound after 1 fold on `x < 2^64`: `m31_fold_bitwise x <= 2^33 + 2^31 - 2 < 2^34`. -/
theorem m31_fold_step1_bound (x : Nat) (hx : x < 2 ^ 64) :
    m31_fold_bitwise x <= 2 ^ 33 + 2 ^ 31 - 2 := by
  rw [m31_fold_bitwise_eq_arith, m31_fold_arith]
  omega

/-- Tight range bound after 2 folds on `x < 2^64`: `m31_fold2 x <= 2^31 + 2 < 2 * (2^31 - 1)`. -/
theorem m31_fold2_bound (x : Nat) (hx : x < 2 ^ 64) :
    m31_fold2 x <= 2 ^ 31 + 2 := by
  have h1 := m31_fold_step1_bound x hx
  unfold m31_fold2
  rw [m31_fold_bitwise_eq_arith, m31_fold_arith]
  omega

/-- Exact witness attaining the `2^31 + 2` bound at `x = 2^64 - 1`. -/
theorem m31_fold2_max_attained :
    m31_fold2 (2 ^ 64 - 1) = 2 ^ 31 + 2 := by
  decide

/-- Soundness of `m31_reduce64` for all `x < 2^64`: exact equality to `x % (2^31 - 1)`. -/
theorem m31_reduce64_eq_mod (x : Nat) (hx : x < 2 ^ 64) :
    m31_reduce64 x = x % (2 ^ 31 - 1) := by
  have hbound := m31_fold2_bound x hx
  have hmod := m31_fold2_mod_eq x
  unfold m31_reduce64
  dsimp only
  generalize m31_fold2 x = t at hbound hmod ⊢
  rw [← hmod]
  split <;> omega

/-- Strict output canonicality of `m31_reduce64` for all `x < 2^64`: result is `< 2^31 - 1`. -/
theorem m31_reduce64_canonical (x : Nat) (hx : x < 2 ^ 64) :
    m31_reduce64 x < 2 ^ 31 - 1 := by
  rw [m31_reduce64_eq_mod x hx]
  exact Nat.mod_lt x (by decide)

/-- Soundness and strict canonicality of `stwo`'s branchless `(((t + 1) >> 31) + t) & 0x7fffffff`
    for all `x < 2^64`. -/
theorem m31_reduce64_branchless_sound_and_canonical (x : Nat) (hx : x < 2 ^ 64) :
    m31_reduce64_branchless x = x % (2 ^ 31 - 1) ∧
    m31_reduce64_branchless x < 2 ^ 31 - 1 := by
  have hbound := m31_fold2_bound x hx
  have hmod := m31_fold2_mod_eq x
  unfold m31_reduce64_branchless
  dsimp only
  generalize m31_fold2 x = t at hbound hmod ⊢
  have hmask : (0x7fffffff : Nat) = 2 ^ 31 - 1 := rfl
  rw [hmask, Nat.and_two_pow_sub_one_eq_mod _ 31, Nat.shiftRight_eq_div_pow _ 31]
  rw [← hmod]
  by_cases ht : t < 2 ^ 31 - 1
  · have hdiv : (t + 1) / (2 ^ 31) = 0 := by omega
    rw [hdiv]; omega
  · have hdiv : (t + 1) / (2 ^ 31) = 1 := by omega
    rw [hdiv]; omega

/-! ### Part 2: `QM31` Delayed-`u64` Limb Accumulator Non-Overflow (`< 2^64`) -/

/-- Exact 4-channel `u64` delayed-reduction accumulators from `Plonky3#2600` (`qm31_mul_u64_dot4`).
    Notice `P ^ x = P - x` for `31`-bit `x <= P`. -/
def qm31_dot4_c0 (a0 a1 a2 a3 b0 b1 wb2 wb3 : Nat) : Nat :=
  a0 * b0 + (M31_P - a1) * b1 + a2 * wb2 + (M31_P - a3) * wb3

def qm31_dot4_c1 (a0 a1 a2 a3 b0 b1 wb2 wb3 : Nat) : Nat :=
  a0 * b1 + a1 * b0 + a2 * wb3 + a3 * wb2

def qm31_dot4_c2 (a0 a1 a2 a3 b0 b1 b2 b3 : Nat) : Nat :=
  a0 * b2 + (M31_P - a1) * b3 + a2 * b0 + (M31_P - a3) * b1

def qm31_dot4_c3 (a0 a1 a2 a3 b0 b1 b2 b3 : Nat) : Nat :=
  a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0

/-- Canonical `mul_by_r` (`R = 2 + i`) pre-reduction in `M31` (`wb = (2 + i) * (b2 + b3*i) mod P`). -/
def qm31_wb_re (b2 b3 : Nat) : Nat := (2 * b2 + M31_P - b3) % M31_P
def qm31_wb_im (b2 b3 : Nat) : Nat := (b2 + 2 * b3) % M31_P

/-- Universal `UInt64` non-overflow across all 4 `dot4` channels even for redundant `31`-bit
    inputs `<= 2^31 - 1` (`4 * (2^31 - 1)^2 = 2^64 - 2^34 + 4 < 2^64`). -/
theorem qm31_dot4_redundant_lt_u64
    (a0 a1 a2 a3 b0 b1 b2 b3 wb2 wb3 : Nat)
    (ha0 : a0 <= 2 ^ 31 - 1) (_ha1 : a1 <= 2 ^ 31 - 1)
    (ha2 : a2 <= 2 ^ 31 - 1) (_ha3 : a3 <= 2 ^ 31 - 1)
    (hb0 : b0 <= 2 ^ 31 - 1) (hb1 : b1 <= 2 ^ 31 - 1)
    (hb2 : b2 <= 2 ^ 31 - 1) (hb3 : b3 <= 2 ^ 31 - 1)
    (hwb2 : wb2 <= 2 ^ 31 - 1) (hwb3 : wb3 <= 2 ^ 31 - 1) :
    qm31_dot4_c0 a0 a1 a2 a3 b0 b1 wb2 wb3 < 2 ^ 64 ∧
    qm31_dot4_c1 a0 a1 a2 a3 b0 b1 wb2 wb3 < 2 ^ 64 ∧
    qm31_dot4_c2 a0 a1 a2 a3 b0 b1 b2 b3 < 2 ^ 64 ∧
    qm31_dot4_c3 a0 a1 a2 a3 b0 b1 b2 b3 < 2 ^ 64 := by
  have hna1 : M31_P - a1 <= 2 ^ 31 - 1 := by unfold M31_P; omega
  have hna3 : M31_P - a3 <= 2 ^ 31 - 1 := by unfold M31_P; omega
  have hcap : 4 * ((2 ^ 31 - 1) * (2 ^ 31 - 1)) < 2 ^ 64 := by decide
  have hc0 : qm31_dot4_c0 a0 a1 a2 a3 b0 b1 wb2 wb3 <= 4 * ((2 ^ 31 - 1) * (2 ^ 31 - 1)) := by
    unfold qm31_dot4_c0
    have p1 := Nat.mul_le_mul ha0 hb0
    have p2 := Nat.mul_le_mul hna1 hb1
    have p3 := Nat.mul_le_mul ha2 hwb2
    have p4 := Nat.mul_le_mul hna3 hwb3
    omega
  have hc1 : qm31_dot4_c1 a0 a1 a2 a3 b0 b1 wb2 wb3 <= 4 * ((2 ^ 31 - 1) * (2 ^ 31 - 1)) := by
    unfold qm31_dot4_c1
    have p1 := Nat.mul_le_mul ha0 hb1
    have p2 := Nat.mul_le_mul _ha1 hb0
    have p3 := Nat.mul_le_mul ha2 hwb3
    have p4 := Nat.mul_le_mul _ha3 hwb2
    omega
  have hc2 : qm31_dot4_c2 a0 a1 a2 a3 b0 b1 b2 b3 <= 4 * ((2 ^ 31 - 1) * (2 ^ 31 - 1)) := by
    unfold qm31_dot4_c2
    have p1 := Nat.mul_le_mul ha0 hb2
    have p2 := Nat.mul_le_mul hna1 hb3
    have p3 := Nat.mul_le_mul ha2 hb0
    have p4 := Nat.mul_le_mul hna3 hb1
    omega
  have hc3 : qm31_dot4_c3 a0 a1 a2 a3 b0 b1 b2 b3 <= 4 * ((2 ^ 31 - 1) * (2 ^ 31 - 1)) := by
    unfold qm31_dot4_c3
    have p1 := Nat.mul_le_mul ha0 hb3
    have p2 := Nat.mul_le_mul _ha1 hb2
    have p3 := Nat.mul_le_mul ha2 hb1
    have p4 := Nat.mul_le_mul _ha3 hb0
    omega
  exact ⟨Nat.lt_of_le_of_lt hc0 hcap,
         Nat.lt_of_le_of_lt hc1 hcap,
         Nat.lt_of_le_of_lt hc2 hcap,
         Nat.lt_of_le_of_lt hc3 hcap⟩

/-- Universal `UInt64` non-overflow for all canonical `M31` inputs (`a_i <= 2^31 - 2`,
    `b_j <= 2^31 - 2`): every `QM31` `dot4` delayed-`u64` accumulator is strictly `< 2^64`. -/
theorem qm31_dot4_canonical_lt_u64
    (a0 a1 a2 a3 b0 b1 b2 b3 : Nat)
    (ha0 : a0 <= 2 ^ 31 - 2) (ha1 : a1 <= 2 ^ 31 - 2)
    (ha2 : a2 <= 2 ^ 31 - 2) (ha3 : a3 <= 2 ^ 31 - 2)
    (hb0 : b0 <= 2 ^ 31 - 2) (hb1 : b1 <= 2 ^ 31 - 2)
    (hb2 : b2 <= 2 ^ 31 - 2) (hb3 : b3 <= 2 ^ 31 - 2) :
    let wb2 := qm31_wb_re b2 b3
    let wb3 := qm31_wb_im b2 b3
    qm31_dot4_c0 a0 a1 a2 a3 b0 b1 wb2 wb3 < 2 ^ 64 ∧
    qm31_dot4_c1 a0 a1 a2 a3 b0 b1 wb2 wb3 < 2 ^ 64 ∧
    qm31_dot4_c2 a0 a1 a2 a3 b0 b1 b2 b3 < 2 ^ 64 ∧
    qm31_dot4_c3 a0 a1 a2 a3 b0 b1 b2 b3 < 2 ^ 64 := by
  intro wb2 wb3
  have hwb2 : wb2 <= 2 ^ 31 - 1 := by
    have := Nat.mod_lt (2 * b2 + M31_P - b3) (show M31_P > 0 by decide)
    unfold wb2 qm31_wb_re M31_P at *; omega
  have hwb3 : wb3 <= 2 ^ 31 - 1 := by
    have := Nat.mod_lt (b2 + 2 * b3) (show M31_P > 0 by decide)
    unfold wb3 qm31_wb_im M31_P at *; omega
  exact qm31_dot4_redundant_lt_u64 a0 a1 a2 a3 b0 b1 b2 b3 wb2 wb3
    (by omega) (by omega) (by omega) (by omega)
    (by omega) (by omega) (by omega) (by omega) hwb2 hwb3

/-- Universal algebraic soundness of `qm31_dot4` + `m31_reduce64`: for all canonical `M31`
    inputs `a_i, b_j <= 2^31 - 2`, reducing the 4 `dot4` `u64` accumulators via `m31_reduce64`
    yields the exact canonical `qm31_schoolbook_mod_m31` result! -/
theorem qm31_dot4_reduce64_eq_schoolbook
    (a0 a1 a2 a3 b0 b1 b2 b3 : Nat)
    (ha0 : a0 <= 2 ^ 31 - 2) (ha1 : a1 <= 2 ^ 31 - 2)
    (ha2 : a2 <= 2 ^ 31 - 2) (ha3 : a3 <= 2 ^ 31 - 2)
    (hb0 : b0 <= 2 ^ 31 - 2) (hb1 : b1 <= 2 ^ 31 - 2)
    (hb2 : b2 <= 2 ^ 31 - 2) (hb3 : b3 <= 2 ^ 31 - 2) :
    let wb2 := qm31_wb_re b2 b3
    let wb3 := qm31_wb_im b2 b3
    let r0 := (m31_reduce64 (qm31_dot4_c0 a0 a1 a2 a3 b0 b1 wb2 wb3) : Int)
    let r1 := (m31_reduce64 (qm31_dot4_c1 a0 a1 a2 a3 b0 b1 wb2 wb3) : Int)
    let r2 := (m31_reduce64 (qm31_dot4_c2 a0 a1 a2 a3 b0 b1 b2 b3) : Int)
    let r3 := (m31_reduce64 (qm31_dot4_c3 a0 a1 a2 a3 b0 b1 b2 b3) : Int)
    Qm31Int.mk r0 r1 r2 r3 =
    qm31_schoolbook_mod_m31 a0 a1 a2 a3 b0 b1 b2 b3 := by
  have ⟨hlt0, hlt1, hlt2, hlt3⟩ :=
    qm31_dot4_canonical_lt_u64 a0 a1 a2 a3 b0 b1 b2 b3 ha0 ha1 ha2 ha3 hb0 hb1 hb2 hb3
  simp only [m31_reduce64_eq_mod _ hlt0, m31_reduce64_eq_mod _ hlt1,
             m31_reduce64_eq_mod _ hlt2, m31_reduce64_eq_mod _ hlt3,
             qm31_schoolbook_mod_m31, qm31_mod_m31, Qm31Int.mk.injEq]
  have natCast_mod (n : Nat) : ((n % (2 ^ 31 - 1) : Nat) : Int) = (n : Int) % M31_P_INT := by
    unfold M31_P_INT; omega
  simp only [natCast_mod]
  have hsub_a1 : ((M31_P - a1 : Nat) : Int) = M31_P_INT - (a1 : Int) := by
    unfold M31_P M31_P_INT; omega
  have hsub_a3 : ((M31_P - a3 : Nat) : Int) = M31_P_INT - (a3 : Int) := by
    unfold M31_P M31_P_INT; omega
  have hwb2_cast : ((qm31_wb_re b2 b3 : Nat) : Int) =
      (2 * (b2 : Int) + M31_P_INT - (b3 : Int)) % M31_P_INT := by
    unfold qm31_wb_re M31_P M31_P_INT; omega
  have hwb3_cast : ((qm31_wb_im b2 b3 : Nat) : Int) =
      ((b2 : Int) + 2 * (b3 : Int)) % M31_P_INT := by
    unfold qm31_wb_im M31_P M31_P_INT; omega
  simp only [qm31_dot4_c0, qm31_dot4_c1, qm31_dot4_c2, qm31_dot4_c3,
             Int.natCast_add, Int.natCast_mul, hsub_a1, hsub_a3, hwb2_cast, hwb3_cast,
             qm31_schoolbook, cm31_mul]
  have push_r (x y : Int) : (x * (y % M31_P_INT)) % M31_P_INT = (x * y) % M31_P_INT := by
    have hx : x % M31_P_INT * (y % M31_P_INT) % M31_P_INT = (x * y) % M31_P_INT :=
      (Int.mul_emod x y M31_P_INT).symm
    have hmod_r : (y % M31_P_INT) % M31_P_INT = y % M31_P_INT := by unfold M31_P_INT; omega
    calc
      (x * (y % M31_P_INT)) % M31_P_INT
        = (x % M31_P_INT * ((y % M31_P_INT) % M31_P_INT)) % M31_P_INT := Int.mul_emod x (y % M31_P_INT) M31_P_INT
      _ = (x % M31_P_INT * (y % M31_P_INT)) % M31_P_INT := by rw [hmod_r]
      _ = (x * y) % M31_P_INT := hx
  have add4_mod (t1 t2 x3 y3 x4 y4 : Int) :
      (t1 + t2 + x3 * (y3 % M31_P_INT) + x4 * (y4 % M31_P_INT)) % M31_P_INT =
      (t1 + t2 + x3 * y3 + x4 * y4) % M31_P_INT := by
    have h3 := push_r x3 y3
    have h4 := push_r x4 y4
    generalize x3 * (y3 % M31_P_INT) = u3, x3 * y3 = v3 at h3 ⊢
    generalize x4 * (y4 % M31_P_INT) = u4, x4 * y4 = v4 at h4 ⊢
    unfold M31_P_INT at *; omega
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [add4_mod]
    have hring :
        (a0 : Int) * (b0 : Int) + (M31_P_INT - (a1 : Int)) * (b1 : Int) +
        (a2 : Int) * (2 * (b2 : Int) + M31_P_INT - (b3 : Int)) +
        (M31_P_INT - (a3 : Int)) * ((b2 : Int) + 2 * (b3 : Int)) =
        ((a0 : Int) * (b0 : Int) - (a1 : Int) * (b1 : Int) +
         (2 * ((a2 : Int) * (b2 : Int) - (a3 : Int) * (b3 : Int)) -
          1 * ((a2 : Int) * (b3 : Int) + (a3 : Int) * (b2 : Int)))) +
        ((b1 : Int) + (a2 : Int) + (b2 : Int) + 2 * (b3 : Int)) * M31_P_INT := by grind
    rw [hring]; unfold M31_P_INT; omega
  · rw [add4_mod]
    have hring :
        (a0 : Int) * (b1 : Int) + (a1 : Int) * (b0 : Int) +
        (a2 : Int) * ((b2 : Int) + 2 * (b3 : Int)) +
        (a3 : Int) * (2 * (b2 : Int) + M31_P_INT - (b3 : Int)) =
        ((a0 : Int) * (b1 : Int) + (a1 : Int) * (b0 : Int) +
         (2 * ((a2 : Int) * (b3 : Int) + (a3 : Int) * (b2 : Int)) +
          1 * ((a2 : Int) * (b2 : Int) - (a3 : Int) * (b3 : Int)))) +
        (a3 : Int) * M31_P_INT := by grind
    rw [hring]; unfold M31_P_INT; omega
  · have hring :
        (a0 : Int) * (b2 : Int) + (M31_P_INT - (a1 : Int)) * (b3 : Int) +
        (a2 : Int) * (b0 : Int) + (M31_P_INT - (a3 : Int)) * (b1 : Int) =
        ((a0 : Int) * (b2 : Int) - (a1 : Int) * (b3 : Int) +
         ((a2 : Int) * (b0 : Int) - (a3 : Int) * (b1 : Int))) +
        ((b3 : Int) + (b1 : Int)) * M31_P_INT := by grind
    rw [hring]; unfold M31_P_INT; omega
  · have hring :
        (a0 : Int) * (b3 : Int) + (a1 : Int) * (b2 : Int) +
        (a2 : Int) * (b1 : Int) + (a3 : Int) * (b0 : Int) =
        ((a0 : Int) * (b3 : Int) + (a1 : Int) * (b2 : Int) +
         ((a2 : Int) * (b1 : Int) + (a3 : Int) * (b0 : Int))) := by grind
    rw [hring]

/-- Sharpness witness: accumulating `5` (or `14`) unreduced maximal `M31` products
    exceeds `2^64`, proving `dot4`'s 4-term unreduced `u64` width is hardware-tight. -/
theorem five_unreduced_m31_products_gt_u64 :
    5 * ((2 ^ 31 - 2) * (2 ^ 31 - 2)) > 2 ^ 64 ∧
    14 * ((2 ^ 31 - 2) * (2 ^ 31 - 2)) > 2 ^ 64 := by
  decide

/-- Delayed-`u64` outer-Karatsuba accumulators from `starkware-libs/proving#9` (`stwo` `QM31::mul`)
    are strictly `< 2^64` for all canonical `M31` inputs `<= 2^31 - 2`. -/
theorem stwo_outer_karatsuba_u64_lt_u64
    (a0 a1 a2 a3 b0 b1 b2 b3 : Nat)
    (ha0 : a0 <= 2 ^ 31 - 2) (ha1 : a1 <= 2 ^ 31 - 2)
    (ha2 : a2 <= 2 ^ 31 - 2) (ha3 : a3 <= 2 ^ 31 - 2)
    (hb0 : b0 <= 2 ^ 31 - 2) (hb1 : b1 <= 2 ^ 31 - 2)
    (hb2 : b2 <= 2 ^ 31 - 2) (hb3 : b3 <= 2 ^ 31 - 2) :
    let cd0 := m31_fold_bitwise (b0 + b2)
    let cd1 := m31_fold_bitwise (b1 + b3)
    a0 * b0 + M31_P * M31_P - a1 * b1 < 2 ^ 64 ∧
    a0 * b1 + a1 * b0 < 2 ^ 64 ∧
    (a0 + a2) * cd0 < 2 ^ 64 ∧
    (a0 + a2) * cd1 + (a1 + a3) * cd0 < 2 ^ 64 := by
  intro cd0 cd1
  have hcd0 : cd0 <= 2 ^ 31 - 1 := by
    unfold cd0; rw [m31_fold_bitwise_eq_arith, m31_fold_arith]; omega
  have hcd1 : cd1 <= 2 ^ 31 - 1 := by
    unfold cd1; rw [m31_fold_bitwise_eq_arith, m31_fold_arith]; omega
  have hab0 : a0 + a2 <= 2 * (2 ^ 31 - 2) := by omega
  have hab1 : a1 + a3 <= 2 * (2 ^ 31 - 2) := by omega
  have p_ac : a0 * b0 <= (2 ^ 31 - 2) * (2 ^ 31 - 2) := Nat.mul_le_mul ha0 hb0
  have p_im1 : a0 * b1 <= (2 ^ 31 - 2) * (2 ^ 31 - 2) := Nat.mul_le_mul ha0 hb1
  have p_im2 : a1 * b0 <= (2 ^ 31 - 2) * (2 ^ 31 - 2) := Nat.mul_le_mul ha1 hb0
  have p_s0 : (a0 + a2) * cd0 <= (2 * (2 ^ 31 - 2)) * (2 ^ 31 - 1) := Nat.mul_le_mul hab0 hcd0
  have p_s1 : (a0 + a2) * cd1 <= (2 * (2 ^ 31 - 2)) * (2 ^ 31 - 1) := Nat.mul_le_mul hab0 hcd1
  have p_s2 : (a1 + a3) * cd0 <= (2 * (2 ^ 31 - 2)) * (2 ^ 31 - 1) := Nat.mul_le_mul hab1 hcd0
  unfold M31_P
  omega

/-- `QM31_Rank7` (`targets/qm31_stwo/qm31_stwo.rs` & `qm31_rank7_cert.json`) peak 62-bit
    intermediate bounds: pre-reduction `u_acc <= 32 * (2^31 - 2) < 2^36`, modular product
    `u_mod * v_mod < 2^62`, and `w_rem * 304226850 < 2^60 < 2^64`. -/
theorem qm31_rank7_u64_bounds
    (a0 a1 a2 a3 u_mod v_mod w_rem : Nat)
    (ha0 : a0 <= 2 ^ 31 - 2) (ha1 : a1 <= 2 ^ 31 - 2)
    (ha2 : a2 <= 2 ^ 31 - 2) (ha3 : a3 <= 2 ^ 31 - 2)
    (hu : u_mod <= 2 ^ 31 - 2) (hv : v_mod <= 2 ^ 31 - 2)
    (hw : w_rem <= 2 ^ 31 - 2) :
    a0 + 7 * a1 + 3 * a2 + 21 * a3 < 2 ^ 36 ∧
    u_mod * v_mod < 2 ^ 62 ∧
    w_rem * 304226850 < 2 ^ 60 := by
  have hprod : u_mod * v_mod <= (2 ^ 31 - 2) * (2 ^ 31 - 2) := Nat.mul_le_mul hu hv
  refine ⟨by omega, ?_, by omega⟩
  omega

end ZkBilinearCerts
