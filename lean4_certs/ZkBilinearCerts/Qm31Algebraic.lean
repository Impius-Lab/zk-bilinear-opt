/-
  ZkBilinearCerts.Qm31Algebraic
  Zero-`sorry`, zero-`axiom` Lean 4 formal proofs of universal ring and modular
  identities for degree-4 Mersenne-31 extension multiplication (`QM31`).

  Covers:
  1. Canonical schoolbook `QM31 = Z[i][u] / (i^2 + 1, u^2 - (2 + i))` in basis `(1, i, u, i*u)`.
  2. Unimodular `{0, +1, -1}` `Karatsuba-9` (`9` variable multiplications, `0` scalar constant
     multiplications — exact schedule in `starkware-libs/proving#9`).
  3. Unimodular basis isomorphism `QM31 ≅ Z[v] / (v^4 - 4v^2 + 5)` (`i = v^2 - 2`, `u = v`)
     and Winograd / Alder-Strassen minimum-rank `Rank-7` schedule on `{-2, -1, 0, 1, 2, 3, ∞}`
     (`Plonky3#2600`, `targets/qm31_stwo/qm31_rank7_cert.json`, and BitVM2), proved universally
     both over `Int` (scaled by `D = 120`, with `24`- and `8`-scaled first two coordinates, plus
     modular inverse certificates for `12`, `24`, and `120` mod `2^31 - 1`) and directly modulo
     `P = 2^31 - 1`.
  4. Symmetric `6`-multiplication squaring schedule (`Plonky3#2600` `qm31_square_min_rank`).
-/

namespace ZkBilinearCerts

/-- Mersenne-31 prime modulus `P = 2^31 - 1 = 2147483647` over `Int`. -/
def M31_P_INT : Int := 2147483647

/-- Element `(c0 + c1 * i) + (c2 + c3 * i) * u` of `Z[i][u] / (i^2 + 1, u^2 - (2 + i))`
    in canonical flattened basis `(1, i, u, i*u)`. -/
structure Qm31Int where
  c0 : Int
  c1 : Int
  c2 : Int
  c3 : Int
  deriving DecidableEq, Repr

/-- Scalar multiplication `k * x` on `Qm31Int`. -/
def qm31_scale (k : Int) (x : Qm31Int) : Qm31Int :=
  { c0 := k * x.c0
  , c1 := k * x.c1
  , c2 := k * x.c2
  , c3 := k * x.c3 }

/-- Coordinate-wise canonical Euclidean reduction modulo `P = 2^31 - 1`. -/
def qm31_mod_m31 (x : Qm31Int) : Qm31Int :=
  { c0 := x.c0 % M31_P_INT
  , c1 := x.c1 % M31_P_INT
  , c2 := x.c2 % M31_P_INT
  , c3 := x.c3 % M31_P_INT }

/-- Canonical complex multiplication `(x0 + x1 * i) * (y0 + y1 * i)` in `Z[i] / (i^2 + 1)`. -/
def cm31_mul (x0 x1 y0 y1 : Int) : Int × Int :=
  (x0 * y0 - x1 * y1, x0 * y1 + x1 * y0)

/-- Canonical schoolbook multiplication in `QM31 = Z[i][u] / (i^2 + 1, u^2 - (2 + i))`:
    `((a0 + a1*i) + (a2 + a3*i)*u) * ((b0 + b1*i) + (b2 + b3*i)*u)`
    `= (ac + (2 + i)*bd) + (ad + bc)*u`. -/
def qm31_schoolbook (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Qm31Int :=
  let (ac0, ac1) := cm31_mul a0 a1 b0 b1
  let (bd0, bd1) := cm31_mul a2 a3 b2 b3
  let (rbd0, rbd1) := cm31_mul 2 1 bd0 bd1
  let (ad0, ad1) := cm31_mul a0 a1 b2 b3
  let (bc0, bc1) := cm31_mul a2 a3 b0 b1
  { c0 := ac0 + rbd0
  , c1 := ac1 + rbd1
  , c2 := ad0 + bc0
  , c3 := ad1 + bc1 }

/-- Canonical schoolbook `QM31` multiplication reduced modulo `P = 2^31 - 1`. -/
def qm31_schoolbook_mod_m31 (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Qm31Int :=
  qm31_mod_m31 (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3)

/-! ### Defining Algebraic Relations of `qm31_schoolbook` -/

theorem qm31_schoolbook_one_left (b0 b1 b2 b3 : Int) :
    qm31_schoolbook 1 0 0 0 b0 b1 b2 b3 = ⟨b0, b1, b2, b3⟩ := by
  simp [qm31_schoolbook, cm31_mul]

theorem qm31_schoolbook_one_right (a0 a1 a2 a3 : Int) :
    qm31_schoolbook a0 a1 a2 a3 1 0 0 0 = ⟨a0, a1, a2, a3⟩ := by
  simp [qm31_schoolbook, cm31_mul]

/-- Verifies `i^2 = -1` in `QM31` (`i = (0, 1, 0, 0)`). -/
theorem qm31_schoolbook_i_sq :
    qm31_schoolbook 0 1 0 0 0 1 0 0 = ⟨-1, 0, 0, 0⟩ := by
  decide

/-- Verifies `u^2 = 2 + i` in `QM31` (`u = (0, 0, 1, 0)`). -/
theorem qm31_schoolbook_u_sq :
    qm31_schoolbook 0 0 1 0 0 0 1 0 = ⟨2, 1, 0, 0⟩ := by
  decide

theorem qm31_schoolbook_comm (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3 =
    qm31_schoolbook b0 b1 b2 b3 a0 a1 a2 a3 := by
  simp only [qm31_schoolbook, cm31_mul, Qm31Int.mk.injEq]
  refine ⟨by grind, by grind, by grind, by grind⟩

theorem qm31_schoolbook_assoc (a0 a1 a2 a3 b0 b1 b2 b3 d0 d1 d2 d3 : Int) :
    let ab := qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3
    let bd := qm31_schoolbook b0 b1 b2 b3 d0 d1 d2 d3
    qm31_schoolbook ab.c0 ab.c1 ab.c2 ab.c3 d0 d1 d2 d3 =
    qm31_schoolbook a0 a1 a2 a3 bd.c0 bd.c1 bd.c2 bd.c3 := by
  simp only [qm31_schoolbook, cm31_mul, Qm31Int.mk.injEq]
  refine ⟨by grind, by grind, by grind, by grind⟩

/-! ### 1. Unimodular `{0, +1, -1}` Karatsuba-9 (`starkware-libs/proving#9`) -/

/-- Exact unimodular `{0, +1, -1}` nested Karatsuba-9 schedule (`qm31_mul_expr_in_air` in
    `starkware-libs/proving#9`).
    Contains **9** variable-variable `Int` multiplications (`m0..m8`) and **0** scalar
    literals or `Const * Var` multiplications anywhere in the schedule: every pre-addition
    and post-addition uses pure `+` and `-`. -/
def qm31_karatsuba9 (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Qm31Int :=
  let ab0 := a0 + a2
  let ab1 := a1 + a3
  let cd0 := b0 + b2
  let cd1 := b1 + b3
  -- Exactly 9 variable-variable multiplications:
  let m0 := a0 * b0
  let m1 := a1 * b1
  let m2 := (a0 + a1) * (b0 + b1)
  let m3 := a2 * b2
  let m4 := a3 * b3
  let m5 := (a2 + a3) * (b2 + b3)
  let m6 := ab0 * cd0
  let m7 := ab1 * cd1
  let m8 := (ab0 + ab1) * (cd0 + cd1)
  -- Pure {0, +1, -1} linear reconstruction (zero scalar multiplications):
  let ac_re := m0 - m1
  let ac_im := m2 - (m0 + m1)
  let bd_re := m3 - m4
  let bd_im := m5 - (m3 + m4)
  let s_re := ac_re + bd_re
  let s_im := ac_im + bd_im
  { c0 := s_re + bd_re - bd_im
  , c1 := s_im + bd_re + bd_im
  , c2 := m6 - m7 - s_re
  , c3 := m8 - (m6 + m7) - s_im }

/-- Universal ring identity over `Int`: unimodular `{0, +1, -1}` `Karatsuba-9` equals
    canonical schoolbook `QM31` multiplication on all 4 coordinates for all `Int` inputs. -/
theorem qm31_karatsuba9_eq_schoolbook (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    qm31_karatsuba9 a0 a1 a2 a3 b0 b1 b2 b3 =
    qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3 := by
  simp only [qm31_karatsuba9, qm31_schoolbook, cm31_mul, Qm31Int.mk.injEq]
  refine ⟨by grind, by grind, by grind, by grind⟩

theorem qm31_karatsuba9_c0_eq (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    (qm31_karatsuba9 a0 a1 a2 a3 b0 b1 b2 b3).c0 =
    (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3).c0 := by
  rw [qm31_karatsuba9_eq_schoolbook]

theorem qm31_karatsuba9_c1_eq (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    (qm31_karatsuba9 a0 a1 a2 a3 b0 b1 b2 b3).c1 =
    (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3).c1 := by
  rw [qm31_karatsuba9_eq_schoolbook]

theorem qm31_karatsuba9_c2_eq (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    (qm31_karatsuba9 a0 a1 a2 a3 b0 b1 b2 b3).c2 =
    (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3).c2 := by
  rw [qm31_karatsuba9_eq_schoolbook]

theorem qm31_karatsuba9_c3_eq (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    (qm31_karatsuba9 a0 a1 a2 a3 b0 b1 b2 b3).c3 =
    (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3).c3 := by
  rw [qm31_karatsuba9_eq_schoolbook]

/-! ### 2. Unimodular Quartic Isomorphism `QM31 ≅ Z[v] / (v^4 - 4v^2 + 5)` & `Rank-7` Schedule -/

/-- Forward unimodular basis map `Z[i][u] / (i^2 + 1, u^2 - (2 + i)) -> Z[v] / (v^4 - 4v^2 + 5)`
    via `v = u`, `i = v^2 - 2`:
    `(a0 + a1*i) + (a2 + a3*i)*u  ↦  (a0 - 2*a1) + (a2 - 2*a3)*v + a1*v^2 + a3*v^3`. -/
def to_simple_quartic (a0 a1 a2 a3 : Int) : Qm31Int :=
  { c0 := a0 - 2 * a1
  , c1 := a2 - 2 * a3
  , c2 := a1
  , c3 := a3 }

/-- Inverse unimodular basis map `Z[v] / (v^4 - 4v^2 + 5) -> QM31`:
    `p0 + p1*v + p2*v^2 + p3*v^3  ↦  ((p0 + 2*p2) + p2*i) + ((p1 + 2*p3) + p3*i)*u`. -/
def from_simple_quartic (p0 p1 p2 p3 : Int) : Qm31Int :=
  { c0 := p0 + 2 * p2
  , c1 := p2
  , c2 := p1 + 2 * p3
  , c3 := p3 }

/-- Polynomial multiplication in `Z[v] / (v^4 - 4v^2 + 5)` (`v^4 = 4v^2 - 5`,
    `v^5 = 4v^3 - 5v`, `v^6 = 11v^2 - 20`). -/
def poly_mul_mod_v4_4v2_5 (p q : Qm31Int) : Qm31Int :=
  let d0 := p.c0 * q.c0
  let d1 := p.c0 * q.c1 + p.c1 * q.c0
  let d2 := p.c0 * q.c2 + p.c1 * q.c1 + p.c2 * q.c0
  let d3 := p.c0 * q.c3 + p.c1 * q.c2 + p.c2 * q.c1 + p.c3 * q.c0
  let d4 := p.c1 * q.c3 + p.c2 * q.c2 + p.c3 * q.c1
  let d5 := p.c2 * q.c3 + p.c3 * q.c2
  let d6 := p.c3 * q.c3
  { c0 := d0 - 5 * d4 - 20 * d6
  , c1 := d1 - 5 * d5
  , c2 := d2 + 4 * d4 + 11 * d6
  , c3 := d3 + 4 * d5 }

theorem from_to_simple_quartic (a0 a1 a2 a3 : Int) :
    let p := to_simple_quartic a0 a1 a2 a3
    from_simple_quartic p.c0 p.c1 p.c2 p.c3 = ⟨a0, a1, a2, a3⟩ := by
  simp only [to_simple_quartic, from_simple_quartic, Qm31Int.mk.injEq]
  refine ⟨by omega, trivial, by omega, trivial⟩

theorem to_from_simple_quartic (p0 p1 p2 p3 : Int) :
    let a := from_simple_quartic p0 p1 p2 p3
    to_simple_quartic a.c0 a.c1 a.c2 a.c3 = ⟨p0, p1, p2, p3⟩ := by
  simp only [to_simple_quartic, from_simple_quartic, Qm31Int.mk.injEq]
  refine ⟨by omega, by omega, trivial, trivial⟩

/-- Universal ring isomorphism theorem: multiplying in `Z[v] / (v^4 - 4v^2 + 5)` under
    `(to_simple_quartic, from_simple_quartic)` equals canonical `qm31_schoolbook`. -/
theorem qm31_quartic_isomorphism (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    let p := to_simple_quartic a0 a1 a2 a3
    let q := to_simple_quartic b0 b1 b2 b3
    let prod := poly_mul_mod_v4_4v2_5 p q
    from_simple_quartic prod.c0 prod.c1 prod.c2 prod.c3 =
    qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3 := by
  simp only [to_simple_quartic, from_simple_quartic, poly_mul_mod_v4_4v2_5,
             qm31_schoolbook, cm31_mul, Qm31Int.mk.injEq]
  refine ⟨by grind, by grind, by grind, by grind⟩

/-- Modular inverse certificates modulo `P = 2^31 - 1 = 2147483647` for `12`, `24`, and `120`. -/
def INV12_MOD_M31  : Int := 894784853
def INV24_MOD_M31  : Int := 1521134250
def INV120_MOD_M31 : Int := 304226850

theorem inv12_mod_m31_cert : (12 * INV12_MOD_M31) % M31_P_INT = 1 := by decide
theorem inv24_mod_m31_cert : (24 * INV24_MOD_M31) % M31_P_INT = 1 := by decide
theorem inv120_mod_m31_cert : (120 * INV120_MOD_M31) % M31_P_INT = 1 := by decide

/-- Winograd / Alder-Strassen optimal `7`-multiplication (`Rank-7`) schedule for `QM31`
    on evaluation locus `{-2, -1, 0, 1, 2, 3, ∞}` modulo `v^4 - 4v^2 + 5 = 0`, scaled by
    the exact Vandermonde common denominator `D = 5! = 120` (matching
    `targets/qm31_stwo/qm31_rank7_cert.json` and `Plonky3#2600` `qm31_mul_min_rank`). -/
def qm31_rank7_scaled120 (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Qm31Int :=
  -- 7 pointwise evaluation products at v ∈ {-2, -1, 0, 1, 2, 3, ∞}:
  let m0 := (a0 + 2 * a1 - 2 * a2 - 4 * a3) * (b0 + 2 * b1 - 2 * b2 - 4 * b3)
  let m1 := (a0 - a1 - a2 + a3) * (b0 - b1 - b2 + b3)
  let m2 := (a0 - 2 * a1) * (b0 - 2 * b1)
  let m3 := (a0 - a1 + a2 - a3) * (b0 - b1 + b2 - b3)
  let m4 := (a0 + 2 * a1 + 2 * a2 + 4 * a3) * (b0 + 2 * b1 + 2 * b2 + 4 * b3)
  let m5 := (a0 + 7 * a1 + 3 * a2 + 21 * a3) * (b0 + 7 * b1 + 3 * b2 + 21 * b3)
  let m6 := a3 * b3
  -- Exact W_z integer reconstruction rows (common denominator D = 120):
  { c0 := 5 * m0 + 100 * m1 - 90 * m2 + 100 * m3 + 5 * m4 - 600 * m6
  , c1 := 15 * m0 - 30 * m2 + 15 * m4 - 600 * m6
  , c2 := -7 * m0 - 55 * m1 + 30 * m2 + 10 * m3 + 25 * m4 - 3 * m5 + 1080 * m6
  , c3 := -9 * m0 + 15 * m1 + 10 * m2 - 30 * m3 + 15 * m4 - m5 + 360 * m6 }

/-- Universal ring identity over `Int` certifying the `Rank-7` `QM31` schedule:
    `qm31_rank7_scaled120(a, b) = 120 * qm31_schoolbook(a, b)` for all `a, b ∈ Int^4`. -/
theorem qm31_rank7_scaled120_eq_schoolbook (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    qm31_rank7_scaled120 a0 a1 a2 a3 b0 b1 b2 b3 =
    qm31_scale 120 (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3) := by
  simp only [qm31_rank7_scaled120, qm31_scale, qm31_schoolbook, cm31_mul, Qm31Int.mk.injEq]
  refine ⟨by grind, by grind, by grind, by grind⟩

/-- Exact `M31` (`mod 2^31 - 1`) execution of the `Rank-7` schedule matching
    `mul_qm31_rank7` in `targets/qm31_stwo/qm31_stwo.rs` (7 modular field multiplications
    followed by `W_z` linear combinations and multiplication by `INV120_MOD_M31 = 304226850`). -/
def qm31_rank7_mod_m31 (a0 a1 a2 a3 b0 b1 b2 b3 : Int) : Qm31Int :=
  let P := M31_P_INT
  let m0 := (((a0 + 2 * a1 - 2 * a2 - 4 * a3) % P) * ((b0 + 2 * b1 - 2 * b2 - 4 * b3) % P)) % P
  let m1 := (((a0 - a1 - a2 + a3) % P) * ((b0 - b1 - b2 + b3) % P)) % P
  let m2 := (((a0 - 2 * a1) % P) * ((b0 - 2 * b1) % P)) % P
  let m3 := (((a0 - a1 + a2 - a3) % P) * ((b0 - b1 + b2 - b3) % P)) % P
  let m4 := (((a0 + 2 * a1 + 2 * a2 + 4 * a3) % P) * ((b0 + 2 * b1 + 2 * b2 + 4 * b3) % P)) % P
  let m5 := (((a0 + 7 * a1 + 3 * a2 + 21 * a3) % P) * ((b0 + 7 * b1 + 3 * b2 + 21 * b3) % P)) % P
  let m6 := ((a3 % P) * (b3 % P)) % P
  let w0 := (5 * m0 + 100 * m1 - 90 * m2 + 100 * m3 + 5 * m4 - 600 * m6) % P
  let w1 := (15 * m0 - 30 * m2 + 15 * m4 - 600 * m6) % P
  let w2 := (-7 * m0 - 55 * m1 + 30 * m2 + 10 * m3 + 25 * m4 - 3 * m5 + 1080 * m6) % P
  let w3 := (-9 * m0 + 15 * m1 + 10 * m2 - 30 * m3 + 15 * m4 - m5 + 360 * m6) % P
  { c0 := (w0 * INV120_MOD_M31) % P
  , c1 := (w1 * INV120_MOD_M31) % P
  , c2 := (w2 * INV120_MOD_M31) % P
  , c3 := (w3 * INV120_MOD_M31) % P }

/-- Helper: cancelling `120` via `INV120_MOD_M31` modulo `M31_P_INT = 2147483647`. -/
theorem cancel_120_mod_m31 (s : Int) :
    (((120 * s) % M31_P_INT) * INV120_MOD_M31) % M31_P_INT = s % M31_P_INT := by
  have hinv_red : INV120_MOD_M31 % M31_P_INT = INV120_MOD_M31 := by decide
  have hmul : (((120 * s) % M31_P_INT) * INV120_MOD_M31) % M31_P_INT =
              ((120 * INV120_MOD_M31) * s) % M31_P_INT := by
    conv => lhs; rw [← hinv_red]
    rw [← Int.mul_emod]
    have hcomm : 120 * s * INV120_MOD_M31 = 120 * INV120_MOD_M31 * s := by grind
    rw [hcomm]
  rw [hmul]
  have hbezout : 120 * INV120_MOD_M31 = 1 + 17 * M31_P_INT := by decide
  have hexpand : (120 * INV120_MOD_M31) * s = s + (17 * s) * M31_P_INT := by
    rw [hbezout]; grind
  rw [hexpand]
  unfold M31_P_INT
  omega

/-- Universal modular equivalence over `M31` (`P = 2^31 - 1`): `qm31_rank7_mod_m31`
    produces the exact same 4 canonical `M31` residues as `qm31_schoolbook_mod_m31`
    for all `a0 a1 a2 a3 b0 b1 b2 b3 : Int`. -/
theorem qm31_rank7_mod_m31_eq_schoolbook (a0 a1 a2 a3 b0 b1 b2 b3 : Int) :
    qm31_rank7_mod_m31 a0 a1 a2 a3 b0 b1 b2 b3 =
    qm31_schoolbook_mod_m31 a0 a1 a2 a3 b0 b1 b2 b3 := by
  have hscaled := qm31_rank7_scaled120_eq_schoolbook a0 a1 a2 a3 b0 b1 b2 b3
  have hc0 := congrArg Qm31Int.c0 hscaled
  have hc1 := congrArg Qm31Int.c1 hscaled
  have hc2 := congrArg Qm31Int.c2 hscaled
  have hc3 := congrArg Qm31Int.c3 hscaled
  simp only [qm31_rank7_scaled120, qm31_scale] at hc0 hc1 hc2 hc3
  simp only [qm31_rank7_mod_m31, qm31_schoolbook_mod_m31, qm31_mod_m31, Qm31Int.mk.injEq]
  have push_prod (u v : Int) : ((u % M31_P_INT) * (v % M31_P_INT)) % M31_P_INT = (u * v) % M31_P_INT :=
    (Int.mul_emod u v M31_P_INT).symm
  simp only [push_prod]
  -- Abstract the 7 unreduced integer products so `omega` handles linear modular congruence:
  generalize (a0 + 2 * a1 - 2 * a2 - 4 * a3) * (b0 + 2 * b1 - 2 * b2 - 4 * b3) = p0 at hc0 hc1 hc2 hc3 ⊢
  generalize (a0 - a1 - a2 + a3) * (b0 - b1 - b2 + b3) = p1 at hc0 hc1 hc2 hc3 ⊢
  generalize (a0 - 2 * a1) * (b0 - 2 * b1) = p2 at hc0 hc1 hc2 hc3 ⊢
  generalize (a0 - a1 + a2 - a3) * (b0 - b1 + b2 - b3) = p3 at hc0 hc1 hc2 hc3 ⊢
  generalize (a0 + 2 * a1 + 2 * a2 + 4 * a3) * (b0 + 2 * b1 + 2 * b2 + 4 * b3) = p4 at hc0 hc1 hc2 hc3 ⊢
  generalize (a0 + 7 * a1 + 3 * a2 + 21 * a3) * (b0 + 7 * b1 + 3 * b2 + 21 * b3) = p5 at hc0 hc1 hc2 hc3 ⊢
  generalize a3 * b3 = p6 at hc0 hc1 hc2 hc3 ⊢
  have hw0 :
      (5 * (p0 % M31_P_INT) + 100 * (p1 % M31_P_INT) - 90 * (p2 % M31_P_INT) +
       100 * (p3 % M31_P_INT) + 5 * (p4 % M31_P_INT) - 600 * (p6 % M31_P_INT)) % M31_P_INT =
      (120 * (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3).c0) % M31_P_INT := by
    unfold M31_P_INT; omega
  have hw1 :
      (15 * (p0 % M31_P_INT) - 30 * (p2 % M31_P_INT) +
       15 * (p4 % M31_P_INT) - 600 * (p6 % M31_P_INT)) % M31_P_INT =
      (120 * (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3).c1) % M31_P_INT := by
    unfold M31_P_INT; omega
  have hw2 :
      (-7 * (p0 % M31_P_INT) - 55 * (p1 % M31_P_INT) + 30 * (p2 % M31_P_INT) +
       10 * (p3 % M31_P_INT) + 25 * (p4 % M31_P_INT) - 3 * (p5 % M31_P_INT) +
       1080 * (p6 % M31_P_INT)) % M31_P_INT =
      (120 * (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3).c2) % M31_P_INT := by
    unfold M31_P_INT; omega
  have hw3 :
      (-9 * (p0 % M31_P_INT) + 15 * (p1 % M31_P_INT) + 10 * (p2 % M31_P_INT) -
       30 * (p3 % M31_P_INT) + 15 * (p4 % M31_P_INT) - (p5 % M31_P_INT) +
       360 * (p6 % M31_P_INT)) % M31_P_INT =
      (120 * (qm31_schoolbook a0 a1 a2 a3 b0 b1 b2 b3).c3) % M31_P_INT := by
    unfold M31_P_INT; omega
  rw [hw0, hw1, hw2, hw3]
  exact ⟨cancel_120_mod_m31 _, cancel_120_mod_m31 _, cancel_120_mod_m31 _, cancel_120_mod_m31 _⟩

/-! ### 3. Symmetric `6`-Multiplication Squaring Schedule (`Plonky3#2600`) -/

/-- Characteristic-free `6`-multiplication symmetric squaring schedule (`qm31_square_min_rank`
    in `Plonky3#2600`). Uses denominator `1` and exactly `6` `Int` multiplications. -/
def qm31_square_rank6 (a0 a1 a2 a3 : Int) : Qm31Int :=
  let v0 := (a0 + a2) * (a0 + 2 * a2 - a3)
  let v1 := (a1 + a3) * (a1 + a2 + 2 * a3)
  let v2 := (a0 + a1 + a2 + a3) * (a0 + a1 + 3 * a2 + a3)
  let v3 := a0 * a2
  let v4 := a1 * a3
  let v5 := (a0 + a1) * (a2 + a3)
  { c0 := v0 - v1 - 4 * v3 + 2 * v4 + v5
  , c1 := -v0 - v1 + v2 + 2 * v3 + 4 * v4 - 3 * v5
  , c2 := 2 * v3 - 2 * v4
  , c3 := -2 * v3 - 2 * v4 + 2 * v5 }

theorem qm31_square_rank6_eq_schoolbook (a0 a1 a2 a3 : Int) :
    qm31_square_rank6 a0 a1 a2 a3 =
    qm31_schoolbook a0 a1 a2 a3 a0 a1 a2 a3 := by
  simp only [qm31_square_rank6, qm31_schoolbook, cm31_mul, Qm31Int.mk.injEq]
  refine ⟨by grind, by grind, by grind, by grind⟩

end ZkBilinearCerts
