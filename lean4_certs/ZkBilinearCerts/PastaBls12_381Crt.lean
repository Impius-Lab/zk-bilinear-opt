/-
  ZkBilinearCerts.PastaBls12_381Crt
  Zero-`sorry`, zero-`axiom` Core Lean 4 formal soundness and unimodular tower
  isomorphism proofs for Zcash `Pasta` (`Pallas` / `Vesta`) and `BLS12-381`
  (`rust_crates/src/halo2_gadgets.rs`, `Consensys/gnark#1951`, and the `ZcashCommunityGrants#590`
  `halo2-bilinear-opt` Fast-Track Grant).

  Covers:
  1. Exact 255-bit `p_pallas`, 255-bit `q_vesta`, and 381-bit `p_bls12_381` prime constants,
     little-endian `u64` limb decompositions (`[u64; 4]` and `[u64; 6]`), oddness, and exact
     bit-length bounds (`2^254 < p_pallas < 2^255`, `2^254 < q_vesta < 2^255`, and
     `2^380 < p_bls12_381 < 2^381`).
  2. Division-free unimodular (`det = ±1`) ring isomorphisms over `Int` for `BLS12-381`:
     - `Fp6 = Z[u, v] / (u^2 + 1, v^3 - (u + 1)) ≅ Z[v] / (v^6 - 2v^3 + 2)`,
     - `Fp12 = Fp6[w] / (w^2 - v) ≅ Z[w] / (w^12 - 2w^6 + 2)`,
     proving exact two-sided bijectivity (`toSimple ∘ fromSimple = id`, `fromSimple ∘ toSimple = id`)
     and multiplication homomorphism on all coordinates.
  3. Constructive odd-modulus / power-of-two coprimality (`Nat.Coprime q_native (2^(t * n_low))`),
     the general non-native CRT integer uniqueness theorem (`crt_uniqueness_of_coprime` &
     `crt_uniqueness_of_odd`), and concrete instantiations for:
     - `Pasta` (`Pallas` / `Vesta`) `3x88`-bit (`t = 88, n_low = 2` linear & `n_low = 3` quadratic mul)
       and `4x64`-bit (`t = 64, n_low = 3` linear & `n_low = 4` quadratic mul) wrong-field CRT gadgets;
     - `BLS12-381` `CRT-30` carry-slack non-overflow (`45 <= 72` on `5x88b` and `45 <= 56` on `6x64b`,
       `0` pre-reductions vs `Rank-23` `77`-bit overflow) and exact CRT multiplication uniqueness
       (`t = 88, n_low = 7` and `t = 64, n_low = 9`).
-/

import ZkBilinearCerts.CrtSoundness

set_option exponentiation.threshold 2048

namespace ZkBilinearCerts

/-! ### 1. Exact Zcash `Pallas`, `Vesta` & `BLS12-381` Prime Constants & Bit Bounds -/

/-- Zcash `Pallas` 255-bit base field (= `Vesta` scalar field) prime `p_pallas`
    (`rust_crates/src/halo2_gadgets.rs:1441-1446`). -/
def p_pallas : Nat :=
  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001

/-- Zcash `Vesta` 255-bit base field (= `Pallas` scalar field) prime `q_vesta`
    (`rust_crates/src/halo2_gadgets.rs:1449-1454`). -/
def q_vesta : Nat :=
  0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

/-- Zcash `BLS12-381` 381-bit base field prime `p_bls12_381`
    (`rust_crates/src/halo2_gadgets.rs:1431-1438`). -/
def p_bls12_381 : Nat :=
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

/-- Verifies `p_pallas` matches its decimal value and `halo2_gadgets.rs` `[u64; 4]` limbs. -/
theorem p_pallas_limbs_and_dec_eq :
    p_pallas = 28948022309329048855892746252171976963363056481941560715954676764349967630337 ∧
    p_pallas =
      0x992D30ED00000001 +
      0x224698FC094CF91B * 2 ^ 64 +
      0x0000000000000000 * 2 ^ 128 +
      0x4000000000000000 * 2 ^ 192 := by
  decide

/-- Exact 255-bit width and oddness of `p_pallas`. -/
theorem p_pallas_bit_bounds :
    2 ^ 254 < p_pallas ∧ p_pallas < 2 ^ 255 ∧ p_pallas % 2 = 1 := by
  decide

/-- Verifies `q_vesta` matches its decimal value and `halo2_gadgets.rs` `[u64; 4]` limbs. -/
theorem q_vesta_limbs_and_dec_eq :
    q_vesta = 28948022309329048855892746252171976963363056481941647379679742748393362948097 ∧
    q_vesta =
      0x8C46EB2100000001 +
      0x224698FC0994A8DD * 2 ^ 64 +
      0x0000000000000000 * 2 ^ 128 +
      0x4000000000000000 * 2 ^ 192 := by
  decide

/-- Exact 255-bit width and oddness of `q_vesta`. -/
theorem q_vesta_bit_bounds :
    2 ^ 254 < q_vesta ∧ q_vesta < 2 ^ 255 ∧ q_vesta % 2 = 1 := by
  decide

/-- Verifies `p_bls12_381` matches its decimal value and `halo2_gadgets.rs` `[u64; 6]` limbs. -/
theorem p_bls12_381_limbs_and_dec_eq :
    p_bls12_381 =
      4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787 ∧
    p_bls12_381 =
      0xB9FEFFFFFFFFAAAB +
      0x1EABFFFEB153FFFF * 2 ^ 64 +
      0x6730D2A0F6B0F624 * 2 ^ 128 +
      0x64774B84F38512BF * 2 ^ 192 +
      0x4B1BA7B6434BACD7 * 2 ^ 256 +
      0x1A0111EA397FE69A * 2 ^ 320 := by
  decide

/-- Exact 381-bit width and oddness of `p_bls12_381`. -/
theorem p_bls12_381_bit_bounds :
    2 ^ 380 < p_bls12_381 ∧ p_bls12_381 < 2 ^ 381 ∧ p_bls12_381 % 2 = 1 := by
  decide

/-! ### 2. Unimodular `BLS12-381` `Fp6` (`v^6 - 2v^3 + 2`) & `Fp12` (`w^12 - 2w^6 + 2`) Isomorphisms -/

/-- 6-coordinate `Int` vector for `BLS12-381` `Fp6` (`(1, u, v, uv, v^2, uv^2)` or `(1, v, ..., v^5)`). -/
structure Bls381Poly6Int where
  c0 : Int
  c1 : Int
  c2 : Int
  c3 : Int
  c4 : Int
  c5 : Int
  deriving DecidableEq, Repr

/-- 12-coordinate `Int` vector for `BLS12-381` `Fp12` (`[C0 (6), C1 (6)]` or `(1, w, ..., w^11)`). -/
structure Bls381Poly12Int where
  c0  : Int
  c1  : Int
  c2  : Int
  c3  : Int
  c4  : Int
  c5  : Int
  c6  : Int
  c7  : Int
  c8  : Int
  c9  : Int
  c10 : Int
  c11 : Int
  deriving DecidableEq, Repr

/-- Quadratic multiplication in `Z[u]/(u^2 + 1)` (`u^2 = -1`). -/
def bls381_fp2_mul_int (a0 a1 b0 b1 : Int) : Int × Int :=
  (a0 * b0 - a1 * b1, a0 * b1 + a1 * b0)

/-- Multiplication by cubic non-residue `ξ = 1 + u` in `Z[u]/(u^2 + 1)`:
    `(1 + u) * (x0 + x1*u) = (x0 - x1) + (x0 + x1)*u`. -/
def bls381_fp2_mul_by_xi_int (x : Int × Int) : Int × Int :=
  (x.1 - x.2, x.1 + x.2)

/-- Canonical `BLS12-381` sextic tower multiplication in `Z[u, v]/(u^2 + 1, v^3 - (u + 1))`
    matching `Fp6::mul_schoolbook_ref` in `rust_crates/src/halo2_gadgets.rs:800-813`. -/
def bls381_fp6_tower_mul (a b : Bls381Poly6Int) : Bls381Poly6Int :=
  let p00 := bls381_fp2_mul_int a.c0 a.c1 b.c0 b.c1
  let p01 := bls381_fp2_mul_int a.c0 a.c1 b.c2 b.c3
  let p02 := bls381_fp2_mul_int a.c0 a.c1 b.c4 b.c5
  let p10 := bls381_fp2_mul_int a.c2 a.c3 b.c0 b.c1
  let p11 := bls381_fp2_mul_int a.c2 a.c3 b.c2 b.c3
  let p12 := bls381_fp2_mul_int a.c2 a.c3 b.c4 b.c5
  let p20 := bls381_fp2_mul_int a.c4 a.c5 b.c0 b.c1
  let p21 := bls381_fp2_mul_int a.c4 a.c5 b.c2 b.c3
  let p22 := bls381_fp2_mul_int a.c4 a.c5 b.c4 b.c5
  let d3 := bls381_fp2_mul_by_xi_int (p12.1 + p21.1, p12.2 + p21.2)
  let d4 := bls381_fp2_mul_by_xi_int p22
  { c0 := p00.1 + d3.1
  , c1 := p00.2 + d3.2
  , c2 := p01.1 + p10.1 + d4.1
  , c3 := p01.2 + p10.2 + d4.2
  , c4 := p02.1 + p11.1 + p20.1
  , c5 := p02.2 + p11.2 + p20.2 }

/-- Division-free unimodular forward map `Fp6 -> Z[v]/(v^6 - 2v^3 + 2)` (`u = v^3 - 1`, `det = ±1`)
    matching `Fp6::to_simple_basis` in `halo2_gadgets.rs:778-787`. -/
def fp6_381_to_simple (x : Bls381Poly6Int) : Bls381Poly6Int :=
  { c0 := x.c0 - x.c1
  , c1 := x.c2 - x.c3
  , c2 := x.c4 - x.c5
  , c3 := x.c1
  , c4 := x.c3
  , c5 := x.c5 }

/-- Inverse unimodular map `Z[v]/(v^6 - 2v^3 + 2) -> Fp6` matching `Fp6::from_simple_basis`
    in `halo2_gadgets.rs:790-797`. -/
def fp6_381_from_simple (p : Bls381Poly6Int) : Bls381Poly6Int :=
  { c0 := p.c0 + p.c3
  , c1 := p.c3
  , c2 := p.c1 + p.c4
  , c3 := p.c4
  , c4 := p.c2 + p.c5
  , c5 := p.c5 }

/-- Polynomial multiplication in `Z[v] / (v^6 - 2v^3 + 2)` (`v^6 = 2v^3 - 2`, `v^9 = 2v^3 - 4`). -/
def poly_mul_mod_v6_2v3_2 (p q : Bls381Poly6Int) : Bls381Poly6Int :=
  let d0  := p.c0 * q.c0
  let d1  := p.c0 * q.c1 + p.c1 * q.c0
  let d2  := p.c0 * q.c2 + p.c1 * q.c1 + p.c2 * q.c0
  let d3  := p.c0 * q.c3 + p.c1 * q.c2 + p.c2 * q.c1 + p.c3 * q.c0
  let d4  := p.c0 * q.c4 + p.c1 * q.c3 + p.c2 * q.c2 + p.c3 * q.c1 + p.c4 * q.c0
  let d5  := p.c0 * q.c5 + p.c1 * q.c4 + p.c2 * q.c3 + p.c3 * q.c2 + p.c4 * q.c1 + p.c5 * q.c0
  let d6  := p.c1 * q.c5 + p.c2 * q.c4 + p.c3 * q.c3 + p.c4 * q.c2 + p.c5 * q.c1
  let d7  := p.c2 * q.c5 + p.c3 * q.c4 + p.c4 * q.c3 + p.c5 * q.c2
  let d8  := p.c3 * q.c5 + p.c4 * q.c4 + p.c5 * q.c3
  let d9  := p.c4 * q.c5 + p.c5 * q.c4
  let d10 := p.c5 * q.c5
  { c0 := d0 - 2 * d6 - 4 * d9
  , c1 := d1 - 2 * d7 - 4 * d10
  , c2 := d2 - 2 * d8
  , c3 := d3 + 2 * d6 + 2 * d9
  , c4 := d4 + 2 * d7 + 2 * d10
  , c5 := d5 + 2 * d8 }

theorem fp6_381_to_from_simple (p : Bls381Poly6Int) :
    fp6_381_to_simple (fp6_381_from_simple p) = p := by
  cases p
  simp only [fp6_381_to_simple, fp6_381_from_simple, Bls381Poly6Int.mk.injEq]
  refine ⟨by omega, by omega, by omega, trivial, trivial, trivial⟩

theorem fp6_381_from_to_simple (x : Bls381Poly6Int) :
    fp6_381_from_simple (fp6_381_to_simple x) = x := by
  cases x
  simp only [fp6_381_to_simple, fp6_381_from_simple, Bls381Poly6Int.mk.injEq]
  refine ⟨by omega, trivial, by omega, trivial, by omega, trivial⟩

/-- **Unimodular `BLS12-381` `Fp6` Trinomial Ring Isomorphism Theorem**:
    `fp6_381_from_simple (poly_mul_mod_v6_2v3_2 (fp6_381_to_simple a) (fp6_381_to_simple b))`
    equals canonical `bls381_fp6_tower_mul a b` identically over `Z`. -/
theorem bls12_381_fp6_trinomial_isomorphism (a b : Bls381Poly6Int) :
    fp6_381_from_simple (poly_mul_mod_v6_2v3_2 (fp6_381_to_simple a) (fp6_381_to_simple b)) =
    bls381_fp6_tower_mul a b := by
  simp only [fp6_381_to_simple, fp6_381_from_simple, poly_mul_mod_v6_2v3_2,
             bls381_fp6_tower_mul, bls381_fp2_mul_int, bls381_fp2_mul_by_xi_int,
             Bls381Poly6Int.mk.injEq]
  refine ⟨by grind, by grind, by grind, by grind, by grind, by grind⟩

/-- Direct forward homomorphism form of `bls12_381_fp6_trinomial_isomorphism`. -/
theorem bls12_381_fp6_to_simple_hom (a b : Bls381Poly6Int) :
    fp6_381_to_simple (bls381_fp6_tower_mul a b) =
    poly_mul_mod_v6_2v3_2 (fp6_381_to_simple a) (fp6_381_to_simple b) := by
  rw [← bls12_381_fp6_trinomial_isomorphism, fp6_381_to_from_simple]

/-- Canonical `BLS12-381` dodecic tower multiplication in `Z[u, v, w]/(u^2 + 1, v^3 - (u + 1), w^2 - v)`
    matching `Fp12::mul_schoolbook_ref` in `halo2_gadgets.rs:1036-1045`. -/
def bls381_fp12_tower_mul (a b : Bls381Poly12Int) : Bls381Poly12Int :=
  let a0 : Bls381Poly6Int := ⟨a.c0, a.c1, a.c2, a.c3, a.c4, a.c5⟩
  let a1 : Bls381Poly6Int := ⟨a.c6, a.c7, a.c8, a.c9, a.c10, a.c11⟩
  let b0 : Bls381Poly6Int := ⟨b.c0, b.c1, b.c2, b.c3, b.c4, b.c5⟩
  let b1 : Bls381Poly6Int := ⟨b.c6, b.c7, b.c8, b.c9, b.c10, b.c11⟩
  let c00 := bls381_fp6_tower_mul a0 b0
  let c11 := bls381_fp6_tower_mul a1 b1
  let c01 := bls381_fp6_tower_mul a0 b1
  let c10 := bls381_fp6_tower_mul a1 b0
  let b2xi := bls381_fp2_mul_by_xi_int (c11.c4, c11.c5)
  { c0  := c00.c0 + b2xi.1
  , c1  := c00.c1 + b2xi.2
  , c2  := c00.c2 + c11.c0
  , c3  := c00.c3 + c11.c1
  , c4  := c00.c4 + c11.c2
  , c5  := c00.c5 + c11.c3
  , c6  := c01.c0 + c10.c0
  , c7  := c01.c1 + c10.c1
  , c8  := c01.c2 + c10.c2
  , c9  := c01.c3 + c10.c3
  , c10 := c01.c4 + c10.c4
  , c11 := c01.c5 + c10.c5 }

/-- Division-free unimodular forward map `Fp12 -> Z[w]/(w^12 - 2w^6 + 2)` (`v = w^2`, `u = w^6 - 1`)
    matching `Fp12::to_simple_basis` in `halo2_gadgets.rs:991-1009`. -/
def fp12_381_to_simple (x : Bls381Poly12Int) : Bls381Poly12Int :=
  { c0  := x.c0 - x.c1
  , c1  := x.c6 - x.c7
  , c2  := x.c2 - x.c3
  , c3  := x.c8 - x.c9
  , c4  := x.c4 - x.c5
  , c5  := x.c10 - x.c11
  , c6  := x.c1
  , c7  := x.c7
  , c8  := x.c3
  , c9  := x.c9
  , c10 := x.c5
  , c11 := x.c11 }

/-- Inverse unimodular map `Z[w]/(w^12 - 2w^6 + 2) -> Fp12` matching `Fp12::from_simple_basis`
    in `halo2_gadgets.rs:1013-1024`. -/
def fp12_381_from_simple (p : Bls381Poly12Int) : Bls381Poly12Int :=
  { c0  := p.c0 + p.c6
  , c1  := p.c6
  , c2  := p.c2 + p.c8
  , c3  := p.c8
  , c4  := p.c4 + p.c10
  , c5  := p.c10
  , c6  := p.c1 + p.c7
  , c7  := p.c7
  , c8  := p.c3 + p.c9
  , c9  := p.c9
  , c10 := p.c5 + p.c11
  , c11 := p.c11 }

/-- Polynomial multiplication in `Z[w] / (w^12 - 2w^6 + 2)` (`w^12 = 2w^6 - 2`, `w^18 = 2w^6 - 4`). -/
def poly_mul_mod_w12_2w6_2 (p q : Bls381Poly12Int) : Bls381Poly12Int :=
  let d0  := p.c0 * q.c0
  let d1  := p.c0 * q.c1 + p.c1 * q.c0
  let d2  := p.c0 * q.c2 + p.c1 * q.c1 + p.c2 * q.c0
  let d3  := p.c0 * q.c3 + p.c1 * q.c2 + p.c2 * q.c1 + p.c3 * q.c0
  let d4  := p.c0 * q.c4 + p.c1 * q.c3 + p.c2 * q.c2 + p.c3 * q.c1 + p.c4 * q.c0
  let d5  := p.c0 * q.c5 + p.c1 * q.c4 + p.c2 * q.c3 + p.c3 * q.c2 + p.c4 * q.c1 + p.c5 * q.c0
  let d6  := p.c0 * q.c6 + p.c1 * q.c5 + p.c2 * q.c4 + p.c3 * q.c3 + p.c4 * q.c2 + p.c5 * q.c1 + p.c6 * q.c0
  let d7  := p.c0 * q.c7 + p.c1 * q.c6 + p.c2 * q.c5 + p.c3 * q.c4 + p.c4 * q.c3 + p.c5 * q.c2 + p.c6 * q.c1 + p.c7 * q.c0
  let d8  := p.c0 * q.c8 + p.c1 * q.c7 + p.c2 * q.c6 + p.c3 * q.c5 + p.c4 * q.c4 + p.c5 * q.c3 + p.c6 * q.c2 + p.c7 * q.c1 + p.c8 * q.c0
  let d9  := p.c0 * q.c9 + p.c1 * q.c8 + p.c2 * q.c7 + p.c3 * q.c6 + p.c4 * q.c5 + p.c5 * q.c4 + p.c6 * q.c3 + p.c7 * q.c2 + p.c8 * q.c1 + p.c9 * q.c0
  let d10 := p.c0 * q.c10 + p.c1 * q.c9 + p.c2 * q.c8 + p.c3 * q.c7 + p.c4 * q.c6 + p.c5 * q.c5 + p.c6 * q.c4 + p.c7 * q.c3 + p.c8 * q.c2 + p.c9 * q.c1 + p.c10 * q.c0
  let d11 := p.c0 * q.c11 + p.c1 * q.c10 + p.c2 * q.c9 + p.c3 * q.c8 + p.c4 * q.c7 + p.c5 * q.c6 + p.c6 * q.c5 + p.c7 * q.c4 + p.c8 * q.c3 + p.c9 * q.c2 + p.c10 * q.c1 + p.c11 * q.c0
  let d12 := p.c1 * q.c11 + p.c2 * q.c10 + p.c3 * q.c9 + p.c4 * q.c8 + p.c5 * q.c7 + p.c6 * q.c6 + p.c7 * q.c5 + p.c8 * q.c4 + p.c9 * q.c3 + p.c10 * q.c2 + p.c11 * q.c1
  let d13 := p.c2 * q.c11 + p.c3 * q.c10 + p.c4 * q.c9 + p.c5 * q.c8 + p.c6 * q.c7 + p.c7 * q.c6 + p.c8 * q.c5 + p.c9 * q.c4 + p.c10 * q.c3 + p.c11 * q.c2
  let d14 := p.c3 * q.c11 + p.c4 * q.c10 + p.c5 * q.c9 + p.c6 * q.c8 + p.c7 * q.c7 + p.c8 * q.c6 + p.c9 * q.c5 + p.c10 * q.c4 + p.c11 * q.c3
  let d15 := p.c4 * q.c11 + p.c5 * q.c10 + p.c6 * q.c9 + p.c7 * q.c8 + p.c8 * q.c7 + p.c9 * q.c6 + p.c10 * q.c5 + p.c11 * q.c4
  let d16 := p.c5 * q.c11 + p.c6 * q.c10 + p.c7 * q.c9 + p.c8 * q.c8 + p.c9 * q.c7 + p.c10 * q.c6 + p.c11 * q.c5
  let d17 := p.c6 * q.c11 + p.c7 * q.c10 + p.c8 * q.c9 + p.c9 * q.c8 + p.c10 * q.c7 + p.c11 * q.c6
  let d18 := p.c7 * q.c11 + p.c8 * q.c10 + p.c9 * q.c9 + p.c10 * q.c8 + p.c11 * q.c7
  let d19 := p.c8 * q.c11 + p.c9 * q.c10 + p.c10 * q.c9 + p.c11 * q.c8
  let d20 := p.c9 * q.c11 + p.c10 * q.c10 + p.c11 * q.c9
  let d21 := p.c10 * q.c11 + p.c11 * q.c10
  let d22 := p.c11 * q.c11
  { c0  := d0  - 2 * d12 - 4 * d18
  , c1  := d1  - 2 * d13 - 4 * d19
  , c2  := d2  - 2 * d14 - 4 * d20
  , c3  := d3  - 2 * d15 - 4 * d21
  , c4  := d4  - 2 * d16 - 4 * d22
  , c5  := d5  - 2 * d17
  , c6  := d6  + 2 * d12 + 2 * d18
  , c7  := d7  + 2 * d13 + 2 * d19
  , c8  := d8  + 2 * d14 + 2 * d20
  , c9  := d9  + 2 * d15 + 2 * d21
  , c10 := d10 + 2 * d16 + 2 * d22
  , c11 := d11 + 2 * d17 }

theorem fp12_381_to_from_simple (p : Bls381Poly12Int) :
    fp12_381_to_simple (fp12_381_from_simple p) = p := by
  cases p
  simp only [fp12_381_to_simple, fp12_381_from_simple, Bls381Poly12Int.mk.injEq]
  refine ⟨by omega, by omega, by omega, by omega, by omega, by omega,
          trivial, trivial, trivial, trivial, trivial, trivial⟩

theorem fp12_381_from_to_simple (x : Bls381Poly12Int) :
    fp12_381_from_simple (fp12_381_to_simple x) = x := by
  cases x
  simp only [fp12_381_to_simple, fp12_381_from_simple, Bls381Poly12Int.mk.injEq]
  refine ⟨by omega, trivial, by omega, trivial, by omega, trivial,
          by omega, trivial, by omega, trivial, by omega, trivial⟩

/-- **Unimodular `BLS12-381` `Fp12` Trinomial Ring Isomorphism Theorem**:
    `fp12_381_from_simple (poly_mul_mod_w12_2w6_2 (fp12_381_to_simple a) (fp12_381_to_simple b))`
    equals canonical `bls381_fp12_tower_mul a b` identically over `Z`. -/
theorem bls12_381_fp12_trinomial_isomorphism (a b : Bls381Poly12Int) :
    fp12_381_from_simple (poly_mul_mod_w12_2w6_2 (fp12_381_to_simple a) (fp12_381_to_simple b)) =
    bls381_fp12_tower_mul a b := by
  simp only [fp12_381_to_simple, fp12_381_from_simple, poly_mul_mod_w12_2w6_2,
             bls381_fp12_tower_mul, bls381_fp6_tower_mul, bls381_fp2_mul_int,
             bls381_fp2_mul_by_xi_int, Bls381Poly12Int.mk.injEq]
  refine ⟨by grind, by grind, by grind, by grind, by grind, by grind,
          by grind, by grind, by grind, by grind, by grind, by grind⟩

/-- Direct forward homomorphism form of `bls12_381_fp12_trinomial_isomorphism`. -/
theorem bls12_381_fp12_to_simple_hom (a b : Bls381Poly12Int) :
    fp12_381_to_simple (bls381_fp12_tower_mul a b) =
    poly_mul_mod_w12_2w6_2 (fp12_381_to_simple a) (fp12_381_to_simple b) := by
  rw [← bls12_381_fp12_trinomial_isomorphism, fp12_381_to_from_simple]

/-! ### 3. General CRT Integer Uniqueness & Concrete `Pasta` + `BLS12-381` `CRT-30` Soundness -/

/-- Constructive Bézout identity for any odd natural number `q_native` (`q_native % 2 = 1`)
    and any power of two `2 ^ m`: `∃ u v : Int, u * q_native + v * 2^m = 1`. -/
theorem odd_bezout_two_pow (q_native : Nat) (hodd : q_native % 2 = 1) (m : Nat) :
    ∃ u v : Int, u * (q_native : Int) + v * ((2 : Int) ^ m) = 1 := by
  induction m with
  | zero =>
    exact ⟨0, 1, by simp⟩
  | succ k ih =>
    obtain ⟨u, v, huv⟩ := ih
    have hpow : (2 : Int) ^ (k + 1) = 2 * ((2 : Int) ^ k) := by grind
    if hv : v % 2 = 0 then
      have hv_eq : v = 2 * (v / 2) := by omega
      refine ⟨u, v / 2, ?_⟩
      rw [hpow]
      have : u * (q_native : Int) + (v / 2) * (2 * (2 : Int) ^ k) =
             u * (q_native : Int) + (2 * (v / 2)) * ((2 : Int) ^ k) := by grind
      rw [this, ← hv_eq, huv]
    else
      have hvq_even : (v + (q_native : Int)) % 2 = 0 := by omega
      have hvq_eq : v + (q_native : Int) = 2 * ((v + (q_native : Int)) / 2) := by omega
      refine ⟨u - (2 : Int) ^ k, (v + (q_native : Int)) / 2, ?_⟩
      rw [hpow]
      have : (u - (2 : Int) ^ k) * (q_native : Int) +
             ((v + (q_native : Int)) / 2) * (2 * (2 : Int) ^ k) =
             u * (q_native : Int) - ((2 : Int) ^ k) * (q_native : Int) +
             (2 * ((v + (q_native : Int)) / 2)) * ((2 : Int) ^ k) := by grind
      rw [this, ← hvq_eq]
      grind

/-- Every odd natural number `q_native` (`q_native % 2 = 1`) is coprime to `2 ^ m` for all `m : Nat`. -/
theorem odd_nat_coprime_two_pow (q_native : Nat) (hodd : q_native % 2 = 1) (m : Nat) :
    Nat.Coprime q_native (2 ^ m) := by
  unfold Nat.Coprime
  obtain ⟨u, v, huv⟩ := odd_bezout_two_pow q_native hodd m
  let g := Nat.gcd q_native (2 ^ m)
  have hg_q : g ∣ q_native := Nat.gcd_dvd_left q_native (2 ^ m)
  have hg_2 : g ∣ 2 ^ m := Nat.gcd_dvd_right q_native (2 ^ m)
  obtain ⟨kq, hkq⟩ := hg_q
  obtain ⟨k2, hk2⟩ := hg_2
  have hg_pos : g >= 1 := by
    if hg0 : g = 0 then
      rw [hg0, Nat.zero_mul] at hkq
      omega
    else
      omega
  if hg1 : g = 1 then
    exact hg1
  else
    have hg_ge2 : (g : Int) >= 2 := by omega
    have hfactor : u * (q_native : Int) + v * ((2 : Int) ^ m) =
        (g : Int) * (u * (kq : Int) + v * (k2 : Int)) := by
      have hq_cast : (q_native : Int) = (g : Int) * (kq : Int) := by exact_mod_cast hkq
      have h2_cast : ((2 : Int) ^ m) = (g : Int) * (k2 : Int) := by exact_mod_cast hk2
      rw [hq_cast, h2_cast]
      grind
    rw [huv] at hfactor
    let w := u * (kq : Int) + v * (k2 : Int)
    have hw : (1 : Int) = (g : Int) * w := hfactor
    if hw_pos : w >= 1 then
      have : (g : Int) * w >= 2 * 1 := Int.mul_le_mul hg_ge2 hw_pos (by omega) (by omega)
      omega
    else if hw_neg : w <= -1 then
      have hneg : (-w) >= 1 := by omega
      have hmul : (g : Int) * (-w) >= 2 * 1 := Int.mul_le_mul hg_ge2 hneg (by omega) (by omega)
      have : (g : Int) * (-w) = -((g : Int) * w) := by grind
      omega
    else
      have hw0 : w = 0 := by omega
      rw [hw0] at hw
      omega

/-- **General Non-Native CRT Uniqueness Theorem (Coprime Formulation)**:
    For any `q_native > 0` coprime to `2^(t * n_low)`, if `|diff| < q_native * 2^(t * n_low)`,
    `diff % q_native = 0`, and `diff % 2^(t * n_low) = 0`, then `diff = 0`! -/
theorem crt_uniqueness_of_coprime
    (q_native t n_low : Nat) (diff : Int)
    (hq_pos : q_native > 0)
    (hcop : Nat.Coprime q_native (2 ^ (t * n_low)))
    (hbound : diff.natAbs < q_native * 2 ^ (t * n_low))
    (hmod_q : diff % (q_native : Int) = 0)
    (hmod_2 : diff % ((2 : Int) ^ (t * n_low)) = 0) :
    diff = 0 := by
  let F : Int := (q_native : Int)
  let M : Int := (2 : Int) ^ (t * n_low)
  have hF_pos : F > 0 := by unfold F; omega
  have hM_pos : M > 0 := by
    have : (2 ^ (t * n_low) : Nat) > 0 := Nat.two_pow_pos (t * n_low)
    unfold M; exact_mod_cast this
  have hgcd_int : Int.gcd F M = 1 := by
    unfold Int.gcd F M
    have hFa : (q_native : Int).natAbs = q_native := Int.natAbs_natCast q_native
    have hMa : ((2 : Int) ^ (t * n_low)).natAbs = 2 ^ (t * n_low) := by
      have hcast : ((2 : Int) ^ (t * n_low)) = ((2 ^ (t * n_low) : Nat) : Int) := by norm_cast
      rw [hcast, Int.natAbs_natCast]
    rw [hFa, hMa]
    exact hcop
  obtain ⟨m, hm⟩ := coprime_mul_dvd_of_emod_zero F M diff hF_pos hM_pos hgcd_int hmod_q hmod_2
  have hFM_cast : F * M = ((q_native * 2 ^ (t * n_low) : Nat) : Int) := by
    unfold F M; norm_cast
  have hlo : -(F * M) < diff := by rw [hFM_cast]; omega
  have hhi : diff < F * M := by rw [hFM_cast]; omega
  exact eq_zero_of_mul_bounded (F * M) diff m (Int.mul_pos hF_pos hM_pos) hm hlo hhi

/-- **General Non-Native CRT Uniqueness Theorem (Odd Native Modulus Formulation)**:
    Whenever `q_native % 2 = 1` and `|diff| < q_native * 2^(t * n_low)`, `diff % q_native = 0`
    and `diff % 2^(t * n_low) = 0` force `diff = 0`! -/
theorem crt_uniqueness_of_odd
    (q_native t n_low : Nat) (diff : Int)
    (hodd : q_native % 2 = 1)
    (hbound : diff.natAbs < q_native * 2 ^ (t * n_low))
    (hmod_q : diff % (q_native : Int) = 0)
    (hmod_2 : diff % ((2 : Int) ^ (t * n_low)) = 0) :
    diff = 0 :=
  crt_uniqueness_of_coprime q_native t n_low diff
    (by omega) (odd_nat_coprime_two_pow q_native hodd (t * n_low)) hbound hmod_q hmod_2

/-- **`Pasta` `3x88`-Bit (`t = 88, n_low = 2`) & `4x64`-Bit (`t = 64, n_low = 3`) Linear/Single-Width
    CRT Uniqueness Corollary** (over both `p_pallas` and `q_vesta`):
    Any integer relation discrepancy `diff = LHS - (r + s * k * p_wrong)` bounded by
    `q_native * 2^(88 * 2)` (resp. `q_native * 2^(64 * 3)`, which covers all `<= 2^175` / `<= 2^191`
    scaled `Pasta` reductions) satisfying the native and low-limb carry equations is identically `0`! -/
theorem pasta_linear_crt_3x88_and_4x64_sound (diff : Int) :
    -- 1. Pallas native (`3x88b` with `n_low = 2`, and `4x64b` with `n_low = 3`):
    (diff.natAbs < p_pallas * 2 ^ (88 * 2) →
      diff % (p_pallas : Int) = 0 → diff % ((2 : Int) ^ (88 * 2)) = 0 → diff = 0) ∧
    (diff.natAbs < p_pallas * 2 ^ (64 * 3) →
      diff % (p_pallas : Int) = 0 → diff % ((2 : Int) ^ (64 * 3)) = 0 → diff = 0) ∧
    -- 2. Vesta native (`3x88b` with `n_low = 2`, and `4x64b` with `n_low = 3`):
    (diff.natAbs < q_vesta * 2 ^ (88 * 2) →
      diff % (q_vesta : Int) = 0 → diff % ((2 : Int) ^ (88 * 2)) = 0 → diff = 0) ∧
    (diff.natAbs < q_vesta * 2 ^ (64 * 3) →
      diff % (q_vesta : Int) = 0 → diff % ((2 : Int) ^ (64 * 3)) = 0 → diff = 0) := by
  have hp_odd := p_pallas_bit_bounds.2.2
  have hq_odd := q_vesta_bit_bounds.2.2
  exact ⟨fun hb h1 h2 => crt_uniqueness_of_odd p_pallas 88 2 diff hp_odd hb h1 h2,
         fun hb h1 h2 => crt_uniqueness_of_odd p_pallas 64 3 diff hp_odd hb h1 h2,
         fun hb h1 h2 => crt_uniqueness_of_odd q_vesta 88 2 diff hq_odd hb h1 h2,
         fun hb h1 h2 => crt_uniqueness_of_odd q_vesta 64 3 diff hq_odd hb h1 h2⟩

/-- **`Pasta` Full Quadratic Wrong-Field Multiplication Soundness (`3x88b` `n_low = 3` & `4x64b` `n_low = 4`)**
    matching `Halo2LookupCostModel::estimate_pasta_wrong_field_mul` (`halo2_gadgets.rs:1767-1827`):
    For both `Pallas`-in-`Vesta` and `Vesta`-in-`Pallas`, for ALL canonical operands `0 <= a, b, r < p_wrong`
    and exact `quoBits = 255` quotients `0 <= k < 2^255`, checking mod-`q_native` and `3` low `88`-bit
    carries (`mod 2^264`, saving `1` carry vs `4`) or `4` low `64`-bit carries (`mod 2^256`, saving `2`
    carries vs `6`) forces exact integer multiplication `a * b - k * p_wrong = r`! -/
theorem pasta_wrong_field_mul_sound
    (a b k r : Int) :
    -- 1. Pallas emulated over Vesta (`3x88b` `n_low = 3` and `4x64b` `n_low = 4`):
    (0 <= a → a < (p_pallas : Int) → 0 <= b → b < (p_pallas : Int) →
     0 <= r → r < (p_pallas : Int) → 0 <= k → k < (2 : Int) ^ 255 →
     crt_mod_eq (q_vesta : Int) ((2 : Int) ^ (88 * 3)) a b (p_pallas : Int) k r →
     crt_int_eq a b (p_pallas : Int) k r) ∧
    (0 <= a → a < (p_pallas : Int) → 0 <= b → b < (p_pallas : Int) →
     0 <= r → r < (p_pallas : Int) → 0 <= k → k < (2 : Int) ^ 255 →
     crt_mod_eq (q_vesta : Int) ((2 : Int) ^ (64 * 4)) a b (p_pallas : Int) k r →
     crt_int_eq a b (p_pallas : Int) k r) ∧
    -- 2. Vesta emulated over Pallas (`3x88b` `n_low = 3` and `4x64b` `n_low = 4`):
    (0 <= a → a < (q_vesta : Int) → 0 <= b → b < (q_vesta : Int) →
     0 <= r → r < (q_vesta : Int) → 0 <= k → k < (2 : Int) ^ 255 →
     crt_mod_eq (p_pallas : Int) ((2 : Int) ^ (88 * 3)) a b (q_vesta : Int) k r →
     crt_int_eq a b (q_vesta : Int) k r) ∧
    (0 <= a → a < (q_vesta : Int) → 0 <= b → b < (q_vesta : Int) →
     0 <= r → r < (q_vesta : Int) → 0 <= k → k < (2 : Int) ^ 255 →
     crt_mod_eq (p_pallas : Int) ((2 : Int) ^ (64 * 4)) a b (q_vesta : Int) k r →
     crt_int_eq a b (q_vesta : Int) k r) := by
  have hpv_64_nat : 2 ^ 255 * p_pallas <= q_vesta * 2 ^ (64 * 4) := by decide
  have hpv_88_nat : 2 ^ 255 * p_pallas <= q_vesta * 2 ^ (88 * 3) := by decide
  have hvp_64_nat : 2 ^ 255 * q_vesta <= p_pallas * 2 ^ (64 * 4) := by decide
  have hvp_88_nat : 2 ^ 255 * q_vesta <= p_pallas * 2 ^ (88 * 3) := by decide
  have hp_lt_255_nat : p_pallas < 2 ^ 255 := p_pallas_bit_bounds.2.1
  have hq_lt_255_nat : q_vesta < 2 ^ 255 := q_vesta_bit_bounds.2.1
  have hp_odd := p_pallas_bit_bounds.2.2
  have hq_odd := q_vesta_bit_bounds.2.2
  have helper (qn pw t nl : Nat)
      (hqn_odd : qn % 2 = 1)
      (hpw_lt_nat : pw < 2 ^ 255)
      (hcap_nat : 2 ^ 255 * pw <= qn * 2 ^ (t * nl))
      (ha0 : 0 <= a) (ha1 : a < (pw : Int)) (hb0 : 0 <= b) (hb1 : b < (pw : Int))
      (hr0 : 0 <= r) (hr1 : r < (pw : Int)) (hk0 : 0 <= k) (hk1 : k < (2 : Int) ^ 255)
      (hmod : crt_mod_eq (qn : Int) ((2 : Int) ^ (t * nl)) a b (pw : Int) k r) :
      crt_int_eq a b (pw : Int) k r := by
    unfold crt_mod_eq at hmod
    unfold crt_int_eq
    have htwo255 : ((2 : Int) ^ 255) = ((2 ^ 255 : Nat) : Int) := (Int.natCast_pow 2 255).symm
    rw [htwo255] at hk1
    generalize (2 ^ 255 : Nat) = QMAX at hpw_lt_nat hcap_nat hk1
    have hpw_lt : (pw : Int) < (QMAX : Int) := Int.ofNat_lt.mpr hpw_lt_nat
    have hcap : (QMAX : Int) * (pw : Int) <= ((qn * 2 ^ (t * nl) : Nat) : Int) := by
      rw [← Int.natCast_mul]
      exact Int.ofNat_le.mpr hcap_nat
    have hab_nn : 0 <= a * b := Int.mul_nonneg ha0 hb0
    have hab_hi : a * b < (QMAX : Int) * (pw : Int) := by
      have h1 : a * b <= ((QMAX : Int) - 1) * ((pw : Int) - 1) :=
        Int.mul_le_mul (by omega) (by omega) hb0 (by omega)
      have hexp : ((QMAX : Int) - 1) * ((pw : Int) - 1) =
                  (QMAX : Int) * (pw : Int) - (pw : Int) - (QMAX : Int) + 1 := by grind
      omega
    have hkp_nn : 0 <= k * (pw : Int) := Int.mul_nonneg hk0 (by omega)
    have hkpr_hi : k * (pw : Int) + r < (QMAX : Int) * (pw : Int) := by
      have h1 : k * (pw : Int) <= ((QMAX : Int) - 1) * (pw : Int) :=
        Int.mul_le_mul_of_nonneg_right (by omega) (by omega)
      have hexp : ((QMAX : Int) - 1) * (pw : Int) = (QMAX : Int) * (pw : Int) - (pw : Int) := by grind
      omega
    have hnatAbs : (a * b - k * (pw : Int) - r).natAbs < qn * 2 ^ (t * nl) := by omega
    have hzero := crt_uniqueness_of_odd qn t nl (a * b - k * (pw : Int) - r)
      hqn_odd hnatAbs hmod.1 hmod.2
    omega
  exact ⟨helper q_vesta p_pallas 88 3 hq_odd hp_lt_255_nat hpv_88_nat,
         helper q_vesta p_pallas 64 4 hq_odd hp_lt_255_nat hpv_64_nat,
         helper p_pallas q_vesta 88 3 hp_odd hq_lt_255_nat hvp_88_nat,
         helper p_pallas q_vesta 64 4 hp_odd hq_lt_255_nat hvp_64_nat⟩

/-- **`BLS12-381` `CRT-30` vs `Rank-23` Carry-Ceiling Soundness over `Pasta` (`5x88b` & `6x64b`)**
    (`halo2_gadgets.rs:1849-1861`):
    - On `5x88`-bit `Pasta` chips (`255 - 2 - 2*88 - 3 - 2 = 72`-bit slack budget), `CRT-30` (`45` bits)
      satisfies `45 <= 72` and `2^(2*88 + 45 + 3 + 2) = 2^226 < min(p_pallas, q_vesta)` (`0` pre-reductions),
      whereas `Rank-23` (`77` bits) breaches `77 > 72`.
    - On `6x64`-bit `Pasta` chips (`56`-bit 2-limb slack budget), `CRT-30` (`45` bits) satisfies
      `45 <= 56` and `2^(196 + 45) = 2^241 < min(p_pallas, q_vesta)` (`0` pre-reductions), whereas
      `Rank-23` (`77` bits) breaches `77 > 56` and overflows `2^(196 + 77) = 2^273 > max(p_pallas, q_vesta)`! -/
theorem bls12_381_crt30_carry_slack_sound :
    -- 5x88b single-limb carry envelope:
    255 - 2 - 2 * 88 - 3 - 2 = 72 ∧
    45 <= 72 ∧
    2 ^ (2 * 88 + 45 + 3 + 2) < p_pallas ∧
    2 ^ (2 * 88 + 45 + 3 + 2) < q_vesta ∧
    77 > 72 ∧
    -- 6x64b packed 2-limb carry envelope:
    45 <= 56 ∧
    2 ^ (196 + 45) < p_pallas ∧
    2 ^ (196 + 45) < q_vesta ∧
    77 > 56 ∧
    2 ^ (196 + 77) > p_pallas ∧
    2 ^ (196 + 77) > q_vesta := by
  decide

/-- **`BLS12-381` `CRT-30` Non-Native Multiplication Uniqueness (`5x88b` `n_low = 7` & `6x64b` `n_low = 9`)**
    (`halo2_gadgets.rs:1863-1876`):
    For EVERY `CRT-30` evaluation product `0 <= prod_uv <= 2^45 * (p_bls12_381 - 1)^2`, quotient
    `0 <= k < 2^426`, and remainder `0 <= r < p_bls12_381` over `q_native ∈ {p_pallas, q_vesta}`,
    enforcing the native check and `7` low `88`-bit carries (`mod 2^616`, saving `1` carry vs `8`)
    or `9` low `64`-bit carries (`mod 2^576`, saving `2` carries vs `11`) forces exact integer
    equality `prod_uv - k * p_bls12_381 = r`! -/
theorem bls12_381_crt30_mul_sound (prod_uv k r : Int)
    (hprod_lo : 0 <= prod_uv)
    (hprod_hi : prod_uv <= ((2 : Int) ^ 45) * ((p_bls12_381 : Int) - 1) * ((p_bls12_381 : Int) - 1))
    (hr_lo : 0 <= r) (hr_hi : r < (p_bls12_381 : Int))
    (hk_lo : 0 <= k) (hk_hi : k < (2 : Int) ^ 426) :
    -- 1. Over Pallas (`5x88b` `n_low = 7` and `6x64b` `n_low = 9`):
    ((prod_uv - k * (p_bls12_381 : Int) - r) % (p_pallas : Int) = 0 →
     (prod_uv - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (88 * 7)) = 0 →
     prod_uv - k * (p_bls12_381 : Int) = r) ∧
    ((prod_uv - k * (p_bls12_381 : Int) - r) % (p_pallas : Int) = 0 →
     (prod_uv - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (64 * 9)) = 0 →
     prod_uv - k * (p_bls12_381 : Int) = r) ∧
    -- 2. Over Vesta (`5x88b` `n_low = 7` and `6x64b` `n_low = 9`):
    ((prod_uv - k * (p_bls12_381 : Int) - r) % (q_vesta : Int) = 0 →
     (prod_uv - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (88 * 7)) = 0 →
     prod_uv - k * (p_bls12_381 : Int) = r) ∧
    ((prod_uv - k * (p_bls12_381 : Int) - r) % (q_vesta : Int) = 0 →
     (prod_uv - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (64 * 9)) = 0 →
     prod_uv - k * (p_bls12_381 : Int) = r) := by
  have hpos_lt_rhs_nat :
      2 ^ 45 * (p_bls12_381 - 1) * (p_bls12_381 - 1) < 2 ^ 426 * p_bls12_381 := by decide
  have hp_88_nat : 2 ^ 426 * p_bls12_381 <= p_pallas * 2 ^ (88 * 7) := by decide
  have hp_64_nat : 2 ^ 426 * p_bls12_381 <= p_pallas * 2 ^ (64 * 9) := by decide
  have hq_88_nat : 2 ^ 426 * p_bls12_381 <= q_vesta * 2 ^ (88 * 7) := by decide
  have hq_64_nat : 2 ^ 426 * p_bls12_381 <= q_vesta * 2 ^ (64 * 9) := by decide
  have hp381_pos : (0 : Int) < (p_bls12_381 : Int) := by decide
  have h45 : ((2 : Int) ^ 45) = ((2 ^ 45 : Nat) : Int) := (Int.natCast_pow 2 45).symm
  have h426 : ((2 : Int) ^ 426) = ((2 ^ 426 : Nat) : Int) := (Int.natCast_pow 2 426).symm
  have hp1 : ((p_bls12_381 : Int) - 1) = ((p_bls12_381 - 1 : Nat) : Int) := by decide
  rw [h45, hp1] at hprod_hi
  rw [h426] at hk_hi
  generalize (2 ^ 426 : Nat) = Q426 at hpos_lt_rhs_nat hp_88_nat hp_64_nat hq_88_nat hq_64_nat hk_hi
  have hprod_lt : prod_uv < (Q426 : Int) * (p_bls12_381 : Int) := by
    have hcast_lhs : ((2 ^ 45 : Nat) : Int) * ((p_bls12_381 - 1 : Nat) : Int) * ((p_bls12_381 - 1 : Nat) : Int) =
        ((2 ^ 45 * (p_bls12_381 - 1) * (p_bls12_381 - 1) : Nat) : Int) := by
      rw [← Int.natCast_mul, ← Int.natCast_mul]
    rw [hcast_lhs] at hprod_hi
    have hlt_int : ((2 ^ 45 * (p_bls12_381 - 1) * (p_bls12_381 - 1) : Nat) : Int) <
        (Q426 : Int) * (p_bls12_381 : Int) := by
      rw [← Int.natCast_mul]
      exact Int.ofNat_lt.mpr hpos_lt_rhs_nat
    omega
  have hkp_nn : 0 <= k * (p_bls12_381 : Int) := Int.mul_nonneg hk_lo (by omega)
  have hkpr_hi : k * (p_bls12_381 : Int) + r < (Q426 : Int) * (p_bls12_381 : Int) := by
    have h1 : k * (p_bls12_381 : Int) <= ((Q426 : Int) - 1) * (p_bls12_381 : Int) :=
      Int.mul_le_mul_of_nonneg_right (by omega) (by omega)
    have hexp : ((Q426 : Int) - 1) * (p_bls12_381 : Int) =
                (Q426 : Int) * (p_bls12_381 : Int) - (p_bls12_381 : Int) := by grind
    omega
  have hp_odd := p_pallas_bit_bounds.2.2
  have hq_odd := q_vesta_bit_bounds.2.2
  have solve_case (qn t nl : Nat) (hodd : qn % 2 = 1)
      (hcap_nat : Q426 * p_bls12_381 <= qn * 2 ^ (t * nl))
      (hm1 : (prod_uv - k * (p_bls12_381 : Int) - r) % (qn : Int) = 0)
      (hm2 : (prod_uv - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (t * nl)) = 0) :
      prod_uv - k * (p_bls12_381 : Int) = r := by
    have hcap : (Q426 : Int) * (p_bls12_381 : Int) <= ((qn * 2 ^ (t * nl) : Nat) : Int) := by
      rw [← Int.natCast_mul]
      exact Int.ofNat_le.mpr hcap_nat
    have hnatAbs : (prod_uv - k * (p_bls12_381 : Int) - r).natAbs < qn * 2 ^ (t * nl) := by omega
    have hz := crt_uniqueness_of_odd qn t nl (prod_uv - k * (p_bls12_381 : Int) - r) hodd hnatAbs hm1 hm2
    omega
  exact ⟨solve_case p_pallas 88 7 hp_odd hp_88_nat,
         solve_case p_pallas 64 9 hp_odd hp_64_nat,
         solve_case q_vesta 88 7 hq_odd hq_88_nat,
         solve_case q_vesta 64 9 hq_odd hq_64_nat⟩

/-- **`BLS12-381` `CRT-30` Output Linear Reconstruction Uniqueness (`n_low = 3` on `5x88b` & `6x64b`)**
    (`halo2_gadgets.rs:1917-1934`, `out_bits = 52`):
    For any signed `W_z * m - D * c` linear combination bounded by `|lhs| <= 2^52 * (p_bls12_381 - 1)`,
    canonical output `0 <= r < p_bls12_381`, and signed quotient `|k| < 2^53`, enforcing mod-`q_native`
    (`q_native ∈ {p_pallas, q_vesta}`) and `3` low carries (`mod 2^264` on `5x88b` or `mod 2^192` on `6x64b`)
    forces exact integer equality `lhs - k * p_bls12_381 = r`! -/
theorem bls12_381_crt30_out_reconstruction_sound (lhs k r : Int)
    (hlhs : lhs.natAbs <= 2 ^ 52 * (p_bls12_381 - 1))
    (hr_lo : 0 <= r) (hr_hi : r < (p_bls12_381 : Int))
    (hk : k.natAbs < 2 ^ 53) :
    ((lhs - k * (p_bls12_381 : Int) - r) % (p_pallas : Int) = 0 →
     (lhs - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (64 * 3)) = 0 →
     lhs - k * (p_bls12_381 : Int) = r) ∧
    ((lhs - k * (p_bls12_381 : Int) - r) % (p_pallas : Int) = 0 →
     (lhs - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (88 * 3)) = 0 →
     lhs - k * (p_bls12_381 : Int) = r) ∧
    ((lhs - k * (p_bls12_381 : Int) - r) % (q_vesta : Int) = 0 →
     (lhs - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (64 * 3)) = 0 →
     lhs - k * (p_bls12_381 : Int) = r) ∧
    ((lhs - k * (p_bls12_381 : Int) - r) % (q_vesta : Int) = 0 →
     (lhs - k * (p_bls12_381 : Int) - r) % ((2 : Int) ^ (88 * 3)) = 0 →
     lhs - k * (p_bls12_381 : Int) = r) := by
  have hp_64 : 2 ^ 52 * (p_bls12_381 - 1) + 2 ^ 53 * p_bls12_381 < p_pallas * 2 ^ (64 * 3) := by decide
  have hp_88 : 2 ^ 52 * (p_bls12_381 - 1) + 2 ^ 53 * p_bls12_381 < p_pallas * 2 ^ (88 * 3) := by decide
  have hq_64 : 2 ^ 52 * (p_bls12_381 - 1) + 2 ^ 53 * p_bls12_381 < q_vesta * 2 ^ (64 * 3) := by decide
  have hq_88 : 2 ^ 52 * (p_bls12_381 - 1) + 2 ^ 53 * p_bls12_381 < q_vesta * 2 ^ (88 * 3) := by decide
  have hkp_abs : (k * (p_bls12_381 : Int)).natAbs <= (2 ^ 53 - 1) * p_bls12_381 := by
    rw [Int.natAbs_mul, Int.natAbs_natCast]
    exact Nat.mul_le_mul_right p_bls12_381 (by omega)
  have hsum_nat : (2 ^ 53 - 1) * p_bls12_381 + p_bls12_381 = 2 ^ 53 * p_bls12_381 := by
    have : (2 ^ 53 - 1 : Nat) + 1 = 2 ^ 53 := by decide
    calc
      (2 ^ 53 - 1) * p_bls12_381 + p_bls12_381
        = ((2 ^ 53 - 1) + 1) * p_bls12_381 := by grind
      _ = 2 ^ 53 * p_bls12_381 := by rw [this]
  have hdiff_abs : (lhs - k * (p_bls12_381 : Int) - r).natAbs <
      2 ^ 52 * (p_bls12_381 - 1) + 2 ^ 53 * p_bls12_381 := by
    omega
  have hp_odd := p_pallas_bit_bounds.2.2
  have hq_odd := q_vesta_bit_bounds.2.2
  exact ⟨fun hm1 hm2 => by
           have hz := crt_uniqueness_of_odd p_pallas 64 3 _ hp_odd (Nat.lt_trans hdiff_abs hp_64) hm1 hm2
           omega,
         fun hm1 hm2 => by
           have hz := crt_uniqueness_of_odd p_pallas 88 3 _ hp_odd (Nat.lt_trans hdiff_abs hp_88) hm1 hm2
           omega,
         fun hm1 hm2 => by
           have hz := crt_uniqueness_of_odd q_vesta 64 3 _ hq_odd (Nat.lt_trans hdiff_abs hq_64) hm1 hm2
           omega,
         fun hm1 hm2 => by
           have hz := crt_uniqueness_of_odd q_vesta 88 3 _ hq_odd (Nat.lt_trans hdiff_abs hq_88) hm1 hm2
           omega⟩

end ZkBilinearCerts
