/-
  ZkBilinearCerts.CrtSoundness
  Zero-`sorry`, zero-`axiom` Lean 4 formalization of the non-native field CRT
  quotient-bit soundness theorem and unmasked-limb forgery counterexamples from
  `Consensys/gnark#1951`.

  Covers:
  1. Constructive Bézout identity and coprime CRT divisibility over `Int` (pure Core Lean 4).
  2. Machine-checked concrete forgery witnesses (`decide`) over BabyBear (`F = 2013265921`,
     limb width `b = 22`, `2 * 22 >= 31`, `2^44 >= F - 1`, `p = 13194140767889`):
     - `babybear_b22_unmasked_forgery_cert`: when `q_witness` allows full limb width `b = 22`
       (`0 <= q_witness < 2^22`) instead of `quoBits = 1`, two distinct canonical witness
       pairs `(0, 0)` and `(639, 13193354832913)` both satisfy the mod-`F`, mod-`2^22` CRT,
       and 2-limb carry equations, while `(639, 13193354832913)` violates integer equality
       `a * b - q_witness * p = r` (`a * b - 639 * p - r = -F * 2^22 != 0`).
     - `babybear_single_limb_unmasked_forgery_cert`: single-limb (`nbLow = 0`, `M_crt = 1`,
       `p = 2^22 - 3 = 4194301`) excess-bit quotient wrap-around forgery (`q_forged = 480`,
       `r_forged = 1441`) matching `singleLimbWideBabyBearParams` in `Consensys/gnark#1951`.
  3. Universal positive integer soundness theorem (`crt_quotient_soundness`) and witness
     uniqueness (`crt_quotient_unique_witness`) whenever `0 <= q_witness < 2^quoBits`,
     `Int.gcd F M_crt = 1`, and `max_diff < F * M_crt`, plus instantiation on BabyBear.
-/

namespace ZkBilinearCerts

/-! ### 1. Non-Native CRT Constraint Predicate & Integer Target -/

/-- The verifier's modular + low-limb CRT equations:
    `a * b - q_witness * p - r ≡ 0 (mod F)` (native SNARK/STARK field check) and
    `a * b - q_witness * p - r ≡ 0 (mod M_crt)` (`M_crt = 2^(b * nbLow)` low-carry check). -/
def crt_mod_eq (F M_crt a b p q_witness r : Int) : Prop :=
  (a * b - q_witness * p - r) % F = 0 ∧
  (a * b - q_witness * p - r) % M_crt = 0

instance (F M_crt a b p q_witness r : Int) :
    Decidable (crt_mod_eq F M_crt a b p q_witness r) := by
  unfold crt_mod_eq; infer_instance

/-- Exact non-native integer multiplication relation `a * b - q_witness * p = r`. -/
def crt_int_eq (a b p q_witness r : Int) : Prop :=
  a * b - q_witness * p = r

instance (a b p q_witness r : Int) :
    Decidable (crt_int_eq a b p q_witness r) := by
  unfold crt_int_eq; infer_instance

/-! ### 2. Concrete BabyBear (`F = 2013265921`, `b = 22`) Forgery Witnesses (`gnark#1951`) -/

/-- BabyBear native prime `F = 15 * 2^27 + 1 = 2013265921` (`31` bits). -/
def BabyBearF : Int := 2013265921

/-- Limb bit-width `b = 22` from `wideBabyBearParams` in `Consensys/gnark#1951`. -/
def WideLimbBits : Nat := 22

/-- CRT power-of-two modulus `M_crt = 2^22 = 4194304` (`nbLow = 1` low carry limb). -/
def WideM_crt : Int := (2 : Int) ^ WideLimbBits

/-- 2-limb emulated prime `p = 13194140767889 = 1234577 + 3145728 * 2^22` (`gnark#1951`). -/
def WideEmulatedP : Int := 13194140767889
def WideEmulatedP0 : Int := 1234577
def WideEmulatedP1 : Int := 3145728

/-- Machine-checked unmasked quotient forgery (`decide`):
    For inputs `(a = 2, b = 0)` in `0 <= a <= 2, 0 <= b < p` (where the honest quotient
    requires only `quoBits = 1`, `0 <= q_witness < 2^1`), allowing unmasked `b = 22`-bit
    quotient limbs (`0 <= q_witness < 2^22`, where `2^(2*22) >= F - 1`) admits TWO distinct
    witness pairs `w_honest = (0, 0)` and `w_forged = (639, 13193354832913)`:
    - both satisfy `0 <= q_i < 2^22` and canonical `0 <= r_i < p` (with valid 22-bit limbs),
    - both satisfy `crt_mod_eq` (`mod F` and `mod 2^22`) AND the 2-limb carry equations
      with small carry `c0 = -189`,
    - `w_honest` satisfies `crt_int_eq`, while `w_forged` VIOLATES `a * b - q_witness * p = r`! -/
theorem babybear_b22_unmasked_forgery_cert :
    let a : Int := 2
    let b : Int := 0
    let q_honest : Int := 0
    let r_honest : Int := 0
    let q_forged : Int := 639
    let r_forged : Int := 13193354832913
    let r_forged_0 : Int := 3828753
    let r_forged_1 : Int := 3145540
    let carry0 : Int := -189
    -- 1. Parameter & excess-width condition (`2^44 >= F - 1`, decomposition of `p` and `r_forged`):
    (2 : Int) ^ (2 * WideLimbBits) >= BabyBearF - 1 ∧
    WideEmulatedP = WideEmulatedP0 + WideEmulatedP1 * WideM_crt ∧
    r_forged = r_forged_0 + r_forged_1 * WideM_crt ∧
    0 <= r_forged_0 ∧ r_forged_0 < WideM_crt ∧
    0 <= r_forged_1 ∧ r_forged_1 < WideM_crt ∧
    -- 2. Distinctness and unmasked `b = 22` witness bounds:
    (q_honest, r_honest) ≠ (q_forged, r_forged) ∧
    0 <= q_honest ∧ q_honest < (2 : Int) ^ WideLimbBits ∧
    0 <= r_honest ∧ r_honest < WideEmulatedP ∧
    0 <= q_forged ∧ q_forged < (2 : Int) ^ WideLimbBits ∧
    0 <= r_forged ∧ r_forged < WideEmulatedP ∧
    -- 3. Both witness pairs satisfy the global mod-`F` + CRT equations (and 2-limb carry check):
    crt_mod_eq BabyBearF WideM_crt a b WideEmulatedP q_honest r_honest ∧
    crt_mod_eq BabyBearF WideM_crt a b WideEmulatedP q_forged r_forged ∧
    (0 - q_forged * WideEmulatedP0 - r_forged_0 = carry0 * WideM_crt) ∧
    ((0 - q_forged * WideEmulatedP1 - r_forged_1 + carry0) % BabyBearF = 0) ∧
    -- 4. Honest witness satisfies integer equality, while forged witness VIOLATES it:
    crt_int_eq a b WideEmulatedP q_honest r_honest ∧
    ¬ crt_int_eq a b WideEmulatedP q_forged r_forged := by
  decide

/-- Machine-checked single-limb (`nbLow = 0`, `M_crt = 1`) BabyBear `b = 22` forgery (`decide`)
    corresponding to `singleLimbWideBabyBearParams` (`p = 2^22 - 3 = 4194301`) in
    `Consensys/gnark#1951`: for `(a = 1, b = 0)` (`quoBits = 0`), unmasked `0 <= q_witness < 2^22`
    admits `(q_forged = 480, r_forged = 1441)` with `a * b - 480 * 4194301 - 1441 = -BabyBearF`! -/
theorem babybear_single_limb_unmasked_forgery_cert :
    let p1 : Int := 4194301
    let a : Int := 1
    let b : Int := 0
    let q_honest : Int := 0
    let r_honest : Int := 0
    let q_forged : Int := 480
    let r_forged : Int := 1441
    (q_honest, r_honest) ≠ (q_forged, r_forged) ∧
    0 <= q_forged ∧ q_forged < (2 : Int) ^ WideLimbBits ∧
    0 <= r_forged ∧ r_forged < p1 ∧
    crt_mod_eq BabyBearF 1 a b p1 q_honest r_honest ∧
    crt_mod_eq BabyBearF 1 a b p1 q_forged r_forged ∧
    crt_int_eq a b p1 q_honest r_honest ∧
    ¬ crt_int_eq a b p1 q_forged r_forged := by
  decide

/-! ### 3. Constructive Bézout & Coprime CRT Divisibility over `Int` -/

/-- Extended Euclidean algorithm on `Nat` computing Bézout coefficients `(u, v) : Int × Int`
    such that `u * a + v * b = Nat.gcd a b`. -/
def ext_gcd_nat (a b : Nat) : Int × Int :=
  if h : a = 0 then
    (0, 1)
  else
    have _ : b % a < a := Nat.mod_lt b (Nat.pos_of_ne_zero h)
    let r := ext_gcd_nat (b % a) a
    (r.2 - r.1 * ((b / a : Nat) : Int), r.1)
termination_by a

/-- Constructive Bézout identity for `Nat.gcd`: `u * a + v * b = Nat.gcd a b`. -/
theorem ext_gcd_nat_bezout (a b : Nat) :
    (ext_gcd_nat a b).1 * (a : Int) + (ext_gcd_nat a b).2 * (b : Int) =
    (Nat.gcd a b : Int) := by
  induction a using Nat.strongRecOn generalizing b with
  | ind a ih =>
    rw [ext_gcd_nat]
    split
    · next h =>
      subst h
      simp [Nat.gcd_zero_left]
    · next h =>
      dsimp only
      have hlt : b % a < a := Nat.mod_lt b (Nat.pos_of_ne_zero h)
      have hrec := ih (b % a) hlt a
      have hgcd : Nat.gcd a b = Nat.gcd (b % a) a := Nat.gcd_rec a b
      have hdiv : (b : Int) = (a : Int) * ((b / a : Nat) : Int) + ((b % a : Nat) : Int) := by
        have := Nat.div_add_mod b a
        omega
      rw [hgcd, ← hrec, hdiv]
      grind

/-- Constructive Bézout identity for positive coprime `Int` moduli `F, M_crt > 0`. -/
theorem bezout_of_int_gcd_eq_one (F M_crt : Int)
    (hF : F >= 0) (hM : M_crt >= 0) (hcop : Int.gcd F M_crt = 1) :
    ∃ u v : Int, u * F + v * M_crt = 1 := by
  refine ⟨(ext_gcd_nat F.natAbs M_crt.natAbs).1, (ext_gcd_nat F.natAbs M_crt.natAbs).2, ?_⟩
  have hbez2 := ext_gcd_nat_bezout F.natAbs M_crt.natAbs
  have hFa : (F.natAbs : Int) = F := Int.natAbs_of_nonneg hF
  have hMa : (M_crt.natAbs : Int) = M_crt := Int.natAbs_of_nonneg hM
  have hgcd : (Nat.gcd F.natAbs M_crt.natAbs : Int) = 1 := by
    unfold Int.gcd at hcop
    omega
  rw [hFa, hMa, hgcd] at hbez2
  exact hbez2

/-- Chinese Remainder Divisibility Lemma: if `F, M_crt > 0` with `Int.gcd F M_crt = 1`,
    and `d % F = 0` and `d % M_crt = 0`, then `d` is an integer multiple of `F * M_crt`. -/
theorem coprime_mul_dvd_of_emod_zero (F M_crt d : Int)
    (hF : F > 0) (hM : M_crt > 0) (hcop : Int.gcd F M_crt = 1)
    (hdF : d % F = 0) (hdM : d % M_crt = 0) :
    ∃ m : Int, d = m * (F * M_crt) := by
  obtain ⟨u, v, huv⟩ := bezout_of_int_gcd_eq_one F M_crt (by omega) (by omega) hcop
  have hqF : d = F * (d / F) := by
    have := Int.emod_def d F
    omega
  have hqM : d = M_crt * (d / M_crt) := by
    have := Int.emod_def d M_crt
    omega
  refine ⟨u * (d / M_crt) + v * (d / F), ?_⟩
  calc
    d = d * 1 := (Int.mul_one d).symm
    _ = d * (u * F + v * M_crt) := by rw [huv]
    _ = d * (u * F) + d * (v * M_crt) := by grind
    _ = (M_crt * (d / M_crt)) * (u * F) + (F * (d / F)) * (v * M_crt) := by
          conv => lhs; arg 1; rw [hqM]
          conv => lhs; arg 2; rw [hqF]
    _ = (u * (d / M_crt) + v * (d / F)) * (F * M_crt) := by grind

/-- Bounded Multiple Zero Lemma: the only multiple `m * N` strictly inside `(-N, N)` is `0`. -/
theorem eq_zero_of_mul_bounded (N d m : Int)
    (hN : N > 0) (hd : d = m * N) (hlo : -N < d) (hhi : d < N) :
    d = 0 := by
  by_cases hm_pos : m >= 1
  · have hge : m * N >= 1 * N := Int.mul_le_mul_of_nonneg_right hm_pos (by omega)
    omega
  · by_cases hm_neg : m <= -1
    · have hpos_negm : -m >= 1 := by omega
      have hge : (-m) * N >= 1 * N := Int.mul_le_mul_of_nonneg_right hpos_negm (by omega)
      have hneg_mul : (-m) * N = -(m * N) := by grind
      omega
    · have hm0 : m = 0 := by omega
      rw [hd, hm0]; simp

/-! ### 4. Universal Positive Non-Native CRT Quotient-Bit Soundness Theorem -/

/-- **Positive Non-Native CRT Quotient-Bit Soundness Theorem (`Consensys/gnark#1951`)**:
    For any odd/coprime moduli `(F, M_crt)` with `Int.gcd F M_crt = 1`, when the witness
    quotient is range-constrained to `0 <= q_witness < 2^quoBits` and the maximum
    positive/negative discrepancy `max_diff` satisfies `max_diff < F * M_crt`,
    any witness satisfying `crt_mod_eq` MUST satisfy exact integer equality
    `a * b - q_witness * p = r`! -/
theorem crt_quotient_soundness
    (F M_crt : Int) (quoBits : Nat) (a b p q_witness r max_diff : Int)
    (hF : F > 0) (hM : M_crt > 0) (hcop : Int.gcd F M_crt = 1)
    (ha : 0 <= a) (hb : 0 <= b) (hab_max : a * b <= max_diff)
    (hp : 0 <= p) (hr : 0 <= r)
    (hq_lo : 0 <= q_witness) (hq_hi : q_witness < (2 : Int) ^ quoBits)
    (hkpr_max : ((2 : Int) ^ quoBits - 1) * p + r <= max_diff)
    (hbound : max_diff < F * M_crt)
    (hmod : crt_mod_eq F M_crt a b p q_witness r) :
    crt_int_eq a b p q_witness r := by
  unfold crt_mod_eq at hmod
  unfold crt_int_eq
  obtain ⟨hdF, hdM⟩ := hmod
  have hFM_pos : F * M_crt > 0 := Int.mul_pos hF hM
  obtain ⟨m, hm⟩ :=
    coprime_mul_dvd_of_emod_zero F M_crt (a * b - q_witness * p - r) hF hM hcop hdF hdM
  have hab_nn : 0 <= a * b := Int.mul_nonneg ha hb
  have hqp_nn : 0 <= q_witness * p := Int.mul_nonneg hq_lo hp
  have hq_le : q_witness <= (2 : Int) ^ quoBits - 1 := by omega
  have hqp_max : q_witness * p <= ((2 : Int) ^ quoBits - 1) * p :=
    Int.mul_le_mul_of_nonneg_right hq_le hp
  have hd_hi : a * b - q_witness * p - r < F * M_crt := by omega
  have hd_lo : -(F * M_crt) < a * b - q_witness * p - r := by omega
  have hd_zero : a * b - q_witness * p - r = 0 :=
    eq_zero_of_mul_bounded (F * M_crt) (a * b - q_witness * p - r) m hFM_pos hm hd_lo hd_hi
  omega

/-- **Canonical Witness Uniqueness Corollary**: under the soundness hypotheses with
    canonical remainders `0 <= r1, r2 < p` (`p > 0`), two valid witness pairs MUST be
    identical `(q1, r1) = (q2, r2)` — excess-bit wrap-around forgery is impossible. -/
theorem crt_quotient_unique_witness
    (F M_crt : Int) (quoBits : Nat) (a b p q1 r1 q2 r2 max_diff : Int)
    (hF : F > 0) (hM : M_crt > 0) (hcop : Int.gcd F M_crt = 1)
    (ha : 0 <= a) (hb : 0 <= b) (hab_max : a * b <= max_diff)
    (hp : p > 0)
    (hr1_lo : 0 <= r1) (hr1_hi : r1 < p)
    (hr2_lo : 0 <= r2) (hr2_hi : r2 < p)
    (hq1_lo : 0 <= q1) (hq1_hi : q1 < (2 : Int) ^ quoBits)
    (hq2_lo : 0 <= q2) (hq2_hi : q2 < (2 : Int) ^ quoBits)
    (hkpr1 : ((2 : Int) ^ quoBits - 1) * p + r1 <= max_diff)
    (hkpr2 : ((2 : Int) ^ quoBits - 1) * p + r2 <= max_diff)
    (hbound : max_diff < F * M_crt)
    (hmod1 : crt_mod_eq F M_crt a b p q1 r1)
    (hmod2 : crt_mod_eq F M_crt a b p q2 r2) :
    (q1, r1) = (q2, r2) := by
  have heq1 := crt_quotient_soundness F M_crt quoBits a b p q1 r1 max_diff
    hF hM hcop ha hb hab_max (by omega) hr1_lo hq1_lo hq1_hi hkpr1 hbound hmod1
  have heq2 := crt_quotient_soundness F M_crt quoBits a b p q2 r2 max_diff
    hF hM hcop ha hb hab_max (by omega) hr2_lo hq2_lo hq2_hi hkpr2 hbound hmod2
  unfold crt_int_eq at heq1 heq2
  have hdiff : r2 - r1 = (q1 - q2) * p := by grind
  have hr_zero : r2 - r1 = 0 :=
    eq_zero_of_mul_bounded p (r2 - r1) (q1 - q2) hp hdiff (by omega) (by omega)
  have hqp_zero : (q1 - q2) * p = 0 := by omega
  have hq_zero : q1 - q2 = 0 := by
    cases Int.mul_eq_zero.mp hqp_zero with
    | inl h => exact h
    | inr h => omega
  have hq_eq : q1 = q2 := by omega
  have hr_eq : r1 = r2 := by omega
  rw [hq_eq, hr_eq]

/-- **BabyBear `b = 22` Masked-`quoBits` Soundness Certificate**:
    On the exact `wideBabyBearParams` (`F = 2013265921`, `M_crt = 2^22`, `p = 13194140767889`)
    where unmasked `b = 22` admitted the `q = 639` forgery above, enforcing `quoBits = 1`
    (`0 <= q_witness < 2`) satisfies `max_diff = 2 * p - 1 < F * M_crt` and guarantees
    `a * b - q_witness * p = r` for ALL valid inputs `0 <= a <= 2`, `0 <= b < p`, `0 <= r < p`! -/
theorem babybear_b22_masked_quobits_sound
    (a b q_witness r : Int)
    (ha_lo : 0 <= a) (ha_hi : a <= 2)
    (hb_lo : 0 <= b) (hb_hi : b < WideEmulatedP)
    (hr_lo : 0 <= r) (hr_hi : r < WideEmulatedP)
    (hq_lo : 0 <= q_witness) (hq_hi : q_witness < (2 : Int) ^ 1)
    (hmod : crt_mod_eq BabyBearF WideM_crt a b WideEmulatedP q_witness r) :
    crt_int_eq a b WideEmulatedP q_witness r := by
  have hab_max : a * b <= 2 * WideEmulatedP - 1 := by
    have hmul : a * b <= 2 * (WideEmulatedP - 1) :=
      Int.mul_le_mul ha_hi (by omega) hb_lo (by omega)
    unfold WideEmulatedP at *; omega
  exact crt_quotient_soundness
    BabyBearF WideM_crt 1 a b WideEmulatedP q_witness r (2 * WideEmulatedP - 1)
    (by decide) (by decide) (by decide)
    ha_lo hb_lo hab_max
    (by decide) hr_lo
    hq_lo hq_hi
    (by unfold WideEmulatedP at *; omega)
    (by decide)
    hmod

end ZkBilinearCerts
