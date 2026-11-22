# `ZkBilinearCerts` — Zero-`sorry` Core Lean 4 Formal Soundness & Bilinear Optimality Proofs (`v0.2`)

`ZkBilinearCerts` is a self-contained, zero-dependency **Core Lean 4** (`leanprover/lean4:v4.36.0`) formal verification suite certifying the extension-field bilinear schedules, 64-bit delayed Mersenne-31 arithmetic, 768-bit lazy Montgomery reduction & Karabina cyclotomic decompression (`BLS12-377`), unimodular pairing-tower isomorphisms (`BLS12-381` & `BLS12-377`), and non-native Chinese Remainder Theorem (CRT) quotient/carry soundness conditions across `zk-bilinear-opt`, its live upstream pull requests, and its ecosystem grant deliverables:

- **`starkware-libs/proving#9` & `#10`** — Unimodular `{0, +1, -1}` `Karatsuba-9` AIR multiplication (`0` non-unit `Const * Var` multiplications) and delayed-`u64` `stwo` `QM31` arithmetic.
- **`Plonky3/Plonky3#2600`** — Winograd / Alder–Strassen minimum-rank `Rank-7` `QM31` multiplication ($`v^4 - 4v^2 + 5`$), characteristic-free `6`-mul symmetric squaring, and 4-channel `u64` `dot4` delayed reduction.
- **`Consensys/gnark#1950`** — Zero-addition involutive coordinate-permutation ring isomorphism mapping `BLS12-377` `Fp12` identically onto $`\mathbb{Z}[W]/(W^{12} + 5)`$.
- **`Consensys/gnark#1951`** — Non-native emulated field CRT quotient bit-width soundness (`packLimbsWithWidth` / `crtRequiredLowCarries`) and BabyBear excess-bit wrap-around forgery prevention.
- **`aleo-labs-protocol/snarkVM#3908` & Aleo `snarkvm-bilinear-opt` Blueprint Grant** — 768-bit (`[u64; 12]`) lazy Montgomery bounds ($`136 q^2 < q \cdot 2^{384}`$), Karabina (2013) compressed cyclotomic squaring & universal 3-branch decompression, and 253-bit `Fr_BLS12_377` `CRT-30` carry non-wrap.
- **`ZcashCommunityGrants/zcashcommunitygrants#590` (`halo2-bilinear-opt`)** — Division-free unimodular `BLS12-381` `Fp6` ($`v^6 - 2v^3 + 2`$) & `Fp12` ($`w^{12} - 2w^6 + 2`$) ring isomorphisms, general odd-modulus CRT integer uniqueness, and concrete `Pasta` (`Pallas` / `Vesta`, `3x88b` & `4x64b`) and `BLS12-381` `CRT-30` (`5x88b` & `6x64b`) soundness proofs.

Because `ZkBilinearCerts` depends solely on Lean 4's standard kernel library (`"packages": []` in `lake-manifest.json`, zero `mathlib4` dependency), a clean scratch build (`lake clean && lake build`) completes in **`~7.2s–8.0s`** (`< 15s` across 16 Lake build jobs) with **`107` formal theorems**, **zero `sorry`**, **zero user-declared `axiom`s**, and **zero `native_decide` compiler-trust axioms**.

---

## Module Architecture & Formal Theorem Summary (`107` Theorems Total)

| Module | Theorems | Scope & Verified Properties |
|---|---|---|
| [`ZkBilinearCerts/Qm31Algebraic.lean`](ZkBilinearCerts/Qm31Algebraic.lean) | `21` | Canonical `QM31`, unimodular `{0, +1, -1}` `Karatsuba-9`, $`v^4 - 4v^2 + 5`$ isomorphism, `Rank-7` over $`\mathbb{Z}`$ & $`\bmod (2^{31}-1)`$, and `Rank-6` squaring |
| [`ZkBilinearCerts/M31Overflow.lean`](ZkBilinearCerts/M31Overflow.lean) | `16` | Two-step `(x &&& 0x7fffffff) + (x >>> 31)` bitwise fold canonicality ($`< 2^{31}-1`$), `dot4` & `stwo` `u64` non-overflow ($`< 2^{64}`$), and width-4 tightness |
| [`ZkBilinearCerts/CrtSoundness.lean`](ZkBilinearCerts/CrtSoundness.lean) | `9` | Constructive Extended Euclidean Bézout, BabyBear `b = 22` unmasked quotient forgery witnesses, and universal positive `quoBits` CRT soundness |
| [`ZkBilinearCerts/Bls12_377Soundness.lean`](ZkBilinearCerts/Bls12_377Soundness.lean) | `38` | Exact `q_bls12_377` / `r_bls12_377` bounds, 768-bit lazy Montgomery safety ($`136 q^2 < q \cdot 2^{384}`$), $`W^{12} + 5`$ involution isomorphism, Karabina squaring & 3-branch decompression, and Aleo 253-bit `Fr` `CRT-30` carry non-wrap |
| [`ZkBilinearCerts/PastaBls12_381Crt.lean`](ZkBilinearCerts/PastaBls12_381Crt.lean) | `23` | Exact `p_pallas` / `q_vesta` / `p_bls12_381` bounds, unimodular `BLS12-381` `Fp6` & `Fp12` trinomial isomorphisms, odd-modulus CRT uniqueness, and `Pasta` (`3x88b`, `4x64b`) + `BLS12-381` `CRT-30` (`5x88b`, `6x64b`) soundness |
| **Total (`100%` `#print axioms` Audited)** | **`107`** | **`22` zero-axiom constructive kernel terms + `85` standard `{propext, Classical.choice, Quot.sound}` terms (`0` `sorryAx`, `0` custom `axiom`s)** |

---

### 1. [`ZkBilinearCerts/Qm31Algebraic.lean`](ZkBilinearCerts/Qm31Algebraic.lean) — Universal `QM31` Ring & Modular Identities (`21` Theorems)

Formalizes canonical degree-4 extension multiplication in $`\mathbb{Z}[i][u] / (i^2 + 1, u^2 - (2 + i))`$ in flattened basis $`(1, i, u, iu)`$ (`qm31_schoolbook`) and proves universal coordinate-wise identities across all $`a_0, a_1, a_2, a_3, b_0, b_1, b_2, b_3 \in \mathbb{Z}`$:

| Theorem | Formal Statement Summary | Upstream Target |
|---|---|---|
| `qm31_schoolbook_i_sq`, `qm31_schoolbook_u_sq`, `qm31_schoolbook_comm`, `qm31_schoolbook_assoc` | Verifies $`i^2 = -1`$, $`u^2 = 2 + i`$, two-sided multiplicative identity, commutativity, and associativity of `qm31_schoolbook` over $`\mathbb{Z}`$. | Reference baseline |
| `qm31_karatsuba9_eq_schoolbook` (`+ c0..c3_eq`) | $`\forall a, b \in \mathbb{Z}^4`$, unimodular `{0, +1, -1}` `Karatsuba-9` (`9` variable multiplications, `0` scalar constant multiplications) equals `qm31_schoolbook(a, b)` on all 4 coordinates. | `starkware-libs/proving#9` |
| `qm31_quartic_isomorphism`, `from_to_simple_quartic`, `to_from_simple_quartic` | $`\forall a, b \in \mathbb{Z}^4`$, the unimodular basis transformation $`(a_0 - 2a_1) + (a_2 - 2a_3)v + a_1 v^2 + a_3 v^3`$ ($`\det = -1`$) is an exact two-sided ring isomorphism onto $`\mathbb{Z}[v]/(v^4 - 4v^2 + 5)`$. | `Plonky3#2600`, `qm31_rank7_cert.json` |
| `inv12_mod_m31_cert`, `inv24_mod_m31_cert`, `inv120_mod_m31_cert` | Kernel-checked modular inverse certificates modulo $`P = 2^{31} - 1`$: $`12 \cdot 894784853 \equiv 1`$, $`24 \cdot 1521134250 \equiv 1`$, and $`120 \cdot 304226850 \equiv 1 \pmod{2^{31}-1}`$. | `Plonky3#2600`, `proving#9`, BitVM2 |
| `qm31_rank7_scaled120_eq_schoolbook` | $`\forall a, b \in \mathbb{Z}^4`$, the 7-point Winograd evaluation schedule on $`\{-2, -1, 0, 1, 2, 3, \infty\}`$ with integer matrix $`W_z`$ equals `120 * qm31_schoolbook(a, b)`. | `qm31_rank7_cert.json`, `Plonky3#2600` |
| `qm31_rank7_mod_m31_eq_schoolbook`, `cancel_120_mod_m31` | $`\forall a, b \in \mathbb{Z}^4`$, modular `M31` execution (`% (2^31 - 1)` on the 7 products and `* 304226850 % (2^31 - 1)` reconstruction) equals `qm31_schoolbook(a, b) mod (2^31 - 1)`. | `targets/qm31_stwo/qm31_stwo.rs` |
| `qm31_square_rank6_eq_schoolbook` | $`\forall a \in \mathbb{Z}^4`$, characteristic-free `6`-multiplication symmetric squaring (`D = 1`) equals `qm31_schoolbook(a, a)`. | `Plonky3#2600` |

---

### 2. [`ZkBilinearCerts/M31Overflow.lean`](ZkBilinearCerts/M31Overflow.lean) — Delayed-`u64` Non-Overflow & Two-Step Mersenne-31 Fold (`16` Theorems)

Formalizes hardware `u64` accumulator bounds and bitwise Mersenne-31 reduction `(x & 0x7fffffff) + (x >> 31)` over `Nat`:

| Theorem | Formal Statement Summary | Upstream Target |
|---|---|---|
| `m31_fold_bitwise_eq_arith`, `m31_fold_mod_eq`, `m31_fold2_mod_eq` | $`\forall x \in \mathbb{N}`$, `(x &&& 0x7fffffff) + (x >>> 31) = x % 2^31 + x / 2^31`, preserving congruence modulo $`2^{31} - 1`$. | `Plonky3#2600`, `proving#9` |
| `m31_fold_step1_bound`, `m31_fold2_bound`, `m31_fold2_max_attained` | $`\forall x < 2^{64}`$, two bitwise folds bound the result to $`\le 2^{31} + 2 < 2(2^{31} - 1)`$ (attained sharply at $`x = 2^{64} - 1`$). | `Plonky3#2600`, `proving#9` |
| `m31_reduce64_eq_mod`, `m31_reduce64_canonical` | $`\forall x < 2^{64}`$, two folds plus a single conditional subtraction yields `x % (2^31 - 1)` strictly inside `[0, 2^31 - 2]`. | `Plonky3#2600` (`reduce_64`) |
| `m31_reduce64_branchless_sound_and_canonical` | $`\forall x < 2^{64}`$, `stwo`'s branchless `(((t + 1) >>> 31) + t) &&& 0x7fffffff` yields canonical `x % (2^31 - 1) < 2^31 - 1`. | `proving#9` (`stwo::reduce_u64`) |
| `qm31_dot4_canonical_lt_u64`, `qm31_dot4_redundant_lt_u64`, `five_unreduced_m31_products_gt_u64` | $`\forall a_i, b_j \le 2^{31} - 2`$ (and redundant $`\le 2^{31} - 1`$), all 4 `QM31` `dot4` `u64` accumulators satisfy $`< 2^{64}`$, while $`5(2^{31}-2)^2 > 2^{64}`$ proves width-4 hardware tightness. | `Plonky3#2600` (`qm31_mul_u64_dot4`) |
| `qm31_dot4_reduce64_eq_schoolbook` | $`\forall a_i, b_j \le 2^{31} - 2`$, reducing the 4 `dot4` `u64` channels via `m31_reduce64` equals canonical `qm31_schoolbook_mod_m31`. | `Plonky3#2600` |
| `stwo_outer_karatsuba_u64_lt_u64`, `qm31_rank7_u64_bounds` | Proves all `stwo` outer-Karatsuba delayed-`u64` channels $`< 2^{64}`$ and `QM31_Rank7` modular products $`< 2^{62}`$. | `proving#9`, `qm31_stwo.rs` |

---

### 3. [`ZkBilinearCerts/CrtSoundness.lean`](ZkBilinearCerts/CrtSoundness.lean) — Non-Native CRT Quotient-Bit Soundness (`9` Theorems)

Formalizes non-native field emulation modulo native prime $`F`$ and low-carry power-of-two modulus $`M = 2^{b \cdot k}`$ (`M_crt`):

| Theorem | Formal Statement Summary | Upstream Target |
|---|---|---|
| `babybear_b22_unmasked_forgery_cert` | Kernel-checked (`decide`) 2-limb forgery over BabyBear ($`F = 2013265921`$, $`b = 22`$, $`2^{44} \ge F - 1`$, $`p = 13194140767889`$): unmasked `22`-bit `q_witness` admits forged $`(639, 13193354832913)`$ passing mod-$`F`$, mod-$`2^{22}`$, and 2-limb carry ($`c_0 = -189`$) checks while $`a b - 639 p - r = -F \cdot 2^{22} \ne 0`$. | `Consensys/gnark#1951` |
| `babybear_single_limb_unmasked_forgery_cert` | Kernel-checked (`decide`) single-limb (`M_crt = 1`, $`p = 2^{22} - 3 = 4194301`$) wrap-around forgery $`(q, r) = (480, 1441)`$ with $`a b - 480 p - 1441 = -F`$. | `Consensys/gnark#1951` |
| `ext_gcd_nat_bezout`, `bezout_of_int_gcd_eq_one`, `coprime_mul_dvd_of_emod_zero`, `eq_zero_of_mul_bounded` | Constructive Extended Euclidean Bézout theorem, coprime CRT divisibility ($`F \mid d \land M \mid d \implies F M \mid d`$), and bounded-multiple zero lemma in pure Core Lean 4. | Core CRT engine |
| `crt_quotient_soundness`, `crt_quotient_unique_witness`, `babybear_b22_masked_quobits_sound` | Universal soundness & witness uniqueness: whenever $`\gcd(F, M) = 1`$, $`0 \le q < 2^{k}`$ (`quoBits`), and `max_diff < F * M_crt`, modular + CRT equations force `a * b - q_witness * p = r` (instantiated on BabyBear `quoBits = 1`). | `Consensys/gnark#1951` |

---

### 4. [`ZkBilinearCerts/Bls12_377Soundness.lean`](ZkBilinearCerts/Bls12_377Soundness.lean) — Aleo `BLS12-377` 768-Bit Lazy Montgomery, $`W^{12} + 5`$ Permutation, Karabina Cyclotomic & `Fr` `CRT-30` (`38` Theorems)

De-risks [`aleo-labs-protocol/snarkVM#3908`](https://github.com/aleo-labs-protocol/snarkVM/pull/3908), [`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950), and the Aleo `snarkvm-bilinear-opt` Blueprint Grant:

| Theorem | Formal Statement Summary | Upstream Target |
|---|---|---|
| `q_bls12_377_bit_bounds`, `q_bls12_377_limbs_and_dec_eq`, `r_bls12_377_bit_bounds`, `r_bls12_377_limbs_and_hex_eq` | Certifies `q_bls12_377` (`[u64; 6]` limbs, $`2^{376} < q_{\mathrm{BLS12-377}} < 2^{377}`$, odd) and `r_bls12_377` (`[u64; 4]` limbs, $`2^{252} < r_{\mathrm{BLS12-377}} < 2^{253}`$, odd). | `snarkVM` `bls12_377/{fq,fr}.rs` |
| `bls12_377_mont_headroom`, `bls12_377_peak136_lt_mont_bound` | Certifies $`152 q < 2^{384} < 153 q`$ and $`136 q^2 < q \cdot 2^{384} < 2^{768}`$ for $`q = q_{\mathrm{BLS12-377}}`$. | `snarkVM#3908` (`fp_384.rs`) |
| `fq2_unred_mul_sound_and_bounded`, `fq6_unred_mul_bounded`, `fq6_unred_mul_by_01_bounded`, `fq12_lazy_mul_by_034_bounded`, `fq12_lazy_mul_by_014_bounded`, `fq12_lazy_mul_bounded` | Universal `0`-borrow unsigned non-underflow and tight upper bounds across `Fq2::mul` ($`< 6q^2`$), `Fq6::mul` ($`< 36q^2`$), `Fq6::mul_by_01` ($`< 26q^2`$), `mul_by_034` ($`< 58q^2`$), `mul_by_014` ($`< 62q^2`$), and `Fq12::mul` ($`< 136q^2`$). | `snarkVM#3908` (`fq2.rs`, `fq6.rs`, `fq12.rs`) |
| `bls12_377_lazy_mont_all_schedules_canonical`, `bls12_377_end_to_end_canonical_lt_mont_bound` | End-to-end proof from raw canonical inputs $`a_i, b_j < q_{\mathrm{BLS12-377}}`$ that all lazy tower accumulators stay $`< q \cdot 2^{384}`$ and single-subtract Montgomery reduction yields a canonical $`< q`$ output. | `snarkVM#3908` |
| `perm_bls12_377_fp12_involutive`, `perm_bls12_377_fp12_bijective`, `bls12_377_w12_plus_5_isomorphism`, `bls12_377_w12_plus_5_to_monomial_hom` | Proves `[0, 6, 2, 8, 4, 10, 1, 7, 3, 9, 5, 11]` is an order-2 bijection on `Fin 12` mapping `BLS12-377` tower multiplication ($`u^2 + 5 = 0, v^3 = u, w^2 = v`$) identically onto $`\mathbb{Z}[W]/(W^{12} + 5)`$ with zero additions. | `Consensys/gnark#1950` (`e12_sz.go`) |
| `cyc_fp12_mul_adj_universal`, `cyclotomic_adj_eq_conj`, `granger_scott_square_eq_fp12_square`, `karabina_square_eq_fp12_square` | Formalizes `IsCyclotomicPhi6 u g` ($`g \cdot \overline{g} = 1 \land N_{\mathbb{F}_{p^{12}}/\mathbb{F}_{p^4}}(g) = 1`$), proves `adj(g) = conj(g)` from cubic associativity, and proves Karabina's 2-`Fp4`-square formula matches full `Fp12` squaring. | `snarkVM#3908` (`fp12_2over3over2.rs`) |
| `karabina_decompression_universal` | Over $`\mathbb{Z}`$ for arbitrary $`u`$ ($`w^6 = u`$), proves Branch 1 ($`4 z_2 z_1 = u z_5^2 + 3 z_4^2 - 2 z_3`$), Branch 2 ($`z_2 = 0 \land u \ne 0 \implies z_3 z_1 = 2 z_4 z_5`$), universal $`z_0 = u(2 z_1^2 + z_2 z_5 - 3 z_3 z_4) + 1`$, and degenerate Branch 3 ($`z_2 = z_3 = 0 \land u \ne 0 \implies g = 1`$). | `snarkVM#3908`, `arkworks` |
| `aleo_fr_crt30_carry_nonwrap_vs_rank23` | Proves $`2^{196} \cdot 2^{45} = 2^{241} < r_{\mathrm{BLS12-377}}`$ (`45 <= 56` carry slack, `0` pre-reductions), whereas naive `Rank-23` overflows $`2^{196} \cdot 2^{77} = 2^{273} > r_{\mathrm{BLS12-377}}`$. | Aleo `snarkvm-bilinear-opt` |

---

### 5. [`ZkBilinearCerts/PastaBls12_381Crt.lean`](ZkBilinearCerts/PastaBls12_381Crt.lean) — Zcash `Pasta` & `BLS12-381` Unimodular Isomorphisms & CRT Uniqueness (`23` Theorems)

De-risks [`ZcashCommunityGrants/zcashcommunitygrants#590`](https://github.com/ZcashCommunityGrants/zcashcommunitygrants/issues/590) (`halo2-bilinear-opt`) and `rust_crates/src/halo2_gadgets.rs`:

| Theorem | Formal Statement Summary | Upstream Target |
|---|---|---|
| `p_pallas_bit_bounds`, `q_vesta_bit_bounds`, `p_bls12_381_bit_bounds` (`+ *_limbs_and_dec_eq`) | Certifies exact `[u64; 4]` / `[u64; 6]` limbs, oddness, $`2^{254} < p_{\mathrm{Pallas}} < 2^{255}`$, $`2^{254} < q_{\mathrm{Vesta}} < 2^{255}`$, and $`2^{380} < p_{\mathrm{BLS12-381}} < 2^{381}`$. | `halo2_gadgets.rs`, `pasta_curves`, `bls12_381` |
| `fp6_381_to_from_simple`, `fp6_381_from_to_simple`, `bls12_381_fp6_trinomial_isomorphism`, `bls12_381_fp6_to_simple_hom` | Proves two-sided bijectivity and universal ring isomorphism over $`\mathbb{Z}`$ between `BLS12-381` `Fp6` ($`v^3 - (u + 1)`$) and $`\mathbb{Z}[v]/(v^6 - 2v^3 + 2)`$ (`Rank-11`). | `halo2_gadgets.rs` (`Fp6::mul_rank11`), `gnark#1951` |
| `fp12_381_to_from_simple`, `fp12_381_from_to_simple`, `bls12_381_fp12_trinomial_isomorphism`, `bls12_381_fp12_to_simple_hom` | Proves two-sided bijectivity and universal ring isomorphism over $`\mathbb{Z}`$ between `BLS12-381` `Fp12` ($`w^2 - v`$) and $`\mathbb{Z}[w]/(w^{12} - 2w^6 + 2)`$ (`Rank-23` & `014` `Rank-18/19/21`). | `halo2_gadgets.rs` (`Fp12::mul_rank23`), `gnark#1951` |
| `odd_bezout_two_pow`, `odd_nat_coprime_two_pow`, `crt_uniqueness_of_coprime`, `crt_uniqueness_of_odd` | Constructive Bézout proof that every odd $`q_{\mathrm{native}}`$ satisfies $`\gcd(q_{\mathrm{native}}, 2^{t \cdot n_{\mathrm{low}}}) = 1`$, forcing $`\mathrm{diff} = 0`$ whenever $`\vert\mathrm{diff}\vert < q_{\mathrm{native}} \cdot 2^{t \cdot n_{\mathrm{low}}}`$ and both modular equations hold. | Core non-native CRT engine |
| `pasta_linear_crt_3x88_and_4x64_sound`, `pasta_wrong_field_mul_sound` | Instantiates exact `Pallas`-in-`Vesta` and `Vesta`-in-`Pallas` soundness for single-width/linear CRT (`3x88b` $`n_{\mathrm{low}} = 2`$, `4x64b` $`n_{\mathrm{low}} = 3`$) and full quadratic wrong-field multiplication (`quoBits = 255`, `3x88b` $`n_{\mathrm{low}} = 3`$, `4x64b` $`n_{\mathrm{low}} = 4`$). | `Zcash #590` (`estimate_pasta_wrong_field_mul`) |
| `bls12_381_crt30_carry_slack_sound`, `bls12_381_crt30_mul_sound`, `bls12_381_crt30_out_reconstruction_sound` | Certifies `CRT-30` carry non-overflow (`45 <= 72` on `5x88b`, `45 <= 56` on `6x64b` vs `Rank-23` `77`-bit overflow) and exact CRT integer uniqueness for base multiplications (`n_low = 7` on `5x88b`, `n_low = 9` on `6x64b`) and `52`-bit `W_z` output reconstructions (`n_low = 3`). | `Zcash #590` (`estimate_bls12_381_fp12_mul`) |

---

### 6. [`ZkBilinearCerts/VerifyAxioms.lean`](ZkBilinearCerts/VerifyAxioms.lean) — `100%` Kernel Axiom Audit (`107 / 107` Theorems)

Executes `#print axioms` during `lake build` across all **107** formal theorems in the repository (`1-to-1` coverage of every `theorem` declaration across all 5 modules), confirming every proof depends exclusively on standard Lean 4 kernel axioms (`propext`, `Classical.choice`, `Quot.sound`) or zero axioms (`22` constructive kernel terms) — zero `sorryAx`, zero `Lean.ofReduceBool` / `Lean.trustCompiler`, and zero custom `axiom` declarations.

---

## Reproducing Locally (`~7.2s–8.0s` Clean Scratch Build)

Install [`elan`](https://github.com/leanprover/elan) (which automatically selects `leanprover/lean4:v4.36.0` from `lean-toolchain`) and run:

```powershell
cd lean4_certs
lake clean
Measure-Command { lake build }
```
