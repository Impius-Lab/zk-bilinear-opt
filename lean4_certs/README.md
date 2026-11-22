# `ZkBilinearCerts` — Zero-`sorry` Lean 4 Formal Soundness & Bilinear Optimality Proofs

`ZkBilinearCerts` is a self-contained, zero-dependency **Core Lean 4** (`leanprover/lean4:v4.36.0`) formal verification suite certifying the extension-field bilinear schedules, 64-bit delayed Mersenne-31 arithmetic, and non-native Chinese Remainder Theorem (CRT) quotient-bit soundness conditions implemented across `zk-bilinear-opt` and its upstream pull requests:

- **`starkware-libs/proving#9`** — Unimodular `{0, +1, -1}` `Karatsuba-9` AIR multiplication (`0` non-unit `Const * Var` multiplications) and delayed-`u64` `stwo` `QM31` arithmetic.
- **`Plonky3/Plonky3#2600`** — Winograd / Alder-Strassen minimum-rank `Rank-7` `QM31` multiplication (`v^4 - 4v^2 + 5`), characteristic-free `6`-mul symmetric squaring, and 4-channel `u64` `dot4` delayed reduction.
- **`Consensys/gnark#1951`** — Non-native emulated field CRT quotient bit-width soundness (`packLimbsWithWidth` / `crtRequiredLowCarries`) and BabyBear excess-bit wrap-around forgery prevention.

Because `ZkBilinearCerts` depends solely on Lean 4's standard kernel library (`"packages": []` in `lake-manifest.json`, zero `mathlib4` dependency), a clean scratch build completes in **under 6 seconds** with **zero `sorry`**, **zero user-declared `axiom`s**, and **zero `native_decide` compiler-trust axioms**.

---

## Module Architecture & Formal Theorem Summary

### 1. [`ZkBilinearCerts/Qm31Algebraic.lean`](ZkBilinearCerts/Qm31Algebraic.lean) — Universal `QM31` Ring & Modular Identities

Formalizes canonical degree-4 extension multiplication in $`\mathbb{Z}[i][u] / (i^2 + 1,\, u^2 - (2 + i))`$ in flattened basis $`(1, i, u, iu)`$ (`qm31_schoolbook`) and proves universal coordinate-wise identities across all $`a_0, a_1, a_2, a_3, b_0, b_1, b_2, b_3 \in \mathbb{Z}`$:

| Theorem | Formal Statement Summary | Upstream Target |
|---|---|---|
| `qm31_schoolbook_i_sq`, `qm31_schoolbook_u_sq`, `qm31_schoolbook_comm`, `qm31_schoolbook_assoc` | Verifies $`i^2 = -1`$, $`u^2 = 2 + i`$, commutativity, and associativity of `qm31_schoolbook` over $`\mathbb{Z}`$. | Reference baseline |
| `qm31_karatsuba9_eq_schoolbook` | $`\forall\, a, b \in \mathbb{Z}^4`$, unimodular `{0, +1, -1}` `Karatsuba-9` (`9` variable multiplications, `0` scalar constant multiplications) equals `qm31_schoolbook(a, b)` on all 4 coordinates. | `starkware-libs/proving#9` |
| `qm31_quartic_isomorphism` | $`\forall\, a, b \in \mathbb{Z}^4`$, the unimodular basis transformation $`(a_0 - 2a_1) + (a_2 - 2a_3)v + a_1 v^2 + a_3 v^3`$ (`det = -1`) is an exact ring isomorphism onto $`\mathbb{Z}[v]/(v^4 - 4v^2 + 5)`$. | `Plonky3#2600`, `qm31_rank7_cert.json` |
| `inv12_mod_m31_cert`, `inv24_mod_m31_cert`, `inv120_mod_m31_cert` | Kernel-checked modular inverse certificates modulo $`P = 2^{31} - 1`$: $`12 \cdot 894784853 \equiv 1`$, $`24 \cdot 1521134250 \equiv 1`$, and $`120 \cdot 304226850 \equiv 1 \pmod{2^{31}-1}`$. | `Plonky3#2600`, `proving#9`, BitVM2 |
| `qm31_rank7_scaled120_eq_schoolbook` | $`\forall\, a, b \in \mathbb{Z}^4`$, the 7-point Winograd evaluation schedule on $`\{-2, -1, 0, 1, 2, 3, \infty\}`$ with integer matrix $`W_z`$ equals `120 * qm31_schoolbook(a, b)`. | `qm31_rank7_cert.json`, `Plonky3#2600` |
| `qm31_rank7_mod_m31_eq_schoolbook` | $`\forall\, a, b \in \mathbb{Z}^4`$, modular `M31` execution (`% (2^31 - 1)` on the 7 products and `* 304226850 % (2^31 - 1)` reconstruction) equals `qm31_schoolbook(a, b) mod (2^31 - 1)`. | `targets/qm31_stwo/qm31_stwo.rs` |
| `qm31_square_rank6_eq_schoolbook` | $`\forall\, a \in \mathbb{Z}^4`$, characteristic-free `6`-multiplication symmetric squaring (`D = 1`) equals `qm31_schoolbook(a, a)`. | `Plonky3#2600` |

---

### 2. [`ZkBilinearCerts/M31Overflow.lean`](ZkBilinearCerts/M31Overflow.lean) — Delayed-`u64` Non-Overflow & Two-Step Mersenne-31 Fold

Formalizes hardware `u64` accumulator bounds and bitwise Mersenne-31 reduction `(x & 0x7fffffff) + (x >> 31)` over `Nat`:

| Theorem | Formal Statement Summary | Upstream Target |
|---|---|---|
| `m31_fold_bitwise_eq_arith`, `m31_fold_mod_eq`, `m31_fold2_mod_eq` | $`\forall\, x \in \mathbb{N}`$, `(x &&& 0x7fffffff) + (x >>> 31) = x % 2^31 + x / 2^31`, preserving congruence modulo $`2^{31} - 1`$. | `Plonky3#2600`, `proving#9` |
| `m31_fold2_bound`, `m31_fold2_max_attained` | $`\forall\, x < 2^{64}`$, two bitwise folds bound the result to $`\le 2^{31} + 2 < 2(2^{31} - 1)`$ (attained sharply at $`x = 2^{64} - 1`$). | `Plonky3#2600`, `proving#9` |
| `m31_reduce64_eq_mod`, `m31_reduce64_canonical` | $`\forall\, x < 2^{64}`$, two folds plus a single conditional subtraction yields `x % (2^31 - 1)` strictly inside `[0, 2^31 - 2]`. | `Plonky3#2600` (`reduce_64`) |
| `m31_reduce64_branchless_sound_and_canonical` | $`\forall\, x < 2^{64}`$, `stwo`'s branchless `(((t + 1) >>> 31) + t) &&& 0x7fffffff` yields canonical `x % (2^31 - 1) < 2^31 - 1`. | `proving#9` (`stwo::reduce_u64`) |
| `qm31_dot4_canonical_lt_u64`, `qm31_dot4_redundant_lt_u64` | $`\forall\, a_i, b_j \le 2^{31} - 2`$ (and redundant $`\le 2^{31} - 1`$), all 4 `QM31` `dot4` `u64` accumulators satisfy $`< 2^{64}`$, while `five_unreduced_m31_products_gt_u64` proves $`5(2^{31}-2)^2 > 2^{64}`$ (tightness of width 4). | `Plonky3#2600` (`qm31_mul_u64_dot4`) |
| `qm31_dot4_reduce64_eq_schoolbook` | $`\forall\, a_i, b_j \le 2^{31} - 2`$, reducing the 4 `dot4` `u64` channels via `m31_reduce64` equals canonical `qm31_schoolbook_mod_m31`. | `Plonky3#2600` |
| `stwo_outer_karatsuba_u64_lt_u64`, `qm31_rank7_u64_bounds` | Proves all `stwo` outer-Karatsuba delayed-`u64` channels $`< 2^{64}`$ and `QM31_Rank7` modular products $`< 2^{62}`$. | `proving#9`, `qm31_stwo.rs` |

---

### 3. [`ZkBilinearCerts/CrtSoundness.lean`](ZkBilinearCerts/CrtSoundness.lean) — Non-Native CRT Quotient-Bit Soundness

Formalizes non-native field emulation modulo native prime $`F`$ and low-carry power-of-two modulus $`M = 2^{b \cdot k}`$ (`M_crt`):

| Theorem | Formal Statement Summary | Upstream Target |
|---|---|---|
| `babybear_b22_unmasked_forgery_cert` | Kernel-checked (`decide`) 2-limb forgery over BabyBear ($`F = 2013265921`$, $`b = 22`$, $`2^{44} \ge F - 1`$, $`p = 13194140767889`$): when `q_witness` allows full `22`-bit width instead of `quoBits = 1`, $`(q, r) = (0, 0)`$ and $`(639, 13193354832913)`$ both satisfy the mod-$`F`$, mod-$`2^{22}`$, and 2-limb carry ($`c_0 = -189`$) constraints while $`a b - 639 p - r = -F \cdot 2^{22} \ne 0`$. | `Consensys/gnark#1951` |
| `babybear_single_limb_unmasked_forgery_cert` | Kernel-checked (`decide`) single-limb (`M_crt = 1`, $`p = 2^{22} - 3 = 4194301`$) wrap-around forgery $`(q, r) = (480, 1441)`$ with $`a b - 480 p - 1441 = -F`$. | `Consensys/gnark#1951` |
| `ext_gcd_nat_bezout`, `coprime_mul_dvd_of_emod_zero` | Constructive Extended Euclidean Bézout theorem and coprime CRT divisibility ($`F \mid d \land M \mid d \implies F M \mid d`$) in pure Core Lean 4. | Core CRT engine |
| `crt_quotient_soundness`, `crt_quotient_unique_witness` | Universal soundness & witness uniqueness: whenever $`\gcd(F, M) = 1`$, $`0 \le q < 2^{k}`$ (`quoBits`), and `max_diff < F * M_crt`, the modular + CRT equations force exact integer equality `a * b - q_witness * p = r`. | `Consensys/gnark#1951` |
| `babybear_b22_masked_quobits_sound` | Instantiates `crt_quotient_soundness` on BabyBear ($`F = 2013265921`$, $`M = 2^{22}`$, $`p = 13194140767889`$, `quoBits = 1`), proving exact integer soundness once `quoBits` masking is enforced. | `Consensys/gnark#1951` |

---

### 4. [`ZkBilinearCerts/VerifyAxioms.lean`](ZkBilinearCerts/VerifyAxioms.lean) — Kernel Axiom Audit

Executes `#print axioms` during `lake build` across all 33 formal theorems, confirming every proof depends exclusively on standard Lean 4 kernel axioms (`propext`, `Classical.choice`, `Quot.sound`, or zero axioms) — zero `sorryAx`, zero `Lean.ofReduceBool` / `Lean.trustCompiler`, and zero custom `axiom` declarations.

---

## Reproducing Locally

Install [`elan`](https://github.com/leanprover/elan) (which automatically selects `leanprover/lean4:v4.36.0` from `lean-toolchain`) and run:

```bash
cd lean4_certs
lake clean
lake build
```
