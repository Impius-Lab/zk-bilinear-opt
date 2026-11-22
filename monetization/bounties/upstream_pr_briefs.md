# Upstream GitHub Pull Request & Issue Specifications

Ready-to-paste upstream PR descriptions and engineering briefs backed by live `Consensys/gnark` branches (`https://github.com/Impius-Lab/gnark`) and reproducible certificates in `targets/`, `rust_crates/`, and `go_gadgets/`.

---

## 1A. `Consensys/gnark` PR 1 — Native 2-Chain `BLS12-377` Minimum-Rank R1CS Gadgets (`-48.89%` `E12.Mul`, `-32.84%` `PairingCheck`)

- **Live Branch**: `perf/bls12377-bilinear-rank11-rank23` (base `Consensys/gnark` `master` `38a87d1`)
- **Proposed PR Title**: `perf(fields_bls12377): use minimum-rank bilinear interpolation for R1CS E6/E12 arithmetic (-14.8% Pair, -32.8% PairingCheck)`

### Ready-to-Paste Upstream PR Description

#### Summary
In `std/algebra/native/fields_bls12377` (compiled over `ecc.BW6_761.ScalarField()` for 2-chain recursive Groth16 proofs), `SCS` + `frontend.Committer` uses Schwartz–Zippel (`mulSZ`/`squareSZ`), whereas `R1CS` previously fell back to `mulToom3OverKaratsuba` (`15` R1CS constraints for `E6.Mul`) and `mulKaratsuba` (`45` R1CS constraints for `E12.Mul`).

Because the `BLS12-377` tower ($`u^2 = -5`$, $`v^3 = u`$, $`w^2 = v`$) maps via **pure coordinate permutations** (zero additions) to $`E_6 \cong \mathbb{F}_p[Y]/(Y^6 + 5)`$ and $`E_{12} \cong \mathbb{F}_p[W]/(W^{12} + 5)`$, and `gnark`'s R1CS compiler folds constant scalar combinations into linear expressions for **zero R1CS constraints**, this PR introduces exact pre-inverted rational Lagrange evaluation-interpolation gadgets over $`\mathbb{Q}`$:

1. **`E6.mulRank11` (`15 -> 11` R1CS, `-26.67%`) & `E6.mulBy01Rank10` (`15 -> 10` R1CS, `-33.33%`)**: Evaluates at $`\{-5, -4, \dots, 4, \infty\}`$ with even/odd polynomial sharing (omitting $`\infty`$ when $`b_5 = 0`$) and folds modulo $`Y^6 = -5`$.
2. **`E6.squareToom3` (`12 -> 10` R1CS, `-16.67%`)**: 5 `E2` squarings with compile-time constant $`6^{-1} \bmod p`$ scaling.
3. **`E12.mulRank23` (`45 -> 23` R1CS, `-48.89%`) & `E12.mulBy01234Rank22` (`45 -> 22` R1CS, `-51.11%`)**: Evaluates at $`\{-11, -10, \dots, 10, \infty\}`$ with even/odd sharing (omitting $`\infty`$ when $`b_{11} = 0`$) and folds modulo $`W^{12} = -5`$.
4. **`E12.Square` (`30 -> 22` R1CS, `-26.67%`), `E12.MulBy034` (`30 -> 20` R1CS, `-33.33%`), & `E12.Square034` (`21 -> 14` R1CS, `-33.33%`)**: Also fixes missing `e.C1.B2.SetZero()` on dirty receivers in `square034SZ` and cuts non-Committer `SCS` gates on `MulBy034` (`116 -> 102`) and `Square034` (`68 -> 40`).
5. **Zero-Overhead Safety**: `SCS` + `frontend.Committer` (`mulSZ`/`squareSZ`) is preserved **bit-for-bit (`0` gate delta)**; denominators divide $`(2n-3)!`$ and automatically fall back to Karatsuba if $`\gcd((2n-3)!, p) \ne 1`$ ($`p \le 7`$ for `E6`, $`p \le 19`$ for `E12`); per-field weight tables are immutable and cached in a concurrency-safe `sync.Map`.

#### Measured Constraint Counts (`ecc.BW6_761.ScalarField()`)

| Operation | R1CS Before | R1CS After | R1CS $`\Delta`$ | SCS (`SZ`) Before | SCS (`SZ`) After | SCS (`noCommit`) Before | SCS (`noCommit`) After |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `E6.Mul` | `15` | **`11`** | **`-26.67%`** (`-4`) | `73` | `73` | `66` | `66` |
| `E6.Square` | `12` | **`10`** | **`-16.67%`** (`-2`) | `57` | `57` | `43` | `43` |
| `E6.MulBy01` | `15` | **`10`** | **`-33.33%`** (`-5`) | `67` | `67` | `46` | `46` |
| `E12.Mul` | `45` | **`23`** | **`-48.89%`** (`-22`) | `151` | `151` | `228` | `228` |
| `E12.Square` | `30` | **`22`** | **`-26.67%`** (`-8`) | `117` | `117` | `156` | `156` |
| `E12.MulBy034` | `30` | **`20`** | **`-33.33%`** (`-10`) | `129` | `129` | `116` | **`102`** (`-12.07%`) |
| `E12.MulBy01234` | `45` | **`22`** | **`-51.11%`** (`-23`) | `145` | `145` | `206` | `206` |
| `E12.Square034` | `21` | **`14`** | **`-33.33%`** (`-7`) | `91` | `91` | `68` | **`40`** (`-41.18%`) |
| `sw_bls12377.FinalExponentiation` | `6,319` | **`5,722`** | **`-9.45%`** (`-597`) | `24,370` | `24,370` | `27,852` | `27,852` |
| `sw_bls12377.MillerLoop` (`1`-pair) | `5,731` | **`4,544`** | **`-20.71%`** (`-1,187`) | `13,951` | `13,951` | `21,264` | **`20,468`** (`-3.74%`) |
| `sw_bls12377.Pair` (`1`-pair) | `12,050` | **`10,266`** | **`-14.80%`** (`-1,784`) | `38,278` | `38,278` | `49,116` | **`48,320`** (`-1.62%`) |
| `sw_bls12377.Pair` (`1`-pair `FixedQ`) | `10,165` | **`8,381`** | **`-17.55%`** (`-1,784`) | `33,855` | `33,855` | `44,543` | **`43,570`** (`-2.18%`) |
| `sw_bls12377.Pair` (`2`-pair `FixedQ`) | `12,205` | **`9,718`** | **`-20.38%`** (`-2,487`) | `38,802` | `38,802` | `51,837` | **`49,933`** (`-3.67%`) |
| `sw_bls12377.PairingCheck` (`2`-pair) | `10,109` | **`8,027`** | **`-20.60%`** (`-2,082`) | `24,208` | `24,208` | `35,098` | **`33,502`** (`-4.55%`) |
| `sw_bls12377.PairingCheck` (`2`-pair `FixedQ`) | `6,339` | **`4,257`** | **`-32.84%`** (`-2,082`) | `15,368` | `15,368` | `25,942` | **`24,002`** (`-7.48%`) |

#### Verification Commands
```bash
go test -v ./std/algebra/native/fields_bls12377/...
go test -v ./std/algebra/native/sw_bls12377/...
go test -v ./internal/stats -run "TestCircuitStatistics/.*bls12377"
```

---

## 1B. `Consensys/gnark` PR 2 — Non-Native Emulated `E12` / `mvCheck` Optimization & Small-Field CRT Soundness Fix (`-14.6%` `BN254` `Pair`, `-9.7%` `BLS12-381` `Pair`)

- **Live Branch**: `perf/emulated-e12-bilinear-mvcheck` (base `Consensys/gnark` `master` `38a87d1`)
- **Proposed PR Title**: `perf(std/math/emulated,algebra/emulated): tighten mvCheck quotient/CRT bounds and share E12 bilinear checks (-14.6% BN254 Pair, -9.7% BLS12-381 Pair)`

### Ready-to-Paste Upstream PR Description

#### Summary
In `std/math/emulated` and `std/algebra/emulated/fields_{bn254,bls12381}`, each direct `E12` operation (`Mul`, `Square`, `MulBy01379`, `MulBy012346789`, `MulBy02368`, `CyclotomicSquareGS`) previously pushed 12 separate `mvCheck` instances onto `f.deferredChecks` — re-committing the same input limbs `12` times (`1,152` limbs on `BN254`, `1,728` limbs on `BLS12-381`), evaluating up to `210` quadratic multiplications in the deferred check, and over-allocating quotient/carry range checks via a `+1 bit per term` heuristic.

This PR delivers three compounding constraint optimizations together with a malicious-prover CRT soundness hardening for small native fields:

1. **Canonical Monomial Deduplication & Zero/Constant Pruning (`polyMvPrep` / `buildCanonicalMv`)**: Strips zero-coefficient and strict-zero factor terms (automatically pruning the `6` zero coordinates of `cubicNonResiduePower` in `PairingCheck`/`AssertFinalExponentiationIsOne`), simplifies `One()` factors, merges duplicate monomials without `int` overflow, and folds pure compile-time constant evaluations.
2. **Exact `*big.Int` Quotient Width, CRT Low-Carry Tightening & Small-Field Soundness Fix (`field_mul.go`)**:
   - Replaces the `+1 bit per term` heuristic with exact signed worst-case `*big.Int` bounds $`(\mathrm{posMax}, \mathrm{negMax}, \max\mathrm{Quo})`$, packing the quotient witness via `packLimbsWithWidth(ret[:nbQuoLimbs], quoBits)` (`quoBits = maxQuo.BitLen()`), tightening `mvLowCarries` (`7 -> 6` low carries per output on `BN254`, `11 -> 9` on `BLS12-381`), and eliding `kNeg` (`AssertIsBoolean` + commitment + sign mul) whenever $`\mathrm{negMax} = 0`$ or $`\mathrm{nbQuoLimbs} = 0`$.
   - **Soundness Hardening (`2t >= F - 1`)**: Previously, packing `quo` to full `nbBits`-wide limbs while bounding carries by the honest quotient bit-length allowed a malicious prover on wide limbs over small native fields ($`2t \ge F - 1`$, e.g., $`t = 22`$ over 31-bit BabyBear $`q = 2013265921`$, permitted by `NewField` since $`F \ge t + 3`$) to pick excess quotient bits $`k_0 < 2^t`$ wrapping $`k_0 p_i - r_i = m_i q \equiv 0 \pmod{q}`$ (and similarly in single-/multi-limb `callMulHint` when uncapped CRT carry requirements exceed `0`). Constraining `quo` to exact `quoBits` and guarding uncapped CRT requirements in `callMulHint` ensures $`\vert h_i^{\mathrm{mal}} + \hat{c}_{i-1} - 2^t \hat{c}_i\vert \le \frac{13}{16} 2^{F-1} < q`$ unconditionally.
3. **Shared-Commitment Sub-Quadratic Deferred Evaluators (`MulPolyModTrinomial12` & `EvalSystem`)**:
   - Commits shared input limbs **once** instead of `12x` (`1,152 -> 96` limbs on `BN254`, `1,728 -> 144` on `BLS12-381`).
   - Dispatches `MulPolyModTrinomial12` to cached modular Even/Odd Vandermonde interpolation at $`\{0, \pm 1, \dots, \pm K\}`$ (`20`–`23` muls vs `60`–`210`) on R1CS & small-field extensions (`extensionApi != nil`), and to the exact $`\mathbb{Z}`$-isomorphic $`2\times 3\times 2`$ tower ($`u = W^6 - \gamma`$) with zero/one slot specialization on native SCS/PlonK.
   - Shares monomials, $`(u - w)(u + w)`$ difference-of-squares, and R1CS 1D Karatsuba cross-sums in `EvalSystem` across `CyclotomicSquareGS` (`43 -> 18` R1CS muls), `Mul01379By01379`, `Mul02368By02368ThenMul`, and `Ext2.{Mul,Square,Cube}`.

#### Measured Constraint Counts (`ecc.BN254.ScalarField()`)

| Curve & Operation | R1CS Before | R1CS After | R1CS $`\Delta`$ | PlonK / SCS Before | PlonK / SCS After | PlonK / SCS $`\Delta`$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `BN254 E12.Mul` | `4,463` | **`3,894`** | **`-12.75%`** (`-569`) | `17,985` | **`16,149`** | **`-10.21%`** (`-1,836`) |
| `BN254 E12.Square` | `3,886` | **`3,413`** | **`-12.17%`** (`-473`) | `15,795` | **`14,019`** | **`-11.24%`** (`-1,776`) |
| `BN254 E12.CyclotomicSquareGS` | `3,775` | **`3,410`** | **`-9.67%`** (`-365`) | `15,636` | **`13,958`** | **`-10.73%`** (`-1,678`) |
| `BN254 E12.MulBy01379` | `3,931` | **`3,521`** | **`-10.43%`** (`-410`) | `16,143` | **`14,474`** | **`-10.34%`** (`-1,669`) |
| `BN254 E12.MulBy012346789` | `4,343` | **`3,813`** | **`-12.20%`** (`-530`) | `17,569` | **`15,775`** | **`-10.21%`** (`-1,794`) |
| `BN254 E12.Expt` | `156,515` | **`131,980`** | **`-15.68%`** (`-24,535`) | `592,131` | **`498,959`** | **`-15.74%`** (`-93,172`) |
| `BN254 FinalExponentiation` | `466,445` | **`399,198`** | **`-14.42%`** (`-67,247`) | `1,683,026` | **`1,443,121`** | **`-14.25%`** (`-239,905`) |
| `BN254 Pair` (`1`-pair witness `G2`) | `836,825` | **`715,060`** | **`-14.55%`** (`-121,765`) | `3,027,526` | **`2,599,706`** | **`-14.13%`** (`-427,820`) |
| `BN254 Pair` (`1`-pair fixed `G2`) | `720,474` | **`611,184`** | **`-15.17%`** (`-109,290`) | `2,608,111` | **`2,233,950`** | **`-14.35%`** (`-374,161`) |
| `BN254 PairingCheck` (`2`-pair) | `736,147` | **`636,622`** | **`-13.52%`** (`-99,525`) | `2,624,114` | **`2,292,250`** | **`-12.65%`** (`-331,864`) |
| `BLS12-381 E12.Mul` | `6,344` | **`5,789`** | **`-8.75%`** (`-555`) | `25,835` | **`24,084`** | **`-6.78%`** (`-1,751`) |
| `BLS12-381 E12.Square` | `5,527` | **`5,068`** | **`-8.30%`** (`-459`) | `22,637` | **`20,946`** | **`-7.47%`** (`-1,691`) |
| `BLS12-381 E12.CyclotomicSquareGS` | `5,456` | **`5,085`** | **`-6.80%`** (`-371`) | `22,634` | **`20,970`** | **`-7.35%`** (`-1,664`) |
| `BLS12-381 E12.MulBy02368` | `5,717` | **`5,293`** | **`-7.42%`** (`-424`) | `23,608` | **`21,897`** | **`-7.25%`** (`-1,711`) |
| `BLS12-381 E12.ExptGS` | `190,078` | **`171,257`** | **`-9.90%`** (`-18,821`) | `730,815` | **`654,154`** | **`-10.49%`** (`-76,661`) |
| `BLS12-381 E12.ExptNeg` | `187,249` | **`163,815`** | **`-12.51%`** (`-23,434`) | `689,264` | **`615,906`** | **`-10.64%`** (`-73,358`) |
| `BLS12-381 FinalExponentiation` | `856,526` | **`774,008`** | **`-9.63%`** (`-82,518`) | `3,185,072` | **`2,863,642`** | **`-10.09%`** (`-321,430`) |
| `BLS12-381 Pair` (`1`-pair witness `G2`) | `1,323,407` | **`1,194,960`** | **`-9.71%`** (`-128,447`) | `4,881,141` | **`4,402,294`** | **`-9.81%`** (`-478,847`) |
| `BLS12-381 Pair` (`1`-pair fixed `G2`) | `1,178,947` | **`1,061,176`** | **`-9.99%`** (`-117,771`) | `4,358,510` | **`3,925,500`** | **`-9.93%`** (`-433,010`) |
| `BLS12-381 PairingCheck` (`2`-pair) | `825,838` | **`752,583`** | **`-8.87%`** (`-73,255`) | `2,958,308` | **`2,715,967`** | **`-8.19%`** (`-242,341`) |
| `internal/stats`: `pairing_bw6761` | `3,242,559` | **`3,100,024`** | **`-4.40%`** (`-142,535`) | `12,295,948` | **`11,687,119`** | **`-4.95%`** (`-608,829`) |
| `internal/stats`: `scalar_mul_G2_bn254` | `449,267` | **`416,348`** | **`-7.33%`** (`-32,919`) | `1,552,336` | **`1,410,982`** | **`-9.11%`** (`-141,354`) |
| `internal/stats`: `scalar_mul_G2_bls12381` | `597,886` | **`567,970`** | **`-5.00%`** (`-29,916`) | `2,095,083` | **`1,966,272`** | **`-6.15%`** (`-128,811`) |
| `internal/stats`: `scalar_mul_P256` | `130,856` | **`118,536`** | **`-9.41%`** (`-12,320`) | `481,361` | **`428,120`** | **`-11.06%`** (`-53,241`) |

#### Verification Commands
```bash
go test ./std/math/emulated/...
go test ./std/algebra/emulated/fields_bn254/... ./std/algebra/emulated/fields_bls12381/...
go test ./std/algebra/emulated/sw_bn254/... ./std/algebra/emulated/sw_bls12381/...
go test ./internal/stats
```

---

## 2. `starkware-libs/stwo` — Optimal 7-Mul `QM31` Recursive AIR & Verifier Gadget (`-22.22%`)

### Proposed Issue / PR Title
`perf(qm31): reduce QM31 bilinear constraint rank from 9 to 7 (-22.22%) via unimodular u^4 - 4u^2 + 5 isomorphism`

### Technical Summary for Maintainers
Currently, `QM31` (`CM31[u]/(u^2 - (2 + i))` over $`p = 2^{31} - 1`$) multiplication in recursive AIR constraints and non-SIMD verifier paths uses 2-level Karatsuba (`3 * 3 = 9` `M31` bilinear multiplications).

Because $`u^2 = 2 + i \implies (u^2 - 2)^2 = i^2 = -1`$, `QM31` is canonically isomorphic to the simple monic quartic field $`\mathbb{M}_{31}[u]/(u^4 - 4u^2 + 5)`$ via the **division-free unimodular ($`\det = 1`$) integer change of basis**:
```text
(a0 + a1*i) + (b0 + b1*i)*u  <-->  (a0 - 2*a1) + (b0 - 2*b1)*u + a1*u^2 + b1*u^3
```
Interpolating on the symmetric projective nodes `{-2, -1, 0, 1, 2, 3, inf}` attains the **exact Winograd / Alder–Strassen lower bound of `7` `M31` multiplications (`-22.22%`)**:
- **Degree-2 AIR / Recursive Verifier Impact**: Cuts degree-2 `M31` bilinear terms per `QM31` multiplication from `9` to `7` (`0` extra degree cost for constant linear combinations).
- **BitVM2 / Bitcoin Script Impact**: Cuts expensive `M31` multiplication opcodes per `QM31` product from `9` to `7` while replacing interpolation divisions by $`120^{-1} \bmod p`$ (where $`2^{-3}`$ is a free Mersenne bit-rotation!).
- **Zero `u64` / `i64` Overflow Guarantee**: Across all inputs in $`[0, 2^{31}-2]^4`$, peak intermediate magnitude in `U*a`, `V*b`, `m_l`, `W_z*m`, and `* INV_120` is **strictly $`\le 62`$ bits (`< 2^63`)**, verified exhaustively on basis pairs + adversarial sign-aligned vectors + `14,000` fuzz samples (`targets/qm31_stwo/`).

### Files Touched in Proposed PR
- `crates/prover/src/core/fields/qm31.rs` (optional verifier/AirEval helper `mul_bilinear_rank7`)
- `crates/constraint-framework/` (`EvalAtRow` `QM31` degree-2 bilinear expression evaluator)

---

## 3. `Plonky3/Plonky3` — Optimal $`2d - 1`$ `BinomialExtensionField` AIR Constraint Evaluators (`-22.22%` to `-44.44%`)

### Proposed Issue / PR Title
`feat(field,air): optimal (2D - 1)-mul bilinear evaluators for BabyBear^{4,5}, KoalaBear^{4,8}, and Goldilocks^{4,5}`

### Technical Summary for Maintainers
In recursive STARK verification (`p3-uni-stark` / `SP1` recursion), `BinomialExtensionField<F, D>` expressions over `AB::Expr` treat multiplication by compile-time `F` constants as degree-0 scalar scaling (`0` extra trace columns), while `AB::Expr * AB::Expr` consumes degree budget / auxiliary columns.

Replacing recursive Karatsuba (`9` muls for $`D=4`$, `15` for $`D=5`$, `27` for $`D=8`$) with small-node projective Lagrange interpolation achieves the **provably minimal Winograd / Alder–Strassen rank $`2D - 1`$** across every `Plonky3` extension:

| `Plonky3` Extension | Polynomial | Current Karatsuba Muls | Certified Optimal Rank | Constraint Reduction | Accumulator Proof |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `BinomialExtensionField<BabyBear, 4>` | $`X^4 - 11`$ | `9` | **`7`** | **`-22.22%`** | `62b < 2^63` (`i64`/`u64`) |
| `BinomialExtensionField<BabyBear, 5>` | $`X^5 - 2`$ | `15` | **`9`** | **`-40.00%`** | `62b < 2^63` (`i64`/`u64`) |
| `BinomialExtensionField<KoalaBear, 4>` | $`X^4 - 3`$ | `9` | **`7`** | **`-22.22%`** | `62b < 2^63` (`i64`/`u64`) |
| `BinomialExtensionField<KoalaBear, 8>` | $`X^8 - 3`$ | `27` | **`15`** | **`-44.44%`** | `63b < 2^63` (2-term chunked `u64`) |
| `BinomialExtensionField<Goldilocks, 4>` | $`X^4 - 7`$ | `9` | **`7`** | **`-22.22%`** | `128b < 2^128` (`u128`) |
| `BinomialExtensionField<Goldilocks, 5>` | $`X^5 - 3`$ | `15` | **`9`** | **`-40.00%`** | `128b < 2^128` (`u128`) |

Reference `#![no_std]` implementation + generic `SymbolicFieldExpr` evaluator is ready in `rust_crates/src/lib.rs` and `targets/plonky3_extensions/`.
