# Upstream GitHub Pull Request & Issue Specifications

Ready-to-paste upstream PR descriptions backed by live open `Consensys/gnark` PRs ([`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) & [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951)), R2-verified `starkware-libs/proving` (`Impius-Lab/proving` branch `perf/qm31-min-rank-and-verifier-ops` @ `149dcdf`) and `Plonky3/Plonky3` (`Impius-Lab/Plonky3` branch `perf/min-rank-extension-algebra` @ `43c843c`) branches, and reproducible certificates in `targets/`, `rust_crates/`, and `go_gadgets/`.

---

## 1A. `Consensys/gnark` PR 1 — Native 2-Chain `BLS12-377` Minimum-Rank R1CS Gadgets (`-48.89%` `E12.Mul`, `-32.84%` `PairingCheck`)

- **Live Upstream PR**: [`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) (`https://github.com/Consensys/gnark/pull/1950`)
- **Live Branch**: `perf/bls12377-bilinear-rank11-rank23` (`5b09aa5`, base `Consensys/gnark` `master` `38a87d1`)
- **PR Title**: `perf(fields_bls12377): use minimum-rank bilinear interpolation for R1CS E6/E12 arithmetic (-14.8% Pair, -32.8% PairingCheck)`

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

- **Live Upstream PR**: [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951) (`https://github.com/Consensys/gnark/pull/1951`)
- **Live Branch**: `perf/emulated-e12-bilinear-mvcheck` (`4a43edf`, base `Consensys/gnark` `master` `38a87d1`)
- **PR Title**: `perf(std/math/emulated,algebra/emulated): tighten mvCheck quotient/CRT bounds and share E12 bilinear checks (-14.6% BN254 Pair, -9.7% BLS12-381 Pair)`

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

## 2. `starkware-libs/proving` (`stwo`) — Scalar `CM31`/`QM31` Acceleration (`2.71x` Mul) & Multi-Backend AIR/Verifier `QM31` Mul Compression (`22 -> 9`, `-59.1%`)

- **Live Branch**: `perf/qm31-min-rank-and-verifier-ops` (`149dcdf`, base `starkware-libs/proving` `main` `9bc8c8d`)
- **Compare URL**: [`https://github.com/starkware-libs/proving/compare/main...Impius-Lab:proving:perf/qm31-min-rank-and-verifier-ops`](https://github.com/starkware-libs/proving/compare/main...Impius-Lab:proving:perf/qm31-min-rank-and-verifier-ops)
- **Proposed PR Title**: `perf(stwo,airs): accelerate CM31/QM31 scalar ops (2.71x mul) and cut AIR/verifier QM31 muls 22 -> 9 (-59.1%)`

### Ready-to-Paste Upstream PR Description

#### Summary
In `crates/stwo/src/core/fields/{cm31.rs,qm31.rs}` and `crates/airs` (`Qm31Ops` & `QM31AddMulOpcode`), scalar `QM31` (`CM31[u]/(u^2 - (2 + i))` over $`P = 2^{31} - 1`$) and symbolic `FeltExpr` `QM31` multiplication previously expanded naive 20-multiplication schoolbook products (`22` total multiplications per `QM31` product in generated AIR/verifier components once the two `* 2` non-residue scalings are counted).

This PR delivers both scalar `stwo` prover/verifier field speedups (`#no_std`-clean) and multi-backend `[AIR-GENERATED]` constraint multiplication reductions across Rust SIMD, `stwo-circuits`, and `stwo_cairo_verifier`:

1. **Scalar `CM31` & `QM31` (`crates/stwo/src/core/fields/{cm31.rs,qm31.rs}`, `#![no_std]` compatible)**:
   - **`CM31::mul` (`1.47x`, `-32.0%`) & `CM31::square` (`4 -> 2` `M31` muls)**: 3-mul Gauss/Karatsuba multiplication and 2-mul `(a + b)(a - b), 2ab` squaring.
   - **`QM31::mul` (`2.71x` 8-way throughput / `2.44x` 1-way latency) & `QM31::square` (`2.55x` / `2.25x`)**: Delayed-`u64` outer Karatsuba (`impl Mul for QM31`) and specialized 7-mul delayed-`u64` `QM31::square` performing **a single Mersenne reduction (`reduce_u64`) per output coordinate**, plus add-only `pub const fn mul_by_r(CM31) -> CM31` in `QM31::inverse`. Exhaustively proven overflow-free and strictly canonical ($`\in [0, P - 1]`$) across all $`[0, P - 1]^4`$ inputs (`s_im <= 0xfffffffa_00000008 < u64::MAX`, `fold_u64 <= 10,737,418,224 < 6P`, `reduce_u64(v) < P` for all `v in 0..=u64::MAX`).
   - **`pub const fn QM31::mul_rank7`**: Exposes the exact Winograd / Alder–Strassen 7-multiplication kernel via the unimodular ($`\det = 1`$) simple-extension isomorphism $`\mathrm{QM31} \cong \mathbb{M}_{31}[u]/(u^4 - 4u^2 + 5)`$ interpolated on $`\{-2, -1, 0, 1, 2, 3, \infty\}`$.
2. **Multi-Backend Symbolic `FeltExpr` `QM31` Multiplication (`crates/airs/src/convolution_utils/qm31_mul.rs`)**:
   - **Architectural Cost Dichotomy (`Const * Var` Lowering)**: In `crates/air_code_gen` and `crates/circuits/src/ops.rs`, every non-unit `Const * Var` ($`c \notin \{0, 1\}`$) in `FeltExpr` lowers to a `PackedM31 * PackedM31` SIMD mul in `SimdDomainEvaluator`, a `qm31_const * QM31` mul in `stwo_cairo_verifier`, and a `Qm31Ops::Mul` circuit gate in `stwo-circuits`. Consequently, `qm31_mul_expr_in_air` (wired into `Qm31Ops` and `QM31AddMulOpcode`) uses **unimodular $`\{0, +1, -1\}`$ nested Karatsuba-9 with `AirBuilder::let_for_constraint` sharing**: `9` `Var * Var` muls + `0` non-unit `Const * Var` muls = **`9` total multiplications vs `22` (`-59.1%`, `-13` muls)** and `36` vs `38` total ops (`-5.3%`), preserving exact constraint degree `3` and identical `sample_evaluations.json` polynomials. Meanwhile, `qm31_mul_expr` and `qm31_mul_rank7_in_air` (`20 -> 7` `Var * Var` muls, `-65.0%`) are provided and tested for degree-0-folded backends.
   - Regenerated all 5 downstream `[AIR-GENERATED]` components (`cairo-air`, `cairo_verifier`, `circuit_prover`, `circuit_verifier`, `stwo_cairo_verifier`) and synced `MULTIVERIFIER_PREPROCESSED_ROOT`, `test_data/multiverifier/proof.bin`, and canonical small circuit registries.

#### Measured `stwo` Scalar CPU Benchmarks (`--release`, `core::hint::black_box`, Median of 5 Trials)

| Operation (`crates/stwo`) | Before (`9bc8c8d`) | After (`149dcdf`) | $`\Delta`$ / Speedup | Notes |
| :--- | :---: | :---: | :---: | :--- |
| `CM31::mul` (8-way throughput) | `2.569 ns` | **`1.748 ns`** | **`-32.0%` (`1.47x`)** | `4 -> 3` `M31` muls |
| `CM31::square` (8-way throughput) | `2.329 ns` | **`2.033 ns`** | **`-12.7%` (`1.15x`)** | `4 -> 2` `M31` muls |
| `QM31::mul` (`impl Mul`, 8-way) | `13.004 ns` | **`4.797 ns`** | **`-63.1%` (`2.71x`)** | Delayed-`u64` outer Karatsuba (1 red/limb) |
| `QM31::mul` (`impl Mul`, 1-way) | `19.970 ns` | **`8.196 ns`** | **`-59.0%` (`2.44x`)** | Dependent chain latency |
| `QM31::mul_rank7` (`const fn`, 1-way) | `19.970 ns` | **`12.616 ns`** | **`-36.8%` (`1.58x`)** | `7` `M31` muls mod $`u^4 - 4u^2 + 5`$ |
| `QM31::square` (8-way throughput) | `13.717 ns` | **`5.376 ns`** | **`-60.8%` (`2.55x`)** | Specialized `7`-mul delayed-`u64` |
| `QM31::square` (1-way latency) | `22.127 ns` | **`9.824 ns`** | **`-55.6%` (`2.25x`)** | Dependent chain latency |
| `QM31::inverse` | `103.504 ns` | **`101.218 ns`** | **`-2.2%`** | Add-only `mul_by_r` |

#### Measured Multi-Backend `[AIR-GENERATED]` Multiplication Counts

| Generated Component / Compiled JSON | Muls Before (`9bc8c8d`) | Muls After (`149dcdf`) | Total Mul $`\Delta`$ | Isolated `QM31` Product |
| :--- | :---: | :---: | :---: | :---: |
| `crates/cairo-air/src/components/qm_31_add_mul_opcode.rs` | `39` | **`26`** | **`-13` (`-33.3%`)** | **`22 -> 9` (`-59.1%`)** |
| `crates/cairo_verifier/src/components/qm_31_add_mul_opcode.rs` | `39` | **`26`** | **`-13` (`-33.3%`)** | **`22 -> 9` (`-59.1%`)** |
| `crates/circuit_prover/src/circuit_air/components/qm_31_ops.rs` | `42` | **`29`** | **`-13` (`-31.0%`)** | **`22 -> 9` (`-59.1%`)** |
| `crates/circuit_verifier/src/components/qm_31_ops.rs` | `42` | **`29`** | **`-13` (`-31.0%`)** | **`22 -> 9` (`-59.1%`)** |
| `stwo_cairo_verifier/crates/circuit_air/src/components/qm_31_ops.cairo` | `46` | **`33`** | **`-13` (`-28.3%`)** | **`22 -> 9` (`-59.1%`)** |
| `outputs/compiled_casm_air/.../qm_31_add_mul_opcode.json` | `39` | **`26`** | **`-13` (`-33.3%`)** | **`22 -> 9` (`-59.1%`)** |
| `outputs/compiled_circuit_air/.../qm_31_ops.json` | `42` | **`29`** | **`-13` (`-31.0%`)** | **`22 -> 9` (`-59.1%`)** |

#### Verification Commands
```bash
cargo test -p stwo --no-default-features
cargo +stable check --manifest-path ensure-verifier-no_std/Cargo.toml
cargo +stable check -p cairo-air -p circuit-cairo-verifier -p circuit-verifier -p circuits -p airs -p air_code_gen
cargo test -p airs -- --skip test_key_generation_python_utils
cargo test --profile ci -p cairo-air -- qm_31_add_mul_opcode
cargo test --profile ci -p circuit-prover -- qm_31_ops
cargo test --profile ci -p circuit-cairo-verifier -p circuit-verifier -p circuit-params
cargo clippy -p stwo -p airs -p cairo-air -p circuit-prover -p circuit-cairo-verifier -p circuit-verifier --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

---

## 3. `Plonky3/Plonky3` — Minimum-Rank $`(2D - 1)`$ `ExtensionAlgebra` Kernels & `Complex<Mersenne31>` Acceleration (`4.26x` `QM31`, `-56.25%` to `-76.56%` AIR Muls)

- **Live Branch**: `perf/min-rank-extension-algebra` (`43c843c`, base `Plonky3/Plonky3` `main` `0d80373`)
- **Compare URL**: [`https://github.com/Plonky3/Plonky3/compare/main...Impius-Lab:Plonky3:perf/min-rank-extension-algebra`](https://github.com/Plonky3/Plonky3/compare/main...Impius-Lab:Plonky3:perf/min-rank-extension-algebra)
- **Proposed PR Title**: `perf(field,air,mersenne-31): minimum-rank (2D - 1) ExtensionAlgebra kernels and Complex<Mersenne31> acceleration`

### Ready-to-Paste Upstream PR Description

#### Summary
In `p3-air`, extension-field arithmetic over `SymbolicExpression` and `ArithmeticExpression` previously lacked `ExtensionAlgebra` implementations, falling back to generic $`D^2`$ schoolbook/convolution expansions (`16` quadratic muls for $`D = 4`$, `25`–`26` for $`D = 5`$, `64` for $`D = 8`$). Meanwhile, in `p3-mersenne-31`, `Complex<Mersenne31>` extensions (`QM31` at $`D = 2`$ and `M31^6` at $`D = 3`$, $`W = 5i`$) performed generic per-product modular reductions and `* (-1)` multiplications.

This PR introduces two `#![no_std]` improvements across `p3-field`, `p3-air`, and `p3-mersenne-31`:

1. **`#![no_std]` Minimum-Rank $`(2D - 1)`$ Kernels (`p3-field`) & Shared-DAG `ExtensionAlgebra` Wiring (`p3-air`)**:
   - Adds `p3_field::extension::min_rank` with compile-time Vandermonde-verified `i128` interpolation matrices (`T * V == denom * I` `const`-asserted, zero heap / zero floating-point):
     * `binomial_mul_min_rank` & `binomial_square_min_rank` for $`D \in \{2, 3, 4, 5, 8\}`$ (`3/2`, `5/5`, `7/7`, `9/9`, `15/15` quadratic ops vs `4, 9, 16, 25, 64`), with clean fallback for unsupported $`D`$ or non-invertible small denominators.
     * `cubic_trinomial_{mul,square}_min_rank` ($`X^3 - X - 1`$: `9 -> 5` muls, `6 -> 5` squares), `quintic_trinomial_{mul,square}_min_rank` ($`X^5 + X^2 - 1`$: `26 -> 9` muls, `17 -> 9` squares), and `qm31_{mul,square}_min_rank` ($`u^4 - 4u^2 + 5`$ unimodular isomorphism: `16 -> 7` muls, `8 -> 6` squares).
   - Adds `Algebra::linear_combinations` with pointer-shared `Arc` overrides on `SymbolicExpression<F>`, `SymbolicExpressionExt<F, EF>`, `ArithmeticExpression<F>`, and `ArithmeticExpressionExt<F, EF>` — preserving shared `Arc` identity across multi-root DAGs (`fold_symbolic_expressions`, JSON wire `flatten`, and `CapturedArithmeticConstraints::lower`), lowering `F::NEG_ONE` weights to `Neg`/`Sub` (**`0` constant scalar leaf multiplications**), and preserving exact `degree_multiple`, `degree_multiple_with_transition`, and `poly_degree`.
2. **`Complex<Mersenne31>` (`CM31`, `QM31`, `M31^6`) Delayed-`u64` Acceleration (`p3-field`, `p3-mersenne-31`)**:
   - Adds `ComplexExtendable::{complex_mul, complex_square}` (eliminating `* (-1)` multiplications; 2-mul Gauss squaring) and `HasComplexBinomialExtension::{complex_ext_mul, complex_ext_square}` specializing $`D \in \{2, 3\}`$ via `mul_by_w`.
   - Overrides both traits on `Mersenne31` with branchless `u64` single-reduction-per-limb `dot4`/`parallel8` (`QM31`) and `dot6`/`fast` (`M31^6`) kernels using `P ^ x == P - x` ($`P = 2^{31} - 1`$), proven overflow-free across all redundant-zero `value in [0, P]` inputs (`4P^2 <= u64::MAX`).

#### Measured Criterion CPU Benchmarks (`cargo +stable bench -p p3-mersenne-31 --bench extension -- --quick`)

| Benchmark (`p3-mersenne-31`) | Before (`0d80373`) | After (`43c843c`) | $`\Delta`$ / Speedup |
| :--- | :---: | :---: | :---: |
| `QM31` `mul-throughput/100` (per op) | `20.331 ns` | **`4.768 ns`** | **`-76.55%` (`4.26x`)** |
| `QM31` `mul-latency/1000` (per op) | `26.047 ns` | **`8.238 ns`** | **`-68.37%` (`3.16x`)** |
| `QM31` `square` | `13.396 ns` | **`5.476 ns`** | **`-59.12%` (`2.45x`)** |
| `QM31` `inv` | `81.627 ns` | **`41.559 ns`** | **`-49.09%` (`1.96x`)** |
| `PackedQM31/square/dependent_64` | `922.13 ns` | **`622.56 ns`** | **`-32.49%` (`1.48x`)** |
| `M31^6` (`D=3`) `mul-throughput/100` (per op) | `43.222 ns` | **`14.957 ns`** | **`-65.40%` (`2.89x`)** |
| `M31^6` (`D=3`) `mul-latency/1000` (per op) | `29.993 ns` | **`21.207 ns`** | **`-29.29%` (`1.41x`)** |
| `M31^6` (`D=3`) `square` | `26.702 ns` | **`11.709 ns`** | **`-56.15%` (`2.28x`)** |
| `M31^6` (`D=3`) `inv` | `116.52 ns` | **`61.828 ns`** | **`-46.94%` (`1.88x`)** |

#### Measured `p3-air` Multi-Root Symbolic & Arithmetic DAG Constraint Counts

| Extension (`p3-air` Multi-Root DAG) | `Sym` Mul Quadratic Muls | `Sym` Mul Add/Sub | `Sym` Sq Quadratic Muls | `Arith` Mul `(Mul, Sq, MixedDot)` | `Arith` Sq `(Mul, Sq, MixedDot)` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `Complex<Mersenne31>` / `Goldilocks` Binomial (`D=2`) | `4 -> 3` (**`-25.0%`**) | `2 -> 5` | `3 -> 2` (**`-33.3%`**) | `(3, 0, 4)` (`0` scalar muls on `M31`) | `(2, 0, 3..4)` |
| `Mersenne31` Binomial (`D=3`) | `9 -> 5` (**`-44.4%`**) | `6 -> 23` | `9 -> 5` (**`-44.4%`**) | `(5, 0, 13)` | `(0, 5, 8)` |
| `BabyBear` / `KoalaBear` Binomial (`D=4`) | `16 -> 7` (**`-56.25%`**) | `12 -> 46` | `10 -> 7` (**`-30.0%`**) | `(7, 0, 24)` | `(0, 7, 14)` |
| `BabyBear` / `Goldilocks` Binomial (`D=5`) | `25 -> 9` (**`-64.0%`**) | `20 -> 79` | `15 -> 9` (**`-40.0%`**) | `(9, 0, 33)` | `(0, 9, 19)` |
| `BabyBear` / `KoalaBear` Binomial (`D=8`) | `64 -> 15` (**`-76.56%`**) | `56 -> 220` | `36 -> 15` (**`-58.3%`**) | `(15, 0, 60)` | `(0, 15, 34)` |
| `Goldilocks` `CubicTrinomial` (`D=3`, $`X^3 - X - 1`$) | `9 -> 5` (**`-44.4%`**) | `9 -> 21` | `6 -> 5` (**`-16.7%`**) | `(5, 0, 14)` | `(0, 5, 9)` |
| `KoalaBear` `QuinticTrinomial` (`D=5`, $`X^5 + X^2 - 1`$) | `26 -> 9` (**`-65.4%`**) | `27 -> 80` | `17 -> 9` (**`-47.1%`**) | `(9, 0, 34)` | `(0, 9, 20)` |
| `Mersenne31` `QM31` Tower (`D=4`, $`u^4 - 4u^2 + 5`$) | `16 -> 7` (**`-56.25%`**) | `18 -> 50` | `8 -> 6` (**`-25.0%`**) | `(7, 0, 27)` | `(6, 0, 10)` |

#### Verification Commands
```bash
cargo +stable test -p p3-field -p p3-air -p p3-mersenne-31 -p p3-baby-bear -p p3-koala-bear -p p3-goldilocks -p p3-monty-31
cargo +stable test -p p3-air --features testing
cargo +stable test -p p3-uni-stark --features parallel
cargo +stable check --no-default-features -p p3-field -p p3-air -p p3-mersenne-31
cargo +stable clippy --no-deps -p p3-field -p p3-air -p p3-mersenne-31 --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo +stable doc --no-deps --document-private-items -p p3-field -p p3-air -p p3-mersenne-31
cargo +stable fmt --all -- --check
```
