# `zk-bilinear-opt` — Certified Optimal Bilinear Extension & Pairing-Tower Gadgets for ZK Circuits

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](./LICENSE-MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB.svg)](./pyproject.toml)
[![Go 1.23+](https://img.shields.io/badge/go-1.23%2B-00ADD8.svg)](./go_gadgets/go.mod)
[![no_std Rust](https://img.shields.io/badge/rust-no__std-DEA584.svg)](./rust_crates/Cargo.toml)
[![Cairo 2.21+](https://img.shields.io/badge/cairo-2.21%2B-FF4F00.svg)](./cairo_gadgets/Scarb.toml)
[![Lean 4 v4.36.0](https://img.shields.io/badge/lean4-zero--sorry-5B21B6.svg)](./lean4_certs/lakefile.toml)

`zk-bilinear-opt` is an exact finite-field bilinear rank certifier, non-native limb-carry Pareto optimizer, zero-`sorry` **Lean 4** formal proof suite ([`lean4_certs/`](./lean4_certs/README.md)), and deterministic `#![no_std]` Rust / Go / Cairo / BitVM2 code generator for Zero-Knowledge STARK and SNARK extension towers (**StarkWare `stwo` & Cairo**, **`Plonky3` / `SP1`**, **`Consensys/gnark`**, **Aleo `snarkVM` (`BLS12-377`)**, **Zcash `Halo2` / `Pasta` / `BLS12-381`**, and **BitVM2 Tapscript**) — accompanied by our live Cloudflare Workers Static Assets B2B storefront ([`https://impius-lab-zk.weight-space-engineering.workers.dev`](https://impius-lab-zk.weight-space-engineering.workers.dev)).

---

## 1. Executive Benchmark Summary

Every schedule in this repository (`64` schedules across `18` extension targets) is verified over **both $`\mathbb{Z}`$ and $`\mathbb{F}_p`$ across 100% of canonical $`d^2`$ basis pairs** (**`3,706` exact basis-pair proofs**, which by bilinearity proves algebraic identity across all $`p^{2d}`$ field pairs), cross-checked against **`109,000` randomized differential fuzz samples**, bounded under adversarial hardware (`i64`/`u64`/`u128`) and non-native ($`4\times 64`$ / $`6\times 64`$) limb-overflow inputs, and validated inside live **`Consensys/gnark` `frontend.Compile`** R1CS and PlonK (`SCS`) circuits.

### A. Native STARK / Recursive AIR / 2-Chain R1CS Extension Towers (`stwo`, `Plonky3` / `SP1` & `gnark` `BLS12-377`)

| Target Extension | Ecosystem | Prime / Modulus | Deg $`d`$ | Upstream Baseline | Certified Optimal Rank ($`2d-1`$) | Bilinear Gate / R1CS Savings | Word / Wire Safety |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`QM31`** (`SecureField`) | StarkWare `stwo` | $`2^{31} - 1`$ | `4` | `9` (`3x3` Karatsuba) | **`7`** (`u^4 - 4u^2 + 5`) | **`-22.22%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| **`BabyBear^4`** | `Plonky3` / `SP1` | $`2^{31} - 2^{27} + 1`$ | `4` | `9` (Karatsuba-4) | **`7`** (`X^4 - 11`) | **`-22.22%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| **`BabyBear^5`** | `Plonky3` / `SP1` | $`2^{31} - 2^{27} + 1`$ | `5` | `15` (Karatsuba-5) | **`9`** (`X^5 - 2`) | **`-40.00%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| **`KoalaBear^4`** | `Plonky3` | $`2^{31} - 2^{24} + 1`$ | `4` | `9` (Karatsuba-4) | **`7`** (`X^4 - 3`) | **`-22.22%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| **`KoalaBear^8`** | `Plonky3` | $`2^{31} - 2^{24} + 1`$ | `8` | `27` (`3^3` Karatsuba) | **`15`** (`X^8 - 3`) | **`-44.44%`** | `63b` (`< 2^63` via 2-term `u64`) |
| **`Goldilocks^2`** | `Plonky2` / `Plonky3` | $`2^{64} - 2^{32} + 1`$ | `2` | `3` (Karatsuba-2) | **`3`** (`X^2 - 7`) | Optimal ($`2d-1`$) | `128b` (`< 2^128` in `u128`) |
| **`Goldilocks^4`** | `Plonky3` | $`2^{64} - 2^{32} + 1`$ | `4` | `9` (Karatsuba-4) | **`7`** (`X^4 - 7`) | **`-22.22%`** | `128b` (`< 2^128` in `u128`) |
| **`Goldilocks^5`** | `Plonky3` | $`2^{64} - 2^{32} + 1`$ | `5` | `15` (Karatsuba-5) | **`9`** (`X^5 - 3`) | **`-40.00%`** | `128b` (`< 2^128` in `u128`) |
| **`BLS12-377` `Fp2`** | `gnark` (`BW6-761`) & Go | $`377`$-bit (`X^2 + 5`) | `2` | `3` (Karatsuba-2) | **`3`** (`X^2 + 5`) | Optimal ($`2d-1`$) | Native wire & `[6]uint64` CIOS |
| **`BLS12-377` `Fp6`** | `gnark` (`BW6-761`) & Go | $`377`$-bit (`Y^6 + 5`) | `6` | `15` (`gnark` Toom3xK) / `18` | **`11`** (`{-5..4, inf}`) | **`-26.67%`** / **`-38.89%`** | `0`-add perm & `[6]uint64` CIOS |
| **`BLS12-377` `Fp12`** | `gnark` (`BW6-761`) & Go | $`377`$-bit (`W^{12} + 5`) | `12` | `45` (`gnark` R1CS) / `54` | **`23`** (`{-11..10, inf}`) | **`-48.89%`** / **`-57.41%`** | `0`-add perm & `[6]uint64` CIOS |

### B. Non-Native Limb-Carry Pareto Frontier ($`4\times 64`$-bit `BN254` & $`6\times 64`$-bit `BLS12-381` / `BLS12-377`)

*(Standalone non-native tower multiplication models over a 254-bit SNARK scalar field — explicitly counting every limb product, quotient witness, pre-multiplication `Reduce()`, and 2-limb carry range-check bit!)*

| Pairing Target | Emulated Limbs | Karatsuba Baseline | Certified Pareto Winner | Native $`\mathbb{F}_p`$ Muls | Pre-Mul `Reduce()` | Net Groth16 R1CS (Savings) | Net PlonK16 Gates (Savings) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`BN254` `Fp6`** | $`4 \times 64`$-bit | `Tower-18` (`15,150` R1CS) | **`Rank-11`** (`{-5..4, inf}`) | `18 -> 11` (`-38.89%`) | `0` | **`11,582` (`-23.55%`)** | **`2,037` (`-23.42%`)** |
| **`BN254` `Fp12`** | $`4 \times 64`$-bit | `Tower-54` (`44,619` R1CS) | **`CRT-30`** (`9` lin + `7` quad) | `54 -> 30` (`-44.44%`) | `0` | **`31,497` (`-29.41%`)** | **`6,171` (`-24.45%`)** |
| **`BN254` `Fp12`** *(Tower)* | $`4 \times 64`$-bit | `Tower-54` (`44,619` R1CS) | **`Tower-33`** (`Toom-6 x K-2`) | `54 -> 33` (`-38.89%`) | `0` | **`32,278` (`-27.66%`)** | **`6,229` (`-23.74%`)** |
| **`BLS12-381` `Fp6`** | $`6 \times 64`$-bit | `Tower-18` (`23,196` R1CS) | **`Rank-11`** (`{-5..4, inf}`) | `18 -> 11` (`-38.89%`) | `0` | **`17,081` (`-26.36%`)** | **`3,485` (`-27.26%`)** |
| **`BLS12-381` `Fp12`** | $`6 \times 64`$-bit | `Tower-54` (`68,032` R1CS) | **`CRT-30`** (`9` lin + `7` quad) | `54 -> 30` (`-44.44%`) | `0` | **`46,078` (`-32.27%`)** | **`10,235` (`-29.83%`)** |
| **`BLS12-377` `Fp6`** | $`6 \times 64`$-bit | `Tower-18` (`22,930` R1CS) | **`Rank-11`** (`{-5..4, inf}`) | `18 -> 11` (`-38.89%`) | `0` | **`16,839` (`-26.56%`)** | **`3,465` (`-27.36%`)** |
| **`BLS12-377` `Fp12`** | $`6 \times 64`$-bit | `Tower-54` (`66,534` R1CS) | **`CRT-30`** (`9` lin + `7` quad) | `54 -> 30` (`-44.44%`) | `0` | **`45,601` (`-31.46%`)** | **`10,394` (`-28.18%`)** |

---

## 2. Measured Production Upstream Compiler & Prover Benchmarks

To validate end-to-end SNARK/STARK compiler, prover, and verifier behavior beyond standalone cost models, we implemented, benchmarked, and adversarially verified **six live open upstream Pull Requests** across **`Consensys/gnark`** ([`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) and [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951)), **`Plonky3/Plonky3`** ([`Plonky3/Plonky3#2600`](https://github.com/Plonky3/Plonky3/pull/2600)), **`starkware-libs/proving` (`stwo`)** ([`starkware-libs/proving#9`](https://github.com/starkware-libs/proving/pull/9) and [`starkware-libs/proving#10`](https://github.com/starkware-libs/proving/pull/10)), and **`aleo-labs-protocol/snarkVM`** ([`aleo-labs-protocol/snarkVM#3908`](https://github.com/aleo-labs-protocol/snarkVM/pull/3908)).

### 2.1 [`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) (`perf/bls12377-bilinear-rank11-rank23`): Native 2-Chain `BLS12-377` over `BW6-761`

Live open PR: [`https://github.com/Consensys/gnark/pull/1950`](https://github.com/Consensys/gnark/pull/1950) (branch `perf/bls12377-bilinear-rank11-rank23` @ `5b09aa5`, base `38a87d1`). Compiled over `ecc.BW6_761.ScalarField()` (`std/algebra/native/fields_bls12377` & `sw_bls12377`). Replaces R1CS `Toom-3`/Karatsuba towers with pre-inverted rational folded Lagrange interpolation (`mulRank11` mod $`Y^6 + 5`$, `mulRank23` mod $`W^{12} + 5`$, sparse `mulBy01Rank10` & `mulBy01234Rank22`, `squareToom3`, and `square034Karatsuba`), while preserving `SCS` + `frontend.Committer` Schwartz–Zippel (`mulSZ`/`squareSZ`) bit-for-bit:

| `gnark` Circuit / Operation | R1CS (`master`) | R1CS (`#1950`) | R1CS $`\Delta`$ | SCS + Committer (`SZ`) | SCS (no Committer) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `fields_bls12377.E6.Mul` | `15` | **`11`** | **`-26.67%`** (`-4`) | `73 -> 73` | `66 -> 66` |
| `fields_bls12377.E6.Square` | `12` | **`10`** | **`-16.67%`** (`-2`) | `57 -> 57` | `43 -> 43` |
| `fields_bls12377.E6.MulBy01` | `15` | **`10`** | **`-33.33%`** (`-5`) | `67 -> 67` | `46 -> 46` |
| `fields_bls12377.E12.Mul` | `45` | **`23`** | **`-48.89%`** (`-22`) | `151 -> 151` | `228 -> 228` |
| `fields_bls12377.E12.Square` | `30` | **`22`** | **`-26.67%`** (`-8`) | `117 -> 117` | `156 -> 156` |
| `fields_bls12377.E12.MulBy034` | `30` | **`20`** | **`-33.33%`** (`-10`) | `129 -> 129` | `116 -> 102` (**`-12.07%`**) |
| `fields_bls12377.E12.MulBy01234` | `45` | **`22`** | **`-51.11%`** (`-23`) | `145 -> 145` | `206 -> 206` |
| `fields_bls12377.E12.Square034` | `21` | **`14`** | **`-33.33%`** (`-7`) | `91 -> 91` | `68 -> 40` (**`-41.18%`**) |
| `sw_bls12377.FinalExponentiation` | `6,319` | **`5,722`** | **`-9.45%`** (`-597`) | `24,370 -> 24,370` | `27,852 -> 27,852` |
| `sw_bls12377.MillerLoop` (`1`-pair) | `5,731` | **`4,544`** | **`-20.71%`** (`-1,187`) | `13,951 -> 13,951` | `21,264 -> 20,468` (`-3.74%`) |
| `sw_bls12377.Pair` (`1`-pair witness `G2`) | `12,050` | **`10,266`** | **`-14.80%`** (`-1,784`) | `38,278 -> 38,278` | `49,116 -> 48,320` (`-1.62%`) |
| `sw_bls12377.Pair` (`1`-pair `FixedQ`) | `10,165` | **`8,381`** | **`-17.55%`** (`-1,784`) | `33,855 -> 33,855` | `44,543 -> 43,570` (`-2.18%`) |
| `sw_bls12377.Pair` (`2`-pair `FixedQ`) | `12,205` | **`9,718`** | **`-20.38%`** (`-2,487`) | `38,802 -> 38,802` | `51,837 -> 49,933` (`-3.67%`) |
| `sw_bls12377.PairingCheck` (`2`-pair witness `G2`) | `10,109` | **`8,027`** | **`-20.60%`** (`-2,082`) | `24,208 -> 24,208` | `35,098 -> 33,502` (`-4.55%`) |
| **`sw_bls12377.PairingCheck` (`2`-pair `FixedQ`)** | `6,339` | **`4,257`** | **`-32.84%`** (`-2,082`) | `15,368 -> 15,368` | `25,942 -> 24,002` (`-7.48%`) |

### 2.2 [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951) (`perf/emulated-e12-bilinear-mvcheck`): Non-Native Emulated `BN254`, `BLS12-381` & `BW6-761`

Live open PR: [`https://github.com/Consensys/gnark/pull/1951`](https://github.com/Consensys/gnark/pull/1951) (branch `perf/emulated-e12-bilinear-mvcheck` @ `4a43edf`, base `38a87d1`). Compiled over `ecc.BN254.ScalarField()` (`std/math/emulated` + `fields_bn254` + `fields_bls12381` + `sw_bn254` + `sw_bls12381`). Combines **(1)** canonical monomial deduplication & zero-factor pruning in `polyMvPrep` (`6` zero coordinates of `cubicNonResiduePower` automatically pruned in `PairingCheck`), **(2)** exact `*big.Int` quotient bit-width range enforcement (`packLimbsWithWidth(ret[:nbQuoLimbs], quoBits)`), signed CRT low-carry bounds (`mvLowCarries`), and `kNeg` sign-bit elision when $`\mathrm{negMax} = 0`$, and **(3)** shared-commitment deferred evaluators `MulPolyModTrinomial12` (`1,152 -> 96` committed limbs on `BN254` `E12.Mul`, `1,728 -> 144` on `BLS12-381`, dispatching `20`–`23`-mul Even/Odd Vandermonde on R1CS/small-field extensions and $`\mathbb{Z}`$-isomorphic $`2\times 3\times 2`$ towers on PlonK) and `EvalSystem`:

| `gnark` Emulated Circuit (`ecc.BN254.ScalarField()`) | R1CS (`master`) | R1CS (`#1951`) | R1CS $`\Delta`$ | PlonK / SCS (`master`) | PlonK / SCS (`#1951`) | PlonK / SCS $`\Delta`$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `fields_bn254.E12.Mul` | `4,463` | **`3,894`** | **`-12.75%`** (`-569`) | `17,985` | **`16,149`** | **`-10.21%`** (`-1,836`) |
| `fields_bn254.E12.Square` | `3,886` | **`3,413`** | **`-12.17%`** (`-473`) | `15,795` | **`14,019`** | **`-11.24%`** (`-1,776`) |
| `fields_bn254.E12.MulBy01379` | `3,931` | **`3,521`** | **`-10.43%`** (`-410`) | `16,143` | **`14,474`** | **`-10.34%`** (`-1,669`) |
| `fields_bn254.E12.Expt` | `156,515` | **`131,980`** | **`-15.68%`** (`-24,535`) | `592,131` | **`498,959`** | **`-15.74%`** (`-93,172`) |
| `sw_bn254.FinalExponentiation` | `466,445` | **`399,198`** | **`-14.42%`** (`-67,247`) | `1,683,026` | **`1,443,121`** | **`-14.25%`** (`-239,905`) |
| **`sw_bn254.Pair` (`1`-pair witness `G2`)** | `836,825` | **`715,060`** | **`-14.55%`** (`-121,765`) | `3,027,526` | **`2,599,706`** | **`-14.13%`** (`-427,820`) |
| **`sw_bn254.Pair` (`1`-pair fixed `G2`)** | `720,474` | **`611,184`** | **`-15.17%`** (`-109,290`) | `2,608,111` | **`2,233,950`** | **`-14.35%`** (`-374,161`) |
| **`sw_bn254.PairingCheck` (`2`-pair)** | `736,147` | **`636,622`** | **`-13.52%`** (`-99,525`) | `2,624,114` | **`2,292,250`** | **`-12.65%`** (`-331,864`) |
| `fields_bls12381.E12.Mul` | `6,344` | **`5,789`** | **`-8.75%`** (`-555`) | `25,835` | **`24,084`** | **`-6.78%`** (`-1,751`) |
| `fields_bls12381.E12.Square` | `5,527` | **`5,068`** | **`-8.30%`** (`-459`) | `22,637` | **`20,946`** | **`-7.47%`** (`-1,691`) |
| `fields_bls12381.E12.MulBy02368` | `5,717` | **`5,293`** | **`-7.42%`** (`-424`) | `23,608` | **`21,897`** | **`-7.25%`** (`-1,711`) |
| `sw_bls12381.FinalExponentiation` | `856,526` | **`774,008`** | **`-9.63%`** (`-82,518`) | `3,185,072` | **`2,863,642`** | **`-10.09%`** (`-321,430`) |
| **`sw_bls12381.Pair` (`1`-pair witness `G2`)** | `1,323,407` | **`1,194,960`** | **`-9.71%`** (`-128,447`) | `4,881,141` | **`4,402,294`** | **`-9.81%`** (`-478,847`) |
| **`sw_bls12381.Pair` (`1`-pair fixed `G2`)** | `1,178,947` | **`1,061,176`** | **`-9.99%`** (`-117,771`) | `4,358,510` | **`3,925,500`** | **`-9.93%`** (`-433,010`) |
| **`sw_bls12381.PairingCheck` (`2`-pair)** | `825,838` | **`752,583`** | **`-8.87%`** (`-73,255`) | `2,958,308` | **`2,715,967`** | **`-8.19%`** (`-242,341`) |
| `internal/stats`: `pairing_bw6761` | `3,242,559` | **`3,100,024`** | **`-4.40%`** (`-142,535`) | `12,295,948` | **`11,687,119`** | **`-4.95%`** (`-608,829`) |
| `internal/stats`: `scalar_mul_G2_bn254` | `449,267` | **`416,348`** | **`-7.33%`** (`-32,919`) | `1,552,336` | **`1,410,982`** | **`-9.11%`** (`-141,354`) |
| `internal/stats`: `scalar_mul_P256` | `130,856` | **`118,536`** | **`-9.41%`** (`-12,320`) | `481,361` | **`428,120`** | **`-11.06%`** (`-53,241`) |

> **Cryptographic Soundness Hardening Included (`Consensys/gnark#1951`)**: During adversarial multi-agent review of `std/math/emulated/field_mul.go`, we uncovered and closed a malicious-prover excess-quotient-bit modulo-$`q`$ wrap-around vulnerability on small native fields ($`2t \ge F - 1`$, permitted by `NewField` since $`F \ge t + 3`$, e.g., $`t = 22`$ over 31-bit BabyBear $`q = 2013265921`$) where unconstrained high bits of a full-limb quotient witness $`k_0 < 2^t`$ allowed $`k_0 p_i - r_i = m_i q \equiv 0 \pmod{q}`$ (including degree-0 single-limb `checkZero` checks with zero carry limbs). Enforcing exact `quoBits = maxQuo.BitLen()` via `packLimbsWithWidth` and guarding uncapped CRT carry requirements eliminates the forgery while saving an additional `51,813` R1CS / `233,162` PlonK constraints on `BN254` pairing!

### 2.3 [`Plonky3/Plonky3#2600`](https://github.com/Plonky3/Plonky3/pull/2600) (`perf/min-rank-extension-algebra`): Minimum-Rank `ExtensionAlgebra` & `Complex<Mersenne31>`

Live open PR: [`https://github.com/Plonky3/Plonky3/pull/2600`](https://github.com/Plonky3/Plonky3/pull/2600) (branch `perf/min-rank-extension-algebra` @ `43c843c`, base `0d80373`). Adds **(1)** `#![no_std]` Winograd / Alder–Strassen $`(2D - 1)`$ minimum-rank multiplication and symmetric squaring kernels in `p3-field` (`T * V == denom * I` `const`-asserted in `i128` at compile time, zero heap/float), wired into `p3-air` via pointer-shared `Arc` `Algebra::linear_combinations` on `SymbolicExpression`, `SymbolicExpressionExt`, `ArithmeticExpression`, and `ArithmeticExpressionExt` (with `F::NEG_ONE` lowered to `Neg`/`Sub` for **`0` constant leaf multiplications**), and **(2)** branchless delayed-`u64` single-reduction-per-limb `Complex<Mersenne31>` (`CM31`, `QM31`, `M31^6`) kernels in `p3-mersenne-31`:

#### A. Criterion CPU Prover Throughput & Latency (`cargo +stable bench -p p3-mersenne-31 --bench extension -- --quick`)

| `p3-mersenne-31` Benchmark | Baseline (`0d80373`) | `perf` Branch (`43c843c`) | $`\Delta`$ / Speedup |
| :--- | :---: | :---: | :---: |
| **`QM31` `mul-throughput/100`** (per op) | `20.331 ns` | **`4.768 ns`** | **`-76.55%` (`4.26x`)** |
| **`QM31` `mul-latency/1000`** (per op) | `26.047 ns` | **`8.238 ns`** | **`-68.37%` (`3.16x`)** |
| **`QM31` `square`** | `13.396 ns` | **`5.476 ns`** | **`-59.12%` (`2.45x`)** |
| **`QM31` `inv`** | `81.627 ns` | **`41.559 ns`** | **`-49.09%` (`1.96x`)** |
| **`PackedQM31/square/dependent_64`** | `922.13 ns` | **`622.56 ns`** | **`-32.49%` (`1.48x`)** |
| **`M31^6` (`D=3`) `mul-throughput/100`** (per op) | `43.222 ns` | **`14.957 ns`** | **`-65.40%` (`2.89x`)** |
| **`M31^6` (`D=3`) `mul-latency/1000`** (per op) | `29.993 ns` | **`21.207 ns`** | **`-29.29%` (`1.41x`)** |
| **`M31^6` (`D=3`) `square`** | `26.702 ns` | **`11.709 ns`** | **`-56.15%` (`2.28x`)** |
| **`M31^6` (`D=3`) `inv`** | `116.52 ns` | **`61.828 ns`** | **`-46.94%` (`1.88x`)** |

#### B. `p3-air` Multi-Root Symbolic & Lowered Arithmetic DAG Constraint Multiplications

| `Plonky3` Extension (`p3-air` Multi-Root DAG) | `Sym` Mul Quadratic Muls | Mul $`\Delta`$ | `Sym` Square Quadratic Muls | Square $`\Delta`$ | `Arith` Mul `(Mul, Sq)` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `Complex<Mersenne31>` / `Goldilocks` Binomial (`D=2`) | `4 -> 3` | **`-25.00%`** | `3 -> 2` | **`-33.33%`** | `(3, 0)` |
| `Mersenne31` Binomial & `Goldilocks` `CubicTrinomial` (`D=3`) | `9 -> 5` | **`-44.44%`** | `9 -> 5` / `6 -> 5` | **`-44.44%` / `-16.67%`** | `(5, 0)` |
| **`BabyBear` / `KoalaBear` Binomial (`D=4`)** | **`16 -> 7`** | **`-56.25%`** | `10 -> 7` | **`-30.00%`** | `(7, 0)` |
| **`Mersenne31` `QM31` Tower (`D=4`, $`u^4 - 4u^2 + 5`$)** | **`16 -> 7`** | **`-56.25%`** | `8 -> 6` | **`-25.00%`** | `(7, 0)` |
| **`BabyBear` / `Goldilocks` Binomial (`D=5`)** | **`25 -> 9`** | **`-64.00%`** | `15 -> 9` | **`-40.00%`** | `(9, 0)` |
| **`KoalaBear` `QuinticTrinomial` (`D=5`, $`X^5 + X^2 - 1`$)** | **`26 -> 9`** | **`-65.38%`** | `17 -> 9` | **`-47.06%`** | `(9, 0)` |
| **`BabyBear` / `KoalaBear` Binomial (`D=8`)** | **`64 -> 15`** | **`-76.56%`** | `36 -> 15` | **`-58.33%`** | `(15, 0)` |

### 2.4 [`starkware-libs/proving#9`](https://github.com/starkware-libs/proving/pull/9) & [`#10`](https://github.com/starkware-libs/proving/pull/10) (`stwo`): `CM31`/`QM31` & Multi-Backend AIR Compression

Live open PRs: [`https://github.com/starkware-libs/proving/pull/9`](https://github.com/starkware-libs/proving/pull/9) (`perf/qm31-min-rank-and-verifier-ops` @ `149dcdf`, base `9bc8c8d`) and [`https://github.com/starkware-libs/proving/pull/10`](https://github.com/starkware-libs/proving/pull/10) (`fix/simd-base-column-into-cpu-vec-ub` @ `89e13e9`, fixing a `GlobalAlloc::dealloc` `align = 64 -> 4` UB / Windows `0xc0000374` crash in `BaseColumn::into_cpu_vec`). Accelerates scalar `CM31` and `QM31` arithmetic in `crates/stwo` (`2.71x` `QM31::mul`, `2.55x` `QM31::square`, plus public `const fn QM31::mul_rank7`) and replaces 20-mul schoolbook `QM31` expansion in `crates/airs` (`Qm31Ops` & `QM31AddMulOpcode`) across all 5 `[AIR-GENERATED]` Rust SIMD, Rust circuit verifier, and Cairo verifier components:

#### A. `stwo` Scalar CPU Throughput & Latency (`--release`, `core::hint::black_box`)

| `stwo` Operation (`crates/stwo`) | Baseline (`9bc8c8d`) | `perf` Branch (`149dcdf`) | $`\Delta`$ / Speedup | Kernel Summary |
| :--- | :---: | :---: | :---: | :--- |
| **`CM31::mul`** (8-way throughput) | `2.569 ns` | **`1.748 ns`** | **`-32.0%` (`1.47x`)** | `4 -> 3` `M31` muls (Karatsuba) |
| **`CM31::square`** (8-way throughput) | `2.329 ns` | **`2.033 ns`** | **`-12.7%` (`1.15x`)** | `4 -> 2` `M31` muls (`(a+b)(a-b), 2ab`) |
| **`QM31::mul` (`impl Mul`, 8-way)** | `13.004 ns` | **`4.797 ns`** | **`-63.1%` (`2.71x`)** | Delayed-`u64` outer Karatsuba (1 red/limb) |
| **`QM31::mul` (`impl Mul`, 1-way)** | `19.970 ns` | **`8.196 ns`** | **`-59.0%` (`2.44x`)** | Zero `u64` overflow across $`[0, P-1]^4`$ |
| **`QM31::mul_rank7` (`const fn`, 1-way)** | `19.970 ns` | **`12.616 ns`** | **`-36.8%` (`1.58x`)** | Exact `7`-mul $`u^4 - 4u^2 + 5 = 0`$ kernel |
| **`QM31::square` (8-way throughput)** | `13.717 ns` | **`5.376 ns`** | **`-60.8%` (`2.55x`)** | Specialized `7`-mul delayed-`u64` |
| **`QM31::square` (1-way latency)** | `22.127 ns` | **`9.824 ns`** | **`-55.6%` (`2.25x`)** | Strict canonicality $`\in [0, P-1]`$ |
| **`QM31::inverse`** | `103.504 ns` | **`101.218 ns`** | **`-2.2%`** | Add-only `pub const fn mul_by_r` |

#### B. `[AIR-GENERATED]` Multi-Backend Prover & Verifier Multiplication Reductions (`22 -> 9`, `-59.1%`)

| Generated Component / Compiled AIR Target (`proving`) | Muls Before (`9bc8c8d`) | Muls After (`149dcdf`) | Net $`\Delta`$ | Isolated `QM31` Product Muls |
| :--- | :---: | :---: | :---: | :---: |
| **Isolated `QM31` Product (`qm31_mul_expr_in_air`)** | `22` (`20` `Var*Var` + `2` `*2`) | **`9`** (`9` `Var*Var` + `0` `Const*Var`) | **`-13` (`-59.1%`)** | **`22 -> 9` (`-59.1%`)** |
| `crates/cairo-air/src/components/qm_31_add_mul_opcode.rs` (SIMD prover) | `39` | **`26`** | **`-13` (`-33.3%`)** | `22 -> 9` (`-59.1%`) |
| `crates/cairo_verifier/src/components/qm_31_add_mul_opcode.rs` (circuit) | `39` | **`26`** | **`-13` (`-33.3%`)** | `22 -> 9` (`-59.1%`) |
| `crates/circuit_prover/src/circuit_air/components/qm_31_ops.rs` (SIMD prover) | `42` | **`29`** | **`-13` (`-31.0%`)** | `22 -> 9` (`-59.1%`) |
| `crates/circuit_verifier/src/components/qm_31_ops.rs` (circuit verifier) | `42` | **`29`** | **`-13` (`-31.0%`)** | `22 -> 9` (`-59.1%`) |
| `stwo_cairo_verifier/crates/circuit_air/src/components/qm_31_ops.cairo` (Cairo) | `46` | **`33`** | **`-13` (`-28.3%`)** | `22 -> 9` (`-59.1%`) |

> **Backend Cost Dichotomy (`{0, +1, -1}` Karatsuba-9 vs `Rank-7`)**: In R1CS, PlonK, and `Plonky3`'s `p3-air`, scaling by a base-field constant $`c \in \mathbb{F}_p`$ has polynomial degree `0` (`0` multiplicative constraints), so Winograd / Alder–Strassen **`Rank-7`** (`7` `Var * Var` muls) is globally optimal (`16 -> 7`, `-56.25%`). Conversely, in StarkWare `proving`'s `air_code_gen` and `crates/circuits/src/ops.rs`, every non-unit `Const * Var` ($`c \notin \{0, 1\}`$) in `FeltExpr` lowers to an explicit `PackedM31 * PackedM31` SIMD mul in `SimdDomainEvaluator`, a `qm31_const * QM31` mul in `stwo_cairo_verifier`, and a `Qm31Ops::Mul` circuit gate in `stwo-circuits`! Under that cost model, `Rank-7` cuts `Var * Var` muls `20 -> 7` (`-65.0%`) but introduces `33` non-unit `Const * Var` muls (`22 -> 40` total muls), whereas **unimodular $`\{0, +1, -1\}`$ nested Karatsuba-9** (`qm31_mul_expr_in_air` with `AirBuilder::let_for_constraint` sharing) uses `9` `Var * Var` + `0` `Const * Var` = **`9` total multiplications (`-59.1%` vs `22`)** and `36` vs `38` total ops (`-5.3%`) across all three backends — while `qm31_mul_expr` and `qm31_mul_rank7_in_air` remain available for degree-0-folded backends.

### 2.5 Cairo Verifier (`cairo_gadgets/`), BitVM2 Tapscript (`bitvm2_qm31.py`), Zcash `Halo2` (`halo2_gadgets.rs`) & Zero-`sorry` Lean 4 Proofs (`lean4_certs/`)

- **Cairo Verifier Package ([`cairo_gadgets/`](./cairo_gadgets/README.md) — `zk_qm31_opt`, Scarb `2.21.0`)**: Implements canonical `u64`-backed Mersenne-31 single-fold arithmetic and compares `Schoolbook-16`, unimodular **`qm31_mul_karatsuba9`** / **`qm31_square_karatsuba6`** (`0` non-unit `Const * Var` muls, cutting 64-iter Cairo VM steps **`70,019 -> 51,641` (`-26.25%`)** and **`70,067 -> 39,738` (`-43.29%`)**), and **`qm31_mul_rank7`** (`7` `M31` variable-variable multiplications via $`\mathrm{QM31} \cong \mathbb{M}_{31}[v]/(v^4 - 4v^2 + 5)`$).
- **BitVM2 Tapscript `QM31` Simulator ([`zk_bilinear/bitvm2_qm31.py`](./zk_bilinear/bitvm2_qm31.py) & [`tests/test_bitvm2_qm31.py`](./tests/test_bitvm2_qm31.py))**: Models `BIP-342` 4-byte `CScriptNum`-safe (`|x| <= 2^31 - 1`) `OP_M31_ADD`, `OP_M31_SUB`, `OP_M31_SCALE_SMALL` (`{2, 3, 4, 6, 12}`), and witness-hinted `4x8`-bit `OP_M31_MUL`, cutting `OP_M31_MUL` **`16 -> 9 -> 7`** (**`-22.22%`** vs `Karatsuba-9`, **`-56.25%`** vs `Schoolbook-16`), witness stack items **`352 -> 198 -> 158`** (`-20.20%` vs `Karatsuba-9`), and Script opcodes **`17,880 -> 10,224 -> 9,447`** (`-7.60%` vs `Karatsuba-9`).
- **Zcash `Halo2` / `BLS12-381` & `Pasta` `#![no_std]` Module ([`rust_crates/src/halo2_gadgets.rs`](./rust_crates/src/halo2_gadgets.rs))**: Compile-time Vandermonde-verified generic `PrimeFieldOps` kernels (`Fp2` Rank-3, `Fp6` Rank-11, `Fp12` Rank-23, sparse Miller-loop `mul_by_014` **Rank-18 / Rank-19 / Rank-21**) plus exact `U1024` `Halo2LookupCostModel` (`FlexGate` + `RangeChip` over 255-bit `Pallas`/`Vesta`): **`CRT-30`** cuts non-native `BLS12-381` `Fp12` PlonKish cells by **`-24.49%` to `-29.85%`** (`0` pre-reductions vs `22` on naive `Rank-23`), and exact `quoBits` cuts `Pasta` wrong-field CRT cells by **`-9.94%` to `-13.05%`**.
- **Zero-`sorry` Core Lean 4 Formal Proof Suite ([`lean4_certs/`](./lean4_certs/README.md) — `ZkBilinearCerts`, `lean4:v4.36.0`)**: Pure Core Lean 4 (`0` external dependencies, clean scratch `lake build` in **`< 6s`**, `33` `#print axioms`-verified theorems with `0` `sorry` and `0` custom `axiom`s) proving universal `Int` & `mod (2^31 - 1)` equivalence of `Karatsuba-9`, `Rank-7`, and `Rank-6` squaring ([`Qm31Algebraic.lean`](./lean4_certs/ZkBilinearCerts/Qm31Algebraic.lean)), `u64` `dot4` / outer-Karatsuba non-overflow (`< 2^64`) and bitwise two-step Mersenne fold canonicality ([`M31Overflow.lean`](./lean4_certs/ZkBilinearCerts/M31Overflow.lean)), and non-native CRT quotient-bit soundness + BabyBear `b = 22` unmasked forgery certificates ([`CrtSoundness.lean`](./lean4_certs/ZkBilinearCerts/CrtSoundness.lean)).
- **Ecosystem Grant Proposals & Cloudflare Workers B2B Storefront**: Complete submission-ready specifications for **Zcash Community Grants** ([`monetization/grants/zcash_zcg_grant.md`](./monetization/grants/zcash_zcg_grant.md) — [`ZCG #590`](https://github.com/ZcashCommunityGrants/zcashcommunitygrants/issues/590)) and **Aleo Network Foundation Blueprint Grants** ([`monetization/grants/aleo_developer_grant.md`](./monetization/grants/aleo_developer_grant.md)), paired with our zero-dependency interactive Prover Cloud & L1 Verifier ROI Storefront ([`docs/index.html`](./docs/index.html)) configured for direct edge deployment via Cloudflare Workers Static Assets ([`wrangler.jsonc`](./wrangler.jsonc)).

### 2.6 [`aleo-labs-protocol/snarkVM#3908`](https://github.com/aleo-labs-protocol/snarkVM/pull/3908) (`perf/bls12-377-tower-opt`): `BLS12-377` 768-Bit Lazy Reduction & Karabina `cyclotomic_exp`

Live open PR: [`https://github.com/aleo-labs-protocol/snarkVM/pull/3908`](https://github.com/aleo-labs-protocol/snarkVM/pull/3908) (fork branch [`Impius-Lab/snarkVM` (`perf/bls12-377-tower-opt`)](https://github.com/Impius-Lab/snarkVM/tree/perf/bls12-377-tower-opt) @ `f5623bd`, base `b6e4725`; `#![forbid(unsafe_code)]` preserved, `0` new dependencies, `87/87` `snarkvm-curves` & `7/7` `snarkvm-fields` suites passing). Combines **(1)** compile-time-certified 768-bit (`[u64; 12]`) lazy Montgomery reduction (`Fp384::modulus_sq_mul(k)` `const`-asserted against $`k \le 151 < R / q = 152.328663`$, bounding `Fq12::mul` strictly to $`(0, 136 q^2] \subset (0, q \cdot R)`$ and cutting `6x6` blocks **`108 -> 66` (`-38.89%`)** and sparse line `mul_by_034`/`mul_by_014` **`78 -> 51` (`-34.62%`)**), **(2)** `f == 1` initial-bit `ell_from_one` specialization in `Bls12::miller_loop`, and **(3)** **Karabina (2013) compressed cyclotomic squaring** (`2` `Fp4` squarings per bit instead of `3`) with simultaneous stack-allocated Montgomery batch decompression (`1` `Fp2::inverse()` across all `6` non-trivial set bits of `X = 0x8508c00000000001`):

| `snarkvm-curves` Criterion Benchmark (`--release`) | Upstream `staging` (`b6e4725e`) | `snarkVM#3908` (`f5623bd`) | $`\Delta`$ / Speedup |
| :--- | :---: | :---: | :---: |
| `bls12_377: fq_square` | `29.290 ns` | **`26.123 ns`** | **`-10.81%` (`1.12x`)** |
| `bls12_377: fq2_mul_assign` | `114.73 ns` | **`88.310 ns`** | **`-23.03%` (`1.30x`)** |
| `bls12_377: fq2_square` | `77.452 ns` | **`71.424 ns`** | **`-7.78%` (`1.08x`)** |
| `bls12_377: fq12_mul_assign` | `2.8855 us` | **`2.1688 us`** | **`-24.84%` (`1.33x`)** |
| `bls12_377: fq12_square` | `1.9839 us` | **`1.6705 us`** | **`-15.80%` (`1.19x`)** |
| `bls12_377: fq12_inverse` | `6.4696 us` | **`5.3708 us`** | **`-16.98%` (`1.20x`)** |
| `bls12_377: pairing_miller_loop` | `274.88 us` | **`211.36 us`** | **`-23.11%` (`1.30x`)** |
| **`bls12_377: pairing_final_exponentiation`** | `508.02 us` | **`340.83 us`** | **`-32.91%` (`1.49x`)** |
| **`bls12_377: pairing_full`** | `881.49 us` | **`643.82 us`** | **`-26.96%` (`1.37x`, `-237.67 us`)** |

---

## 3. Mathematical Foundations

### 3.1 Why Bounded-Norm Bilinear Rank Beats Karatsuba in ZK Circuits
On a CPU, additions and multiplications both consume ALU cycles, making Karatsuba (`3` muls for quadratic, `9` for quartic, `18` for sextic, `54` for dodecic) a standard default. Inside **R1CS, PlonK custom gates, and degree-2 STARK AIRs**, fixed-constant linear combinations fold into $`(A, B, C)`$ matrices or degree-1 symbolic expressions for **zero multiplicative gates** — **unless** large evaluation constants trigger `u64` register overflow on CPU provers or inflate limb-carry range checks in non-native circuits!

Our engine synthesizes exact integer-rational bilinear decompositions:

```math
a \cdot b = \frac{1}{D} W_{\mathbb{Z}} \Big((U a) \odot (V b)\Big) \pmod{p}, \qquad U, V \in \mathbb{Z}^{r \times d},\; W_{\mathbb{Z}} \in \mathbb{Z}^{d \times r},\; \gcd(D, p) = 1,
```

co-optimizing bilinear rank $`r`$, input row product slack $`\Vert U_\ell\Vert_1 \Vert V_\ell\Vert_1`$, and output denominator/numerator weight $`\Vert W_{\mathbb{Z}, k}\Vert_1 + D`$.

### 3.2 Winograd (1977) / Alder–Strassen (1981) $`2d - 1`$ Lower Bound
Let $`K = \mathbb{F}_p[X]/(f(X))`$ with $`f`$ irreducible of degree $`d`$ over $`\mathbb{F}_p`$ (verified via Rabin's test in `zk_bilinear/fields.py`). Suppose $`m(x, y) = \sum_{\ell=1}^r u_\ell(x) v_\ell(y) w_\ell`$ computes multiplication in $`K`$. Because $`K`$ has zero left-annihilator, $`\mathrm{span}(u_1, \dots, u_r) = K^*`$; reordering so $`u_1, \dots, u_d`$ are linearly independent, $`\bigcap_{\ell=1}^{d-1} \ker(u_\ell) \subset K`$ has dimension $`1`$. Picking $`0 \ne x_0`$ in that intersection gives $`x_0 K \subseteq \mathrm{span}(w_d, \dots, w_r)`$. Since $`K`$ is a field, $`y \mapsto x_0 y`$ has full image $`K`$ of dimension $`d`$, forcing $`r - (d - 1) \ge d \iff \mathbf{r \ge 2d - 1}`$. Because $`\vert \mathbb{P}^1(\mathbb{F}_p)\vert = p + 1 \ge 2d - 1`$ for all ZK primes here, $`R_{\mathbb{F}_p}(K) = 2d - 1`$ is attained exactly.

### 3.3 Division-Free Unimodular ($`\det = \pm 1`$) Tower-to-Simple Isomorphisms
Stacked quadratic/cubic towers hide simple-extension structure. We prove explicit **integer unimodular ($`\det = \pm 1`$) basis transformations** (`T_from * T_to = I_d` over $`\mathbb{Z}`$, zero divisions):
- **`stwo` `QM31`**: $`u^2 = 2 + i \implies i = u^2 - 2 \implies \mathbf{u^4 - 4u^2 + 5 = 0}`$, mapping `(a0 + a1*i) + (b0 + b1*i)*u` $`\mapsto`$ `(a0 - 2*a1) + (b0 - 2*b1)*u + a1*u^2 + b1*u^3`.
- **`BLS12-377` ($`u^2 = -5, v^3 = u, w^2 = v`$)**: pure coordinate permutations (`det = -1`, **zero additions**) map `Fp6` to $`\mathbb{F}_p[Y]/(Y^6 + 5)`$ (`[0, 2, 4, 1, 3, 5]`) and `Fp12` to $`\mathbb{F}_p[W]/(W^{12} + 5)`$ (`[0, 6, 2, 8, 4, 10, 1, 7, 3, 9, 5, 11]`).
- **`BN254` ($`\xi = 9 + u`$)**: $`u = v^3 - 9 = w^6 - 9 \implies \mathbf{v^6 - 18v^3 + 82 = 0}`$ (`Fp6`) and $`\mathbf{w^{12} - 18w^6 + 82 = 0}`$ (`Fp12`).
- **`BLS12-381` ($`\xi = 1 + u`$)**: $`u = v^3 - 1 = w^6 - 1 \implies \mathbf{v^6 - 2v^3 + 2 = 0}`$ (`Fp6`) and $`\mathbf{w^{12} - 2w^6 + 2 = 0}`$ (`Fp12`).

### 3.4 The `56`-Bit Non-Native Limb-Carry Phase Transition (`CRT-30` vs `Rank-23`)
In standalone non-native emulated `Fp` towers over a 254-bit SNARK scalar field, packing two adjacent 64-bit limb equations (`128 + 64 = 192` bits, plus `4` bits for signed carry + co-addition) leaves **`56` bits** (`192 + 4 + 56 = 252 < 254`) for $`L \cdot \Vert U_\ell\Vert_1 \cdot \Vert V_\ell\Vert_1`$:
- Direct `Rank-23` Vandermonde over `Fp` (`{-11..10, inf}`) hits $`\vert -11\vert^{11} \approx 2^{38.1}`$ (`77`-bit slack $`> 56`$-bit), triggering **22 mandatory pre-multiplication `Reduce()` gadgets** (`34,444` R1CS on `BN254`). *(Conversely, inside `gnark`'s deferred polynomial-identity checker `MulPolyModTrinomial12`, `Rank-23` runs over native scalar-field evaluations $`a(\gamma), b(\gamma) \in \mathbb{F}_r`$ where linear combinations are free and no limb overflow occurs — cutting the deferred check from `210` to `23` `api.Mul`s!)*
- For direct non-native `Fp` multiplication gadgets, our **Cyclotomic/Quadratic CRT schedule `CRT-30`** (`9` small linear nodes `{-4..3, inf}` + `7` small/cyclotomic quadratic moduli $`\Phi_4, \Phi_3, \Phi_6, \dots`$) caps slack at **`45` bits ($`\le 56`$-bit limit, `0` pre-reductions!)** and $`D`$ at **`45.2` bits** (single-word output quotients!), slashing net Groth16 R1CS to **`31,497` (`-29.41%`)** on `BN254` and **`46,078` (`-32.27%`)** on `BLS12-381`.

---

## 4. Quickstart & Verification

All five local verification suites run deterministically offline without external network calls:

```powershell
# 1. Python algebraic & artifact audit + 23 unittest suites (109,000+ fuzz samples, BitVM2 & mutations)
.\.venv\Scripts\python.exe -m zk_bilinear.cli audit
.\.venv\Scripts\python.exe -m unittest discover -s tests -v

# 2. Cairo QM31 verifier gadget suite (`zk_qm31_opt`: Schoolbook-16, Karatsuba-9/6 & Rank-7)
Push-Location cairo_gadgets
scarb --offline test
Pop-Location

# 3. Pure Core Lean 4 formal soundness & bilinear optimality proofs (`0` sorry, `0` custom axioms)
Push-Location lean4_certs
lake build
Pop-Location

# 4. #![no_std] Rust & Zcash Halo2 / BLS12-381 / Pasta gadget tests + strict Clippy
cargo +stable test --manifest-path rust_crates/Cargo.toml
cargo +stable clippy --manifest-path rust_crates/Cargo.toml --all-targets -- -D warnings

# 5. Native Go gadget test suite (QM31, Plonky3, BN254, BLS12-381 & [6]uint64 CIOS BLS12-377)
Push-Location go_gadgets
go test -count=1 -v ./...
Pop-Location

# 6. Cloudflare Workers Static Assets B2B storefront dry-run bundle validation
npx --yes wrangler@latest deploy --dry-run
```

---

## 5. Repository Architecture

```text
zk-bilinear-opt/
├── zk_bilinear/
│   ├── fields.py           # Exact primes, Rabin irreducibility, reference towers & unimodular isomorphisms
│   ├── tensor_cert.py      # Basis-complete Z + Fp d^2 algebraic verifier + u64/u128 overflow checker
│   ├── cost_models.py      # Native R1CS/PlonK/AIR + gnark 2-limb carry-packed non-native R1CS/PlonK16 models
│   ├── pareto_search.py    # Vandermonde, Cyclotomic-CRT & Binomial-Tower synthesis (64 certified schedules)
│   ├── bitvm2_qm31.py      # BitVM2 BIP-342 Tapscript M31/QM31 verifier simulator (Schoolbook-16, K-9, Rank-7)
│   ├── codegen.py          # Deterministic #![no_std] Rust, Go math/big, [6]uint64 CIOS & R1CS JSON emitters
│   └── cli.py              # CLI (`audit`, `verify`, `generate-all`, `report`)
├── cairo_gadgets/          # Standalone Scarb Cairo package `zk_qm31_opt` (`src/lib.cairo`, 12/12 tests)
├── lean4_certs/            # Zero-sorry Core Lean 4 proofs (`Qm31Algebraic`, `M31Overflow`, `CrtSoundness`)
├── targets/
│   ├── qm31_stwo/          # Module A: StarkWare stwo QM31 (9 -> 7 muls, -22.22%, <2^63 u64-safe)
│   ├── plonky3_extensions/ # Module B: BabyBear^{4,5}, KoalaBear^{4,8}, Goldilocks^{2,4,5} JSON + Rust
│   └── pairing_towers/     # Module C: BN254, BLS12-381 & BLS12-377 Fp2/Fp6/Fp12 Pareto curves + certs
├── rust_crates/            # #![no_std] Rust crate (`src/lib.rs`, `src/generated.rs`, Zcash `src/halo2_gadgets.rs`)
├── go_gadgets/             # Native Go module (`math/big` gadgets + zero-alloc [6]uint64 CIOS `bls12377_fp.go`)
├── tests/                  # 23 unittest suites: Z/Fp basis proofs, BitVM2 traces, 109k+ fuzz & mutation tests
├── docs/
│   └── index.html          # Self-contained B2B storefront, Whop/USDC intake modal & ROI calculator
├── wrangler.jsonc          # Cloudflare Workers Static Assets edge config (`impius-lab-zk` -> `./docs`)
└── monetization/           # Benchmarks, grants (`zcash_zcg_grant.md`, `aleo_developer_grant.md`, AI4Math, ZK ESP) & B2B offer
```

---

## 6. Author & License

**Author**: Houssem Aguentil (`Aguentil H.`) — Impius-Lab (`2aghous94@gmail.com`) · [https://github.com/Impius-Lab/zk-bilinear-opt](https://github.com/Impius-Lab/zk-bilinear-opt)

Dual-licensed under either of **[MIT License](./LICENSE-MIT)** or **[Apache License, Version 2.0](./LICENSE-APACHE)** at your option.
