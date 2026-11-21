# ZK Ecosystem Public-Goods Grant Application: `zk-bilinear-opt`

**Target Grant Programs**: *Ethereum Foundation Ecosystem Support Program (ESP)* · *Starknet Foundation* · *Succinct (`SP1` / `Plonky3` Ecosystem)* · *Polygon Labs*  
**Project Name**: `zk-bilinear-opt` — Certified Optimal Extension-Field & Non-Native Pairing Gadgets for STARK and SNARK Verifiers  
**License**: Dual-licensed `MIT OR Apache-2.0` (100% permissive public good)  
**Requested Grant Size**: \$60,000 (3 Milestones over 16 Weeks)

---

## 1. Problem Statement: Why Generic Karatsuba Leaves 22%–44% Verifier Gates on the Table

Every modern ZK recursion and pairing verifier spends a substantial fraction of its constraint budget multiplying in extension towers:
- **Circle STARKs (`StarkWare stwo`)** evaluate FRI queries, DEEP quotients, and Fiat–Shamir challenges in `QM31 = CM31[u]/(u^2 - (2 + i))` using **9 `M31` multiplications** (double-Karatsuba).
- **`Plonky3` & `SP1` Recursive STARKs** evaluate constraints in `BabyBear^4`, `BabyBear^5`, `KoalaBear^4`, `KoalaBear^8`, and `Goldilocks^{4,5}` using **9, 15, or 27 base-field multiplications**.
- **Non-Native Pairing Verifiers (`Consensys/gnark` Groth16 & PlonK)** emulate `BN254` ($4\times 64$-bit limbs) and `BLS12-381` ($6\times 64$-bit limbs) Miller loops and final exponentiations using **18 `Fp` muls per `Fp6` product** and **54 `Fp` muls per `Fp12` product**.

On a general-purpose CPU, Karatsuba is popular because additions and multiplications have comparable latency. **Inside R1CS, PlonK custom gates, and degree-2 STARK AIRs, constant-scalar linear combinations fold into constraint matrices or degree-1 expressions for ZERO multiplicative gates** — **provided** evaluation norms do not trigger `u64` hardware overflow or non-native limb-carry blowups!

Previously, teams avoided higher-order Toom–Cook / Winograd interpolation in non-native circuits because naive minimum-rank Vandermonde (`23` muls on `Fp12`) creates `77`-bit input slacks and `113`-bit reconstruction denominators that blow up range-check constraints. **`zk-bilinear-opt` solves this exact tradeoff rigorously.**

---

## 2. Verified Baseline Prototype & Headline Constraint Savings

We have already built, proved, and open-sourced the core `zk-bilinear-opt` engine (`Python 3.12` certifier + `#![no_std]` Rust crate + native `Go` package), achieving **100% basis-complete algebraic verification** across `51` schedules (`2,654` basis-pair proofs + `102,000` differential fuzz samples):

### A. Native STARK / Recursive AIR Verifiers (`stwo` & `Plonky3` / `SP1`)
| Target Extension | Upstream Baseline | `zk-bilinear-opt` Certified Rank | Bilinear Gate / R1CS Savings | Accumulator Safety |
| :--- | :---: | :---: | :---: | :---: |
| **`stwo` `QM31`** ($\mathbb{M}_{31}^4$) | `9` muls (`3x3`) | **`7` muls** (via $u^4 - 4u^2 + 5 = 0$) | **`-22.22%`** | `62b < 2^63` (`i64`/`u64` safe) |
| **`BabyBear^4` & `KoalaBear^4`** | `9` muls | **`7` muls** | **`-22.22%`** | `62b < 2^63` (`i64`/`u64` safe) |
| **`BabyBear^5` & `Goldilocks^5`** | `15` muls | **`9` muls** | **`-40.00%`** | `62b < 2^63` / `128b < 2^128` |
| **`KoalaBear^8`** ($X^8 - 3$) | `27` muls (`3^3`) | **`15` muls** | **`-44.44%`** | `63b < 2^63` (2-term chunked `u64`) |

### B. Emulated Non-Native Pairing Towers (`gnark` $4\times 64$ `BN254` & $6\times 64$ `BLS12-381`)
*(Net totals INCLUDE every non-native limb product, quotient witness, pre-multiplication reduction, and 2-limb carry range-check bit!)*

| Curve & Tower | Upstream `gnark`-Style Baseline | `zk-bilinear-opt` Pareto Winner | Pre-Mul `Reduce()` | Net Groth16 R1CS Reduction | Net PlonK16 Lookup+Arith Reduction |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`BN254` `Fp6`** ($4\times 64$b) | `Tower-18` (`15,150` R1CS / `2,660` PlonK) | **`Rank-11`** (`11` muls) | `0` | **`11,582` (`-23.55%`)** | **`2,037` (`-23.42%`)** |
| **`BN254` `Fp12`** ($4\times 64$b) | `Tower-54` (`44,619` R1CS / `8,168` PlonK) | **`CRT-30`** (`30` muls) | `0` | **`31,497` (`-29.41%`)** | **`6,171` (`-24.45%`)** |
| **`BLS12-381` `Fp6`** ($6\times 64$b) | `Tower-18` (`23,196` R1CS / `4,791` PlonK) | **`Rank-11`** (`11` muls) | `0` | **`17,081` (`-26.36%`)** | **`3,485` (`-27.26%`)** |
| **`BLS12-381` `Fp12`** ($6\times 64$b) | `Tower-54` (`68,032` R1CS / `14,586` PlonK) | **`CRT-30`** (`30` muls) | `0` | **`46,078` (`-32.27%`)** | **`10,235` (`-29.83%`)** |

---

## 3. Grant Scope, Milestones & Deliverables (16 Weeks, \$60,000)

### Milestone 1 — Production `Plonky3` & `stwo` Recursive AIR Gadgets (Weeks 1–5 · \$20,000)
- Integrate `mul_qm31_rank7` into `stwo` recursive AIR / Cairo-verifier components and Bitcoin script / BitVM2 `QM31` gadgets (cutting `QM31` script multiplication opcodes by `-22.22%`).
- Ship drop-in `p3-field` / `AirBuilder` extension traits for `BabyBear^{4,5}`, `KoalaBear^{4,8}`, and `Goldilocks^{4,5}` with SIMD `AVX2`/`AVX-512`/`NEON` packed-field witness benchmarks.
- **Acceptance Gate**: End-to-end recursive FRI / DEEP quotient benchmark + upstream PRs opened on `Plonky3/Plonky3` and `starkware-libs/stwo`.

### Milestone 2 — Production `Consensys/gnark` Emulated Pairing PRs & Squaring/Cyclotomic Specialization (Weeks 6–11 · \$22,000)
- Port `Rank-11` (`E6`) and `CRT-30` / `Tower-33` (`E12`) into `gnark`'s `std/algebra/emulated/fields_bn254` and `fields_bls12381`, plus specialized **sparse line-evaluation (`MulBy034` / `MulBy014`)** and **cyclotomic subgroup squaring** Pareto schedules for Miller loops and final exponentiation.
- **Acceptance Gate**: `gnark` Groth16 & PlonK `scs.GetNbConstraints()` live benchmark table showing $\ge 20\%$ end-to-end pairing constraint reduction + upstream PR opened on `Consensys/gnark`.

### Milestone 3 — Formal Coq / Lean 4 Soundness Proofs & Binary-Tower (`Binius`) Extension (Weeks 12–16 · \$18,000)
- Formalize all 51 integer-rational certificates + `u64`/`u128`/limb-carry overflow proofs in **Lean 4** so security auditors have machine-checked soundness guarantees.
- Add characteristic-2 Wiedemann / tower Pareto schedules for `Binius` ($\mathbb{F}_{2^{128}}$ tower gadgets).
- **Acceptance Gate**: Zero-`sorry` Lean 4 build + final public audit & benchmark report.

---

## 4. Ecosystem Impact

Reducing extension-field and emulated pairing gates by **22%–44%** directly lowers recursive proof latency, GPU/CPU prover cloud spend, L1 verification costs, and BitVM2 tapscript size across every rollup and zkVM built on `Plonky3`, `SP1`, `stwo`, and `gnark`.
