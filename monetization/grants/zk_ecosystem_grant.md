# ZK Ecosystem Public-Goods Grant Application: `zk-bilinear-opt`

**Target Grant Programs**: *Ethereum Foundation Ecosystem Support Program (ESP)* · *Starknet Foundation* · *Succinct (`SP1` / `Plonky3` Ecosystem)* · *Polygon Labs*  
**Applicant**: Houssem Aguentil (`Aguentil H.`) — Impius-Lab (`2aghous94@gmail.com`)  
**Repositories & Live PRs**: `https://github.com/Impius-Lab/zk-bilinear-opt` · [`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) · [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951) · `https://github.com/Impius-Lab/Plonky3` · `https://github.com/Impius-Lab/proving`  
**Project Name**: `zk-bilinear-opt` — Certified Optimal Extension-Field & Non-Native Pairing Gadgets for STARK and SNARK Verifiers  
**License**: Dual-licensed `MIT OR Apache-2.0` (100% permissive public good)  
**Requested Grant Size**: \$60,000 (3 Milestones over 16 Weeks)

---

## 1. Problem Statement: Why Generic Karatsuba & Unshared `Eval` Leave 14%–51% Verifier Gates on the Table

Every modern ZK recursion and pairing verifier spends a substantial fraction of its constraint budget multiplying in extension towers:
- **Circle STARKs (`StarkWare stwo`)** evaluate FRI queries, DEEP quotients, and Fiat–Shamir challenges in `QM31 = CM31[u]/(u^2 - (2 + i))` using **9 `M31` multiplications** (double-Karatsuba).
- **`Plonky3` & `SP1` Recursive STARKs** evaluate constraints in `BabyBear^4`, `BabyBear^5`, `KoalaBear^4`, `KoalaBear^8`, and `Goldilocks^{4,5}` using **9, 15, or 27 base-field multiplications**.
- **2-Chain Recursive Pairing Verifiers (`Consensys/gnark` `BLS12-377` over `BW6-761`)** compile Groth16 R1CS `E6.Mul` (`15` muls) and `E12.Mul` (`45` muls) via `Toom-3` and Karatsuba towers instead of minimum-rank $`2d - 1`$ rational interpolation (`11` and `23` muls).
- **Non-Native Emulated Pairing Verifiers (`Consensys/gnark` `BN254`, `BLS12-381`, `BW6-761`)** emit 12 separate `mvCheck` commitments per `E12` product (`1,152`–`1,728` committed limbs and up to `210` deferred multiplications) with heuristic `+1 bit per term` quotient/carry bounds.

On a general-purpose CPU, Karatsuba is popular because additions and multiplications have comparable latency. **Inside R1CS, PlonK custom gates, and degree-2 STARK AIRs, constant-scalar linear combinations fold into constraint matrices or degree-1 expressions for ZERO multiplicative gates** — **provided** evaluation norms do not trigger `u64` hardware overflow or non-native limb-carry blowups!

---

## 2. Completed Prototype & Live Upstream Compiler / Prover Benchmarks

Unlike speculative grant proposals, we have already built, certified, and open-sourced **both** the standalone `zk-bilinear-opt` synthesis suite (`64` schedules, **`3,706` exact $`\mathbb{Z}`$ and $`\mathbb{F}_p`$ basis-pair proofs**, `109,000` differential fuzz samples, `#![no_std]` Rust crate, and zero-alloc `[6]uint64` CIOS Montgomery Go gadgets) **and four live, test-passing upstream integrations** across `Consensys/gnark` (open PRs [`#1950`](https://github.com/Consensys/gnark/pull/1950) & [`#1951`](https://github.com/Consensys/gnark/pull/1951)), `Plonky3/Plonky3` (`perf/min-rank-extension-algebra` @ `43c843c`), and `starkware-libs/proving` (`perf/qm31-min-rank-and-verifier-ops` @ `149dcdf`):

### A. Live Open `Consensys/gnark` Pull Requests ([`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) & [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951))

| Live `gnark` PR & Circuit | R1CS (`master`) | R1CS (Ours) | R1CS $`\Delta`$ | PlonK / SCS (`master`) | PlonK / SCS (Ours) | PlonK / SCS $`\Delta`$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **[`#1950`](https://github.com/Consensys/gnark/pull/1950)** (`BW6-761` native): `E6.Mul` | `15` | **`11`** | **`-26.67%`** | `73` (`SZ`) | `73` (`SZ`) | `0.00%` (untouched) |
| **[`#1950`](https://github.com/Consensys/gnark/pull/1950)**: `E12.Mul` / `MulBy01234` | `45` / `45` | **`23` / `22`** | **`-48.89%` / `-51.11%`** | `151` / `145` | `151` / `145` | `0.00%` (untouched) |
| **[`#1950`](https://github.com/Consensys/gnark/pull/1950)**: `sw_bls12377.Pair` (`1`-pair) | `12,050` | **`10,266`** | **`-14.80%`** (`-1,784`) | `38,278` | `38,278` | `0.00%` (`-1.62%` noCommit) |
| **[`#1950`](https://github.com/Consensys/gnark/pull/1950)**: `PairingCheck` (`2`-pair `FixedQ`) | `6,339` | **`4,257`** | **`-32.84%`** (`-2,082`) | `15,368` | `15,368` | `0.00%` (`-7.48%` noCommit) |
| **[`#1951`](https://github.com/Consensys/gnark/pull/1951)** (`BN254` scalar): `BN254 E12.Mul` | `4,463` | **`3,894`** | **`-12.75%`** (`-569`) | `17,985` | **`16,149`** | **`-10.21%`** (`-1,836`) |
| **[`#1951`](https://github.com/Consensys/gnark/pull/1951)**: `sw_bn254.Pair` (`1`-pair witness `G2`) | `836,825` | **`715,060`** | **`-14.55%`** (`-121,765`) | `3,027,526` | **`2,599,706`** | **`-14.13%`** (`-427,820`) |
| **[`#1951`](https://github.com/Consensys/gnark/pull/1951)**: `sw_bn254.Pair` (`1`-pair fixed `G2`) | `720,474` | **`611,184`** | **`-15.17%`** (`-109,290`) | `2,608,111` | **`2,233,950`** | **`-14.35%`** (`-374,161`) |
| **[`#1951`](https://github.com/Consensys/gnark/pull/1951)**: `sw_bn254.PairingCheck` (`2`-pair) | `736,147` | **`636,622`** | **`-13.52%`** (`-99,525`) | `2,624,114` | **`2,292,250`** | **`-12.65%`** (`-331,864`) |
| **[`#1951`](https://github.com/Consensys/gnark/pull/1951)**: `sw_bls12381.Pair` (`1`-pair witness `G2`) | `1,323,407` | **`1,194,960`** | **`-9.71%`** (`-128,447`) | `4,881,141` | **`4,402,294`** | **`-9.81%`** (`-478,847`) |
| **[`#1951`](https://github.com/Consensys/gnark/pull/1951)**: `pairing_bw6761` (`internal/stats`) | `3,242,559` | **`3,100,024`** | **`-4.40%`** (`-142,535`) | `12,295,948` | **`11,687,119`** | **`-4.95%`** (`-608,829`) |

*(Bonus Public-Good Security Impact: While auditing `gnark`'s `std/math/emulated/field_mul.go` for [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951), we also uncovered and fixed a malicious-prover excess-quotient-bit modulo-$`q`$ wrap-around vulnerability on wide limbs over small native fields such as BabyBear where $`2t \ge F - 1`$, enforcing exact `quoBits` via `packLimbsWithWidth` and guarding uncapped CRT carry bounds.)*

### B. Live `Plonky3` & StarkWare `proving` (`stwo`) Prover & AIR Constraint Benchmarks

| Upstream Branch & Target | Upstream Baseline | Measured (`perf` Branch) | Verified Speedup / Savings |
| :--- | :---: | :---: | :---: |
| **`Plonky3` (`43c843c`)**: `p3-mersenne-31` Criterion `QM31` `mul-throughput` / `latency` | `20.331 ns` / `26.047 ns` | **`4.768 ns` / `8.238 ns`** | **`4.26x` (`-76.55%`) / `3.16x` (`-68.37%`)** |
| **`Plonky3` (`43c843c`)**: Criterion `QM31` `square` / `inv` & `PackedQM31` `square` | `13.396` / `81.627` / `922.13 ns` | **`5.476` / `41.559` / `622.56 ns`** | **`2.45x` / `1.96x` / `1.48x`** |
| **`Plonky3` (`43c843c`)**: Criterion `M31^6` `mul-throughput` / `square` / `inv` | `43.222` / `26.702` / `116.52 ns` | **`14.957` / `11.709` / `61.828 ns`** | **`2.89x` / `2.28x` / `1.88x`** |
| **`Plonky3` (`43c843c`)**: `p3-air` DAG Quadratic Muls (`D=4` & `QM31` / `D=5` / `D=8`) | `16` / `25`–`26` / `64` | **`7` / `9` / `15`** | **`-56.25%` / `-64.0%`–`-65.4%` / `-76.56%`** |
| **StarkWare `proving` (`149dcdf`)**: `stwo` `CM31::mul` & `QM31::mul` (8-way / 1-way) | `2.569 ns` & `13.004` / `19.970 ns` | **`1.748 ns` & `4.797` / `8.196 ns`** | **`1.47x` & `2.71x` / `2.44x`** |
| **StarkWare `proving` (`149dcdf`)**: `stwo` `QM31::square` (8-way / 1-way) | `13.717 ns` / `22.127 ns` | **`5.376 ns` / `9.824 ns`** | **`2.55x` (`-60.8%`) / `2.25x` (`-55.6%`)** |
| **StarkWare `proving` (`149dcdf`)**: `[AIR-GENERATED]` `QM31` Muls (SIMD, Cairo & Circuits) | `22` (`39` / `42` / `46` per gate) | **`9`** (**`26` / `29` / `33`** per gate) | **`-59.1%`** (`-13` muls across all 5 files) |

### C. Standalone Native STARK / Recursive AIR & Emulated Limb-Carry Pareto Certificates (`zk-bilinear-opt`)

| Target Extension | Upstream Baseline | `zk-bilinear-opt` Certified Winner | Gate / R1CS Savings | Safety Certificate |
| :--- | :---: | :---: | :---: | :--- |
| **`stwo` `QM31`** ($`\mathbb{M}_{31}^4`$) | `9` muls (`3x3`) | **`7` muls** ($`u^4 - 4u^2 + 5 = 0`$) | **`-22.22%`** | `62b < 2^63` (`i64`/`u64` safe) |
| **`BabyBear^4` & `KoalaBear^4`** | `9` muls | **`7` muls** | **`-22.22%`** | `62b < 2^63` (`i64`/`u64` safe) |
| **`BabyBear^5` & `Goldilocks^5`** | `15` muls | **`9` muls** | **`-40.00%`** | `62b < 2^63` / `128b < 2^128` |
| **`KoalaBear^8`** ($`X^8 - 3`$) | `27` muls (`3^3`) | **`15` muls** | **`-44.44%`** | `63b < 2^63` (2-term chunked `u64`) |
| **`BLS12-377` `Fp6` & `Fp12`** (native / Go) | `15` / `45` `gnark` R1CS | **`Rank-11` / `Rank-23`** | **`-26.67%` / `-48.89%`** | `0`-add perm + `[6]uint64` CIOS |
| **Standalone `BN254` & `BLS12-381` `Fp12`** | `Tower-54` (`44.6k` / `68.0k`) | **`CRT-30`** (`30` muls, `0` pre-red) | **`-29.41%` / `-32.27%`** | `<= 252`-bit 2-limb SNARK safe |

---

## 3. Grant Scope, Milestones & Deliverables (16 Weeks, \$60,000)

### Milestone 1 — Upstream `Plonky3` & StarkWare `proving` (`stwo`) PR Shepherding, SIMD Packed Kernels & BitVM2 Gadgets (Weeks 1–5 · \$20,000)
- Shepherd our completed `Plonky3/Plonky3` (`perf/min-rank-extension-algebra` @ `43c843c`) and `starkware-libs/proving` (`perf/qm31-min-rank-and-verifier-ops` @ `149dcdf`) branches through upstream maintainer review.
- Extend vectorized SIMD `AVX2`/`AVX-512`/`NEON` packed-field multiplication/squaring kernels (`PackedQM31` & `MontyField31` binomial towers) and ship Bitcoin script / BitVM2 `QM31` `Rank-7` gadgets (`-22.22%` tapscript `M31` muls).
- **Acceptance Gate**: Upstream PRs reviewed on `Plonky3/Plonky3` and `starkware-libs/proving` + end-to-end recursive FRI / BitVM2 script benchmark suite.

### Milestone 2 — Upstream `Consensys/gnark` `#1950` / `#1951` Landing, `BW6-761` Extension & Halo2 Port (Weeks 6–11 · \$22,000)
- Shepherd our two live open `Consensys/gnark` PRs ([`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) and [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951)) through maintainer review, extend shared `EvalSystem` / `Rank-11` `E6` evaluators to emulated `BW6-761` (`fields_bw6761`) and `BLS12-377` (`emulated`), and port `CRT-30` / `Rank-11` non-native pairing gadgets to `halo2wrong` (Scroll / Axiom / Aztec PlonKish lookup tables).
- **Acceptance Gate**: Upstream `Consensys/gnark` PRs merged/green + reproducible `halo2wrong` `BN254`/`BLS12-381` lookup-table benchmark suite.

### Milestone 3 — Formal Lean 4 Soundness Proofs & Binary-Tower (`Binius`) Extension (Weeks 12–16 · \$18,000)
- Formalize all `64` integer-rational certificates, `u64`/`u128` register bounds, and `gnark` CRT carry/quotient soundness inequalities in **Lean 4** so security auditors have machine-checked soundness guarantees.
- Add characteristic-2 Wiedemann / Chudnovsky tower Pareto schedules for `Binius` ($`\mathbb{F}_{2^{128}}`$ tower gadgets).
- **Acceptance Gate**: Zero-`sorry` Lean 4 build + final public audit & benchmark report.

---

## 4. Ecosystem Impact

Cutting native 2-chain pairing checks by **`-32.84%`** ([`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950)), non-native `BN254`/`BLS12-381` pairing verifiers by **`-9.71%` to `-15.17%`** (`-121k` to `-478k` constraints per pairing, [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951)), Circle STARK `QM31` CPU prover throughput by **`2.71x` (`stwo`) to `4.26x` (`Plonky3`)**, and STARK AIR / verifier extension multiplications by **`-56.25%` to `-76.56%`** (`p3-air`) and **`-59.1%`** (`proving` SIMD, Cairo & `stwo-circuits`) directly lowers L2 proving cloud spend, recursion latency, L1 wrapper costs, and BitVM2 tapscript size across the entire ZK ecosystem.
