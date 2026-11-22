# ZK Ecosystem Public-Goods Grant Application: `zk-bilinear-opt`

**Target Grant Programs**: *Ethereum Foundation Ecosystem Support Program (ESP)* · *Starknet Foundation* · *Succinct (`SP1` / `Plonky3` Ecosystem)* · *Polygon Labs*  
**Applicant**: Houssem Aguentil (`Aguentil H.`) — Impius-Lab (`2aghous94@gmail.com`)  
**Repositories**: `https://github.com/Impius-Lab/zk-bilinear-opt` · `https://github.com/Impius-Lab/gnark`  
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

## 2. Completed Prototype & Live `Consensys/gnark` Compiler Benchmarks

Unlike speculative grant proposals, we have already built, certified, and open-sourced **both** the standalone `zk-bilinear-opt` synthesis suite (`64` schedules, **`3,706` exact $`\mathbb{Z}`$ and $`\mathbb{F}_p`$ basis-pair proofs**, `109,000` differential fuzz samples, `#![no_std]` Rust crate, and zero-alloc `[6]uint64` CIOS Montgomery Go gadgets) **and two live, test-passing `Consensys/gnark` branches**:

### A. Live `Consensys/gnark` `frontend.Compile` Benchmarks (`https://github.com/Impius-Lab/gnark`)

| Live `gnark` PR Branch & Circuit | R1CS (`master`) | R1CS (Ours) | R1CS $`\Delta`$ | PlonK / SCS (`master`) | PlonK / SCS (Ours) | PlonK / SCS $`\Delta`$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`perf/bls12377-bilinear-rank11-rank23`** (`BW6-761` native): `E6.Mul` | `15` | **`11`** | **`-26.67%`** | `73` (`SZ`) | `73` (`SZ`) | `0.00%` (untouched) |
| **`perf/bls12377-bilinear-rank11-rank23`**: `E12.Mul` / `MulBy01234` | `45` / `45` | **`23` / `22`** | **`-48.89%` / `-51.11%`** | `151` / `145` | `151` / `145` | `0.00%` (untouched) |
| **`perf/bls12377-bilinear-rank11-rank23`**: `sw_bls12377.Pair` (`1`-pair) | `12,050` | **`10,266`** | **`-14.80%`** (`-1,784`) | `38,278` | `38,278` | `0.00%` (`-1.62%` noCommit) |
| **`perf/bls12377-bilinear-rank11-rank23`**: `PairingCheck` (`2`-pair `FixedQ`) | `6,339` | **`4,257`** | **`-32.84%`** (`-2,082`) | `15,368` | `15,368` | `0.00%` (`-7.48%` noCommit) |
| **`perf/emulated-e12-bilinear-mvcheck`** (`BN254` scalar): `BN254 E12.Mul` | `4,463` | **`3,894`** | **`-12.75%`** (`-569`) | `17,985` | **`16,149`** | **`-10.21%`** (`-1,836`) |
| **`perf/emulated-e12-bilinear-mvcheck`**: `sw_bn254.Pair` (`1`-pair witness `G2`) | `836,825` | **`715,060`** | **`-14.55%`** (`-121,765`) | `3,027,526` | **`2,599,706`** | **`-14.13%`** (`-427,820`) |
| **`perf/emulated-e12-bilinear-mvcheck`**: `sw_bn254.Pair` (`1`-pair fixed `G2`) | `720,474` | **`611,184`** | **`-15.17%`** (`-109,290`) | `2,608,111` | **`2,233,950`** | **`-14.35%`** (`-374,161`) |
| **`perf/emulated-e12-bilinear-mvcheck`**: `sw_bn254.PairingCheck` (`2`-pair) | `736,147` | **`636,622`** | **`-13.52%`** (`-99,525`) | `2,624,114` | **`2,292,250`** | **`-12.65%`** (`-331,864`) |
| **`perf/emulated-e12-bilinear-mvcheck`**: `sw_bls12381.Pair` (`1`-pair witness `G2`) | `1,323,407` | **`1,194,960`** | **`-9.71%`** (`-128,447`) | `4,881,141` | **`4,402,294`** | **`-9.81%`** (`-478,847`) |
| **`perf/emulated-e12-bilinear-mvcheck`**: `pairing_bw6761` (`internal/stats`) | `3,242,559` | **`3,100,024`** | **`-4.40%`** (`-142,535`) | `12,295,948` | **`11,687,119`** | **`-4.95%`** (`-608,829`) |

*(Bonus Public-Good Security Impact: While auditing `gnark`'s `std/math/emulated/field_mul.go`, we also uncovered and fixed a malicious-prover excess-quotient-bit modulo-$`q`$ wrap-around vulnerability on wide limbs over small native fields such as BabyBear where $`2t \ge F - 1`$, enforcing exact `quoBits` via `packLimbsWithWidth` and guarding uncapped CRT carry bounds.)*

### B. Native STARK / Recursive AIR & Emulated Limb-Carry Pareto Certificates (`zk-bilinear-opt`)

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

### Milestone 1 — Production `Plonky3` & `stwo` Recursive AIR Gadgets (Weeks 1–5 · \$20,000)
- Integrate `mul_qm31_rank7` into `stwo` recursive AIR / Cairo-verifier components and Bitcoin script / BitVM2 `QM31` gadgets (cutting `QM31` script multiplication opcodes by `-22.22%`).
- Ship drop-in `p3-field` / `AirBuilder` extension traits for `BabyBear^{4,5}`, `KoalaBear^{4,8}`, and `Goldilocks^{4,5}` with SIMD `AVX2`/`AVX-512`/`NEON` packed-field witness benchmarks.
- **Acceptance Gate**: End-to-end recursive FRI / DEEP quotient benchmark + upstream PRs opened on `Plonky3/Plonky3` and `starkware-libs/stwo`.

### Milestone 2 — Upstream `Consensys/gnark` PR Shepherding, `BW6-761` Extension & Halo2 Port (Weeks 6–11 · \$22,000)
- Shepherd our two completed `Consensys/gnark` branches (`perf/bls12377-bilinear-rank11-rank23` and `perf/emulated-e12-bilinear-mvcheck`) through upstream maintainer review, extend shared `EvalSystem` / `Rank-11` `E6` evaluators to emulated `BW6-761` (`fields_bw6761`) and `BLS12-377` (`emulated`), and port `CRT-30` / `Rank-11` non-native pairing gadgets to `halo2wrong` (Scroll / Axiom / Aztec PlonKish lookup tables).
- **Acceptance Gate**: Upstream `Consensys/gnark` PRs submitted & green + reproducible `halo2wrong` `BN254`/`BLS12-381` lookup-table benchmark suite.

### Milestone 3 — Formal Lean 4 Soundness Proofs & Binary-Tower (`Binius`) Extension (Weeks 12–16 · \$18,000)
- Formalize all `64` integer-rational certificates, `u64`/`u128` register bounds, and `gnark` CRT carry/quotient soundness inequalities in **Lean 4** so security auditors have machine-checked soundness guarantees.
- Add characteristic-2 Wiedemann / Chudnovsky tower Pareto schedules for `Binius` ($`\mathbb{F}_{2^{128}}`$ tower gadgets).
- **Acceptance Gate**: Zero-`sorry` Lean 4 build + final public audit & benchmark report.

---

## 4. Ecosystem Impact

Cutting native 2-chain pairing checks by **`-32.84%`**, non-native `BN254`/`BLS12-381` pairing verifiers by **`-9.71%` to `-15.17%`** (`-121k` to `-478k` constraints per pairing!), and STARK recursive extension gates by **`-22.22%` to `-44.44%`** directly lowers L2 proving cloud spend, recursion latency, L1 wrapper costs, and BitVM2 tapscript size across the entire ZK ecosystem.
