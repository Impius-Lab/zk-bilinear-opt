# Aleo Network Foundation Developer Grants (`Blueprint` Tier) Proposal — `snarkvm-bilinear-opt`

**Applicant**: Houssem Aguentil (`Individual` · `Independent Researcher` · `Impius-Lab` · `2aghous94@gmail.com` · `Alger, Algeria`)  
**Grant Track & Tier**: **Aleo Developer Grants — `Blueprint` Grant** (`USD 10,000 – USD 100,000` Core Infrastructure & Cryptographic Tooling Track)  
**Requested Grant Amount**: **USD 30,000** (`USD 0` upfront · 2 Delivery-Gated Milestones over 8 Weeks: M1 `USD 15,000` + M2 `USD 15,000`)  
**License**: `Apache-2.0` (dual-licensed `MIT OR Apache-2.0`, 100% compatible with [`ProvableHQ/snarkVM`](https://github.com/ProvableHQ/snarkVM) and [`ProvableHQ/leo`](https://github.com/ProvableHQ/leo))

---

## 0. Verified Live Aleo Developer Grants Portal & Step-by-Step Submission Guide

*(Verified directly against the live Aleo Network Foundation Developer Grants portal at [`https://aleo.org/grants`](https://aleo.org/grants) — formatted field-by-field for immediate one-pass submission.)*

1. **Official Aleo Developer Grants Landing Page**:
   - Portal URL: [`https://aleo.org/grants`](https://aleo.org/grants) (*Developer Grants Program | Aleo Network Foundation* — milestone-based funding up to `USD 100,000` per Blueprint track proposal).
   - Direct Official Application Form URL (Asana Intake Form embedded on `aleo.org/grants`):
     [`https://form.asana.com/?k=sCm0WT9M-V_fHl8AA48czQ&d=1199198487809755`](https://form.asana.com/?k=sCm0WT9M-V_fHl8AA48czQ&d=1199198487809755)
   - Contributor Terms & Grants Desk: [`https://aleo.org/contributor-terms.pdf`](https://aleo.org/contributor-terms.pdf) · `grants@aleo.org`
2. **Aleo Grant Tiers & Track Selection**:
   - **`Ignition` Grant (`~USD 3,000`)**: Introductory Leo applications for newcomers to zero-knowledge development.
   - **`Blueprint` Grant (`USD 10,000 – USD 100,000` — Selected Tier: `USD 30,000`)**: Core zero-knowledge infrastructure, `snarkVM` / `snarkOS` cryptographic acceleration, `Leo` / R1CS circuit libraries, and formal verification tooling.
   - **`Launch` Grant (`USD 10,000 – USD 200,000+`)**: Long-term, multi-stage full-scale network applications and ecosystem protocols.
3. **Eligibility & Open-Source Alignment**:
   - Under Aleo Network Foundation (`ANF`) guidelines, solo `Individual` researchers are explicitly eligible, all deliverables must contain open-source components built directly for the Aleo stack (`snarkVM` and `Leo`), and payouts execute strictly upon verified milestone completion.

---

## 1. Ready-to-Paste Application Form Fields (`aleo.org/grants` Intake Schema)

### Applicant & Team Profile
- **Applicant Legal Name**: `Houssem Aguentil` (`First = Houssem`, `Last = Aguentil`)
- **Applicant Type / Entity**: `Individual` (`Independent Researcher`)
- **Organization / GitHub Handle**: `Impius-Lab` ([`https://github.com/Impius-Lab`](https://github.com/Impius-Lab))
- **Email Address**: `2aghous94@gmail.com`
- **Location & Timezone**: `Alger, Algeria (Africa/Algiers, UTC+01:00)`
- **Telegram Handle**: `N/A` *(Alternative direct contact: `2aghous94@gmail.com` and `https://github.com/Impius-Lab`)*
- **Project Title**: `snarkvm-bilinear-opt: Certified BLS12-377 Pairing Acceleration, R1CS Non-Native & Extension Gadgets for Leo/snarkVM, and Zero-Sorry Lean 4 Soundness Proofs`
- **Project Category**: `Zero-Knowledge Infrastructure / Cryptography / Developer Tooling (snarkVM & Leo)`
- **Grant Tier & Requested Funding**: `Blueprint Grant — USD 30,000 (Milestone 1: USD 15,000 at Week 4; Milestone 2: USD 15,000 at Week 8; USD 0 upfront)`

### Elevator Pitch (`<= 300 words`)
Every private transaction and block proof on the Aleo Network relies on **Varuna** batch-R1CS proofs and **KZG10** polynomial commitments over **`BLS12-377`** (`snarkvm-fields` and `snarkvm-curves`). Meanwhile, privacy-preserving `Leo` and `snarkvm-circuit` applications (cross-chain ETH/`USDCx` bridges, `zPass` selective-disclosure identity credentials, and recursive proof verifiers) execute inside Aleo's 253-bit `Field<E>` (`Fr_BLS12_377`) R1CS constraint system, which currently lacks native extension-tower and non-native prime-field CRT gadgets.

We have **already implemented and benchmarked** a bit-exact `BLS12-377` tower & pairing optimization branch on [`ProvableHQ/snarkVM`](https://github.com/ProvableHQ/snarkVM) (`Impius-Lab/snarkVM` branch `perf/bls12-377-tower-opt`), cutting full `Bls12_377::pairing` latency by **`-26.96%` (`881.49 us -> 643.82 us`, `1.37x` speedup)**, `final_exponentiation` by **`-32.91%` (`508.02 us -> 340.83 us`, `1.49x`)**, `miller_loop` by **`-23.11%` (`274.88 us -> 211.36 us`, `1.30x`)**, and `Fq12` multiplication by **`-24.84%` (`2.8855 us -> 2.1688 us`, `1.33x`)** across all 86 `snarkvm-curves` unit tests with `#![forbid(unsafe_code)]`.

This **USD 30,000**, 8-week Blueprint Grant delivers three concrete open-source pillars for Aleo:
1. **Upstream `ProvableHQ/snarkVM` `BLS12-377` Host Acceleration**: Production PRs accelerating `Fq2`, `Fq6`, `Fq12`, Miller-loop `mul_by_034`, Karabina compressed `cyclotomic_exp`, and multi-pair KZG10 batch verification (`product_of_pairings`) for Varuna validators and provers.
2. **`snarkvm-bilinear-opt` R1CS Gadget Library & `Leo` Integration Templates**: Certified minimum-rank extension gadgets (`Rank-3`, `Rank-11`, `Rank-23`) and `6x64`-bit non-native `Fq_BLS12_377` / `BN254` / `BLS12-381` **`CRT-30`** gadgets over Aleo's 253-bit `Field<E>` (cutting non-native `BLS12-377` `Fp12` R1CS constraints by **`-31.46%`**, `66,534 -> 45,601`), plus `BW6-761` 2-chain Varuna wrapper schedules.
3. **Zero-`sorry` Core Lean 4 `BLS12-377` Soundness Suite**: Machine-checked proofs of 768-bit lazy-reduction bounds, Karabina cyclotomic decompression completeness, and 253-bit `Fr_BLS12_377` CRT non-overflow soundness.

---

## 2. Technical Problem Statement & Mission Alignment with Aleo

Aleo's architecture ("*private and compliant by design*") rests on two cryptographic pillars in [`ProvableHQ/snarkVM`](https://github.com/ProvableHQ/snarkVM):

### 2.1 Bottleneck A — Native `BLS12-377` Tower & Pairing Cost in Varuna / KZG10 Verification (`snarkvm-fields` & `snarkvm-curves`)
Every Aleo `snarkOS` validator, client verifier, and `VarunaSNARK` KZG10 commitment check calls `Bls12_377::product_of_pairings` (`algorithms/src/polycommit/kzg10/mod.rs:319`). Direct code inspection and Criterion profiling of `ProvableHQ/snarkVM` (`b6e4725e8ed9`) revealed four compounding inefficiencies:
1. **Eager Montgomery Reduction & Slice-Fold Overhead in `Fp2`, `Fp6`, and `Fp12`**:
   - Although `BLS12-377`'s 377-bit base prime $`q < 2^{377}`$ has **7 spare bits** below $`R = 2^{384}`$ ($`R / q = 152.328663`$, giving $`152 \cdot q^2 < q \cdot R`$ of unreduced 768-bit accumulator headroom), `Fp2::mul_assign` (`fields/src/fp2.rs:429`) executes 4 base multiplications via non-inlined slice-iterator `Fp384::sum_of_products` calls, and `Fp12::mul_assign` executes **72** `6x6` limb products and **36** `6x6` Montgomery reductions (`108` `6x6` blocks = `3,888` `mac`s).
2. **Uncompressed `cyclotomic_exp` Across 5 Powering Chains in `final_exponentiation` (`508.02 us`, `57.6%` of Total Pairing Time)**:
   - `Bls12::final_exponentiation` (`curves/src/templates/bls12/bls12.rs:207-215`) invokes `exp_by_x` **5 times** on the 64-bit `BLS12-377` seed `X = 0x8508c00000000001` ($`2^{63} + 2^{58} + 2^{56} + 2^{51} + 2^{47} + 2^{46} + 1`$), executing **`315` calls to `Fp12::cyclotomic_square`**, each using `6` full `Fp2` multiplications instead of Karabina compressed 2-`Fp4`-square chains (`4` `Fp2` multiplications per bit) with simultaneous Montgomery batch decompression.
3. **Eager D-Twist `mul_by_034` & Redundant First-Bit `1^2` Squaring in `Bls12::miller_loop` (`274.88 us`)**:
   - Each of the `69` line evaluations in `Bls12_377::miller_loop` executes `26` separate Montgomery reductions instead of `12` lazy reductions, and the initial MSB iteration squares `f = 1` and runs full `mul_by_034` against `1`.
4. **Redundant Karatsuba Expansion in `Fp6::mul_by_1` (`fields/src/fp6_3over2.rs:82`)**:
   - Computing $`(a_0 + a_1 v + a_2 v^2)(c_1 v) = u a_2 c_1 + a_0 c_1 v + a_1 c_1 v^2`$ previously performed unnecessary Karatsuba additions and subtractions to recover single products.

### 2.2 Bottleneck B — Missing Extension-Tower & Non-Native CRT Gadgets in `snarkvm-circuit` (`Field<E>`)
In `snarkvm-circuit` (`circuit/types/field/src/mul.rs:49-59`), multiplying an R1CS variable `Field<E>` by a constant `Field<E>` folds directly into `self.linear_combination * *other.eject_value()` for **zero R1CS constraints**, whereas variable-by-variable multiplication emits `E::enforce(|| (self, other, &product))` (`1` R1CS constraint). However, `snarkvm-circuit` currently exposes only prime-field `Field<E>`, `Scalar<E>`, `Group<E>` (`Edwards-BLS12`), and fixed-width integers `I8..I128`/`U8..U128`:
- Building **selective-disclosure compliance (`zPass`) verifiers** (ECDSA `secp256k1`/`P-256` or BLS `BLS12-381`), **trustless ETH/`USDCx` bridge light clients** (`BN254` / `BLS12-381` pairings), or **recursive `BLS12-377` KZG10 verifiers** inside Aleo circuits requires non-native field & tower arithmetic over Aleo's **253-bit** `Fr_BLS12_377` scalar field.
- Naive schoolbook/Karatsuba non-native `Fp12` over $`6 \times 64`$-bit limbs consumes **`66,534` R1CS constraints per `Fp12` multiplication**, while naive `23`-mul Vandermonde blows past Aleo's 2-limb carry ceiling ($`F_{\mathrm{bits}} - 1 = 252`$ bits, leaving $`252 - 196 = 56`$ bits of slack) and triggers **22 mandatory pre-multiplication reductions**.
- Simultaneously, as demonstrated by our discovery and fix of an excess-quotient-bit modulo-$`F`$ wrap-around bug in [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951), non-native quotient and carry witnesses without machine-checked bit bounds are a prime source of critical soundness vulnerabilities.

---

## 3. Completed Proof-of-Execution: Measured `snarkVM` `BLS12-377` Benchmarks & Live Upstream PRs

### 3.1 Completed `ProvableHQ/snarkVM` Prototype (`Impius-Lab/snarkVM` @ `perf/bls12-377-tower-opt`)
Before submitting this proposal, we built, algebraically certified, and benchmarked the core host-side `BLS12-377` optimization directly on `ProvableHQ/snarkVM` (`#![forbid(unsafe_code)]` preserved in `snarkvm-fields`, `0` external dependencies added, `86/86` `snarkvm-curves` unit tests passing including adversarial `[0, 1, q - 1]` 768-bit carry corners and degenerate $`z_2 = z_3 = 0`$ cyclotomic boundary tests):

1. **Compile-Time Certified 768-Bit Lazy Montgomery Reduction (`Fp384`, `Fq2`, `Fq6`, `Fq12`, `mul_by_034`, `mul_by_014`)**:
   - Because $`q < 2^{377}`$ and $`R = 2^{384}`$, `Fp384::modulus_sq_mul(k)` (`const`-asserted against `k <= u64::MAX / (MODULUS[5] + 1) - 1 = 151`) shifts unreduced 768-bit (`[u64; 12]`) Karatsuba combinations strictly into $`(0, 136 q^2] \subset (0, q \cdot R)`$ using LLVM-lowered `overflowing_add`/`overflowing_sub` (`ADC`/`SBB`) chains:
     - `Fq2::mul`: `4` products + `2` reductions (`216` `mac`s + slice-fold) $`\to`$ **`3` products + `2` reductions (`180` `mac`s, `-23.03%` latency)**.
     - `Fq12::mul`: `72` products + `36` reductions (`108` blocks) $`\to`$ **`54` products + `12` reductions (`66` blocks, `-38.89%` `mac`s, `-24.84%` latency)**.
     - `Fq12::mul_by_034` & `mul_by_014`: `52` products + `26` reductions (`78` blocks) $`\to`$ **`39` products + `12` reductions (`51` blocks, `-34.62%` `mac`s)**.
2. **Karabina (2013) Compressed Cyclotomic Powering + Simultaneous Stack Batch Decompression (`Fp12::cyclotomic_exp`)**:
   - Over $`\mathbb{G}_{\phi_6(q^2)}`$, `KarabinaCompressed` stores $`(z_2, z_3, z_4, z_5)`$ and squares in `2` `Fp4` squarings (`4` `Fq2` multiplications) instead of `3`. Using the universal cyclotomic identities (`2 * B_y + E_2 = 0` and `E_0 - A_0 = 0`):

```math
4 z_2 z_1 = u z_5^2 + 3 z_4^2 - 2 z_3 \quad (z_2 \ne 0), \qquad z_3 z_1 = 2 z_4 z_5 \quad (z_2 = 0,\; z_3 \ne 0), \qquad z_0 = u(2 z_1^2 + z_2 z_5 - 3 z_3 z_4) + 1,
```

   - All `6` non-trivial set-bit powers of `X = 0x8508c00000000001` (`bits 46, 47, 51, 56, 58, 63`) are decompressed simultaneously on a fixed stack buffer using **one single `Fp2::inverse()`** (`0` heap allocations, `0` `unwrap()`s, bit-for-bit identical output across all $`\mathbb{G}_{\phi_6(q^2)}`$ elements, with $`\mathbb{F}_{q^4} \cap \mathbb{G}_{\phi_6(q^2)} = \{1\}`$ since $`q^2 \equiv 1 \pmod{3} \implies 3 \nmid (q^4 - q^2 + 1)`$).

#### Measured Criterion Benchmarks on Unmodified `snarkvm-curves/benches/curves.rs` (`--release`, 100 Samples)

| `snarkvm-curves` Criterion Benchmark | Upstream `main` (`b6e4725e`) | `perf/bls12-377-tower-opt` | Exact Mean $`\Delta`$ | Speedup |
| :--- | :---: | :---: | :---: | :---: |
| `bls12_377: fq_square` | `29.290 ns` | **`26.123 ns`** | **`-10.81%`** | **`1.12x`** |
| `bls12_377: fq2_mul_assign` | `114.73 ns` | **`88.310 ns`** | **`-23.03%`** | **`1.30x`** |
| `bls12_377: fq2_square` | `77.452 ns` | **`71.424 ns`** | **`-7.78%`** | **`1.08x`** |
| `bls12_377: fq12_mul_assign` | `2.8855 us` | **`2.1688 us`** | **`-24.84%`** | **`1.33x`** |
| `bls12_377: fq12_square` | `1.9839 us` | **`1.6705 us`** | **`-15.80%`** | **`1.19x`** |
| `bls12_377: fq12_inverse` | `6.4696 us` | **`5.3708 us`** | **`-16.98%`** | **`1.20x`** |
| `bls12_377: pairing_miller_loop` | `274.88 us` | **`211.36 us`** | **`-23.11%`** | **`1.30x`** |
| **`bls12_377: pairing_final_exponentiation`** | `508.02 us` | **`340.83 us`** | **`-32.91%`** | **`1.49x`** |
| **`bls12_377: pairing_full`** | `881.49 us` | **`643.82 us`** | **`-26.96%` (`-237.67 us`)** | **`1.37x`** |

### 3.2 Track Record Across Production ZK Stacks (Five Live Open Upstream PRs)

| Live Upstream PR | Target Stack & Component | Baseline | Measured (Ours) | Verified Improvement & Security Impact |
| :--- | :--- | :---: | :---: | :--- |
| [`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) | Native 2-chain **`BLS12-377` over `BW6-761`** `E6.Mul` / `E12.Mul` / `PairingCheck` (`FixedQ`) | `15` / `45` / `6,339` R1CS | **`11` / `23` / `4,257` R1CS** | **`-26.67%` / `-48.89%` / `-32.84%`** (`-14.80%` `1`-pair `Pair`) |
| [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951) | Non-native `BN254` & `BLS12-381` `Pair` + CRT Soundness Fix | `836,825` / `1,323,407` R1CS | **`715,060` / `1,194,960` R1CS** | **`-14.55%` / `-9.71%` R1CS** (`-478,847` PlonK) + BabyBear `2t >= F-1` CRT forgery fix |
| [`Plonky3/Plonky3#2600`](https://github.com/Plonky3/Plonky3/pull/2600) | `p3-mersenne-31` `QM31` CPU & `p3-air` `ExtensionAlgebra` (`D=4..8`) | `20.331 ns` / `16..64` AIR muls | **`4.768 ns` / `7..15` AIR muls** | **`4.26x` CPU throughput** & **`-56.25%` to `-76.56%`** AIR muls |
| [`starkware-libs/proving#9`](https://github.com/starkware-libs/proving/pull/9) & [`#10`](https://github.com/starkware-libs/proving/pull/10) | StarkWare `stwo` `QM31` CPU, `[AIR-GENERATED]` verifiers & SIMD UB fix | `13.004 ns` / `22` AIR muls | **`4.797 ns` / `9` AIR muls** | **`2.71x` CPU**, **`-59.1%` AIR/Cairo verifier muls**, & `BaseColumn` `align=64->4` UB fix |

### 3.3 Certified `BLS12-377` R1CS & Non-Native CRT Pareto Frontier Over Aleo's 253-Bit `Fr_BLS12_377`
In [`Impius-Lab/zk-bilinear-opt`](https://github.com/Impius-Lab/zk-bilinear-opt) (`targets/pairing_towers/bls12_377_fp{2,6,12}_*.json`), we already synthesized and basis-verified the exact R1CS schedules for Aleo's curve pair:
- **Outer 2-Chain `BW6-761` R1CS Circuits (Wrapping Aleo Varuna Proofs for L1 Bridges)**: Because $`u^2 = -5, v^3 = u, w^2 = v`$ maps `BLS12-377` `Fp6` to $`\mathbb{F}_q[Y]/(Y^6 + 5)`$ and `Fp12` to $`\mathbb{F}_q[W]/(W^{12} + 5)`$ via **zero-addition coordinate permutations** ($`\det = -1`$), Winograd / Alder–Strassen interpolation achieves **`Rank-3`** (`Fp2`), **`Rank-11`** (`Fp6`, `-38.89%` vs `18` Karatsuba), and **`Rank-23`** (`Fp12`, `-57.41%` vs `54` Karatsuba).
- **Inner Aleo `snarkvm-circuit` R1CS Over 253-Bit `Fr_BLS12_377` (`r = 8444461749428370424248824938781546531375899335154063827935233455917409239041`)**: Since $`2^{252} < r_{\mathrm{BLS12-377}} < 2^{253}`$, packing two adjacent 64-bit limb equations (`128 + 64 + 4 = 196` bits) leaves **exactly `56` bits** ($`252 - 196 = 56`$) of carry slack. Our cyclotomic **`CRT-30`** schedule (`9` linear nodes `{-4..3, inf}` + `7` quadratic factors) caps slack at **`45` bits ($`\le 56`$ bits, `0` pre-multiplication reductions!)**:

| `snarkvm-circuit` Non-Native Target (`6x64`-bit over 253-bit `Fr`) | Karatsuba Baseline | Certified Pareto Winner | Base Muls | Pre-Mul `Reduce()` | Net R1CS Constraints ($`\Delta`$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`BLS12-377` `Fq6`** (Recursive Varuna / KZG) | `Tower-18` (`22,930` R1CS) | **`Rank-11`** (`{-5..4, inf}`) | `18 -> 11` | `0` | **`16,839` (`-26.56%`)** |
| **`BLS12-377` `Fq12`** (Recursive Varuna / KZG) | `Tower-54` (`66,534` R1CS) | **`CRT-30`** (`9` lin + `7` quad) | `54 -> 30` | `0` | **`45,601` (`-31.46%`)** |
| **`BLS12-381` `Fp12`** (`zPass` / BLS Attestations) | `Tower-54` (`68,032` R1CS) | **`CRT-30`** (`9` lin + `7` quad) | `54 -> 30` | `0` | **`46,078` (`-32.27%`)** |
| **`BN254` `Fp12`** (`4x64`-bit ETH / `USDCx` Bridge) | `Tower-54` (`44,619` R1CS) | **`CRT-30`** (`9` lin + `7` quad) | `54 -> 30` | `0` | **`31,497` (`-29.41%`)** |

---

## 4. Scope of Work, Milestones & Acceptance Criteria (8 Weeks · `USD 30,000` Total)

- **Upfront / Startup Funding Requested**: `USD 0` *(de-risked by our working `perf/bls12-377-tower-opt` `snarkVM` branch and `zk-bilinear-opt` schedules).*
- **Compensation Breakdown**: `320 hours` full-time cryptographic R&D, `snarkVM` / `snarkvm-circuit` Rust engineering, and Lean 4 formal verification by Principal Investigator Houssem Aguentil at `USD 93.75/hour` (`USD 30,000` total; `USD 0` hardware/cloud overhead).

### Milestone 1 — Upstream `ProvableHQ/snarkVM` `BLS12-377` Acceleration & Multi-Pair KZG10 Batch Optimization (Weeks 1–4 · `USD 15,000`)
- **Deliverables**:
  1. **Upstream `ProvableHQ/snarkVM` Pull Request(s)** (`Apache-2.0`, `#![forbid(unsafe_code)]`): Land our `perf/bls12-377-tower-opt` lazy 768-bit `Fq2`/`Fq6`/`Fq12`/`mul_by_034`/`mul_by_014` kernels and Karabina compressed `cyclotomic_exp` + extend shared multi-pair `Bls12_377::miller_loop` (`product_of_pairings`) with batched lazy line accumulation for `KZG10::batch_check` and `VarunaSNARK::verify`.
  2. **End-to-End Varuna & KZG10 Benchmark Suite**: Criterion benchmark suite measuring single-pair pairing, `KZG10::batch_check`, and `VarunaSNARK::verify_batch` throughput across Aleo mainnet transaction shapes (`1`, `4`, `16`, and `64` instances).
  3. **Differential Fuzz & Boundary Test Suite**: `100,000`-iteration differential fuzz harness and boundary-corner unit tests (`0`, `1`, `q - 1`, subgroup degeneracies) in `snarkvm-fields` and `snarkvm-curves`.
- **Acceptance Criteria**:
  - `cargo +stable test -p snarkvm-fields -p snarkvm-curves -p snarkvm-algorithms` and `cargo +stable clippy -- -D warnings` exit `0`.
  - Criterion benchmarks reproduce $`\ge 25\%`$ latency reduction on `bls12_377: pairing_full` and $`\ge 30\%`$ reduction on `pairing_final_exponentiation` with 100% bit-identical outputs to upstream `snarkVM`.

### Milestone 2 — `snarkvm-bilinear-opt` R1CS Non-Native & Extension Gadgets, `Leo` Reference Circuits & Zero-`sorry` Lean 4 Proofs (Weeks 5–8 · `USD 15,000`)
- **Deliverables**:
  1. **Open-Source `snarkvm-bilinear-opt` Crate (`Apache-2.0 OR MIT`, `#![forbid(unsafe_code)]`)**: Generic over `snarkvm_circuit_environment::Environment` (`Circuit` / `AleoV0`), providing:
     - Native `Field<E>` degree-`2`/`6`/`12` minimum-rank extension gadgets (`Rank-3`, `Rank-11`, `Rank-23` leveraging `0`-constraint `LinearCombination` constant scaling).
     - Non-native CRT gadgets over 253-bit `Fr_BLS12_377` with exact `quoBits` (`packLimbsWithWidth`) and `crtLowCarries` range enforcement for `Fq_BLS12_377` (`377`-bit, `Fq6` `Rank-11`, `Fq12` `CRT-30`), `BLS12-381`, `BN254`, and `secp256k1`/`P-256` (`zPass` & bridge primitives).
  2. **`Leo` / `snarkVM` Reference Verifier Examples & Constraint Audit**: Working `snarkvm-circuit` + `Leo` integration examples (BLS signature / KZG opening verifier and `secp256k1` `zPass` credential check) with exact `Circuit::num_constraints()` regression pins and adversarial malicious-prover witness-tampering rejection tests (`!Circuit::is_satisfied()`).
  3. **Zero-`sorry` Core Lean 4 `BLS12-377` Soundness Package (`lean4_certs/Bls12_377Soundness.lean`)**: Pure Core Lean 4 (`v4.36.0`, `0` Mathlib dependencies, `< 15s` `lake build`) formally proving:
     - `BLS12-377` 768-bit lazy-reduction bounds ($`0 < W \le 136 q^2 < q \cdot 2^{384}`$) and Montgomery reduction canonicality;
     - Universal completeness of Karabina's 3-case cyclotomic decompression over $`\mathbb{G}_{\phi_6(q^2)}`$;
     - Exact non-native CRT uniqueness ($`\vert \mathrm{LHS} - (r + s \cdot k \cdot p)\vert < r_{\mathrm{BLS12-377}} \cdot 2^{64 n_{\mathrm{low}}}`$) over Aleo's 253-bit scalar field.
- **Acceptance Criteria**:
  - `cargo +stable test` and `clippy -D warnings` exit `0` across `snarkvm-bilinear-opt`, confirming $`\ge 30\%`$ R1CS constraint reduction on non-native `BLS12-377` `Fq12` (`CRT-30` vs `Tower-54`) and `100%` rejection of tampered quotient/non-canonical witnesses.
  - `lake build` exits `0` in `< 15s` with `0` `sorry` and `0` custom `axiom`s (`#print axioms` verified).

---

## 5. Risk Mitigation & Transparency Disclosure

1. **Zero Consensus Divergence Risk**: All host-side `snarkvm-fields` and `snarkvm-curves` optimizations preserve exact field representations (`#[repr(transparent)]` `Fp384(BigInteger384)` — keeping CUDA FFI byte layouts untouched) and return **100% bit-for-bit identical** canonical Montgomery elements for every input, including exact `Bls12_377::final_exponentiation` exponent parity.
2. **Non-Overlapping Funding Disclosure**: We maintain a separate Zcash-specific grant application ([`ZcashCommunityGrants/zcashcommunitygrants#590`](https://github.com/ZcashCommunityGrants/zcashcommunitygrants/issues/590)) scoped exclusively to Zcash `Halo2` PlonKish lookup chips (`Pasta` `Pallas`/`Vesta` + `zkcrypto/bls12_381`). There is **zero code, curve, or budget overlap** with this Aleo `BLS12-377` `snarkVM` / `snarkvm-circuit` R1CS / `Leo` Blueprint Grant.

---

## 6. Verification Links & Artifacts

- **`snarkVM` `BLS12-377` Optimization Fork (`perf/bls12-377-tower-opt`)**: [`https://github.com/Impius-Lab/snarkVM/tree/perf/bls12-377-tower-opt`](https://github.com/Impius-Lab/snarkVM/tree/perf/bls12-377-tower-opt)
- **`zk-bilinear-opt` Main Repository & Certified `BLS12-377` Schedules**: [`https://github.com/Impius-Lab/zk-bilinear-opt`](https://github.com/Impius-Lab/zk-bilinear-opt) (`targets/pairing_towers/bls12_377_fp{2,6,12}_*.json` & `lean4_certs/`)
- **Live Upstream PR 1 (`Consensys/gnark#1950` — Native `BLS12-377` `-32.84%` `PairingCheck`)**: [`https://github.com/Consensys/gnark/pull/1950`](https://github.com/Consensys/gnark/pull/1950)
- **Live Upstream PR 2 (`Consensys/gnark#1951` — Emulated Pairing `-478,847` PlonK Gates & CRT Soundness Fix)**: [`https://github.com/Consensys/gnark/pull/1951`](https://github.com/Consensys/gnark/pull/1951)
- **Live Upstream PR 3 (`Plonky3/Plonky3#2600` — `4.26x` `QM31` & `-56.25%..-76.56%` `p3-air` `ExtensionAlgebra`)**: [`https://github.com/Plonky3/Plonky3/pull/2600`](https://github.com/Plonky3/Plonky3/pull/2600)
- **Live Upstream PR 4 (`starkware-libs/proving#9` — `2.71x` `stwo` `QM31` & `-59.1%` AIR/Cairo Verifier Muls)**: [`https://github.com/starkware-libs/proving/pull/9`](https://github.com/starkware-libs/proving/pull/9)
- **Live Upstream PR 5 (`starkware-libs/proving#10` — `stwo` SIMD `BaseColumn` Memory-Safety UB Fix)**: [`https://github.com/starkware-libs/proving/pull/10`](https://github.com/starkware-libs/proving/pull/10)
