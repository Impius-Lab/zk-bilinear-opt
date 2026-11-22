# Zcash Community Grants (`ZCG`) Fast-Track Proposal — `halo2-bilinear-opt`

**Applicant**: Houssem Aguentil (`Individual` · `Independent Researcher` · `Impius-Lab` · `2aghous94@gmail.com` · `Alger, Algeria`)  
**Requested Grant Amount**: **USD 30,000** (`<= USD 50,000` fast-track tier · `USD 0` upfront · 2 Milestones over 8 Weeks: M1 `USD 15,000` + M2 `USD 15,000`)  
**License**: `MIT` (dual-licensed `MIT OR Apache-2.0` per [`zcash/librustzcash`](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md#styleguides) & `zcash/halo2` upstream standards)

---

## 0. Verified Live ZCG Submission Portal & Step-by-Step Filing Guide

*(Verified directly against the live `ZcashCommunityGrants/zcashcommunitygrants` GitHub repository schema `.github/ISSUE_TEMPLATE/grant_application.yaml` — ready for one-pass submission without edits.)*

1. **GitHub Issue Application URL (Primary Portal)**:
   - Repository: [`https://github.com/ZcashCommunityGrants/zcashcommunitygrants`](https://github.com/ZcashCommunityGrants/zcashcommunitygrants)
   - Direct Form URL: [`https://github.com/ZcashCommunityGrants/zcashcommunitygrants/issues/new?template=grant_application.yaml`](https://github.com/ZcashCommunityGrants/zcashcommunitygrants/issues/new?template=grant_application.yaml)
   - Issue Title Format: `Grant Application - halo2-bilinear-opt: Certified Pairing & Pasta Wrong-Field Gadgets for Zcash Halo2 and Tachyon`
   - Automatic Label Applied: `Pending Grant Application`
2. **Mandatory Zcash Community Forum Post (`forum.zcashcommunity.com`)**:
   - Forum Category URL: [`https://forum.zcashcommunity.com/c/grants/33`](https://forum.zcashcommunity.com/c/grants/33) (*Grants* category)
   - Posting Rule: Immediately after opening the GitHub issue, create a new topic in `https://forum.zcashcommunity.com/c/grants/33` containing the Executive Summary, Milestone table, and direct link to the GitHub issue. Under ZCG governance rules, **posting the GitHub issue link to the Community Forum is a mandatory prerequisite** before the ZCG Committee discusses and votes on the proposal at its bi-weekly meeting.
   - Governance References: [ZCG Code of Conduct](https://forum.zcashcommunity.com/t/zcg-code-of-conduct/41787) · [ZCG Communication Guidelines](https://forum.zcashcommunity.com/t/zcg-communication-guidelines/44284) · [`librustzcash` Style Guides](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md#styleguides).
3. **Fast-Track / FPF Compliance Note (`<= USD 50,000`)**:
   - Under `grant_application.yaml`, mandatory Financial Privacy Foundation (`FPF`) KYC is triggered above `USD 50,000` (*"if funded above USD 50,000"*); at **USD 30,000** (`USD 0` startup, two `USD 15,000` delivery-verified milestones), this proposal qualifies for streamlined ZCG review while remaining ready for standard FPF grantee onboarding (`First = Houssem`, `Last = Aguentil`, `Alger, Algeria`).

---

## 1. Field-by-Field Values for `grant_application.yaml`

### Issue Title
`Grant Application - halo2-bilinear-opt: Certified Pairing & Pasta Wrong-Field Gadgets for Zcash Halo2 and Tachyon`

### Terms and Conditions (`terms_and_conditions_checkboxes`)
- [x] I agree to the Grant Agreement terms if funded
- [x] I agree to Provide KYC information if funded above USD 50,000
- [x] I agree to disclose conflicts of interest *(None)*
- [x] I agree to adhere to the Code of Conduct and Communication Guidelines
- [x] I understand all milestone deliverables will be validated and accepted by their intended users or their representatives, who will confirm that the deliverables meet the required quality, functionality, and usability for each user story.
- [x] I agree that for any new open-source software, I will create a `CONTRIBUTING.md` file that reflects the high standards of Zcash development, using the `librustzcash` style guides as a primary reference.
- [x] I understand when contributing to existing Zcash code, I am required to adhere to the project specific contribution guidelines, paying close attention to any merge, branch, pull request, and commit guidelines as exemplified in the `librustzcash` repository.
- [x] I agree to post request details on the Community Forum (`https://forum.zcashcommunity.com/c/grants/33`)
- [x] I understand it is my responsibility to post a link to this issue on the Zcash Community Forums after this application has been submitted so the community can give input. I understand this is required in order for ZCG to discuss and vote on this grant application.

### Application Owners (`assignees`)
`@Impius-Lab`

---

## 2. Organization & Team Information

- **Organization Name (`organization_details_name`)**: `Houssem Aguentil (Individual — Independent Researcher, Impius-Lab)`
- **How did you learn about Zcash Community Grants (`organization_details_discovery`)**: `Zcash open-source cryptography ecosystem (zcash/halo2, zkcrypto/bls12_381, pasta_curves, Zebra, and Project Tachyon research)`
- **Requested Grant Amount (`project_overview_amount`)**: `USD 30,000` *(enter `30,000` USD in form)*
- **Category (`project_overview_category`)**: `Research & Development` *(with direct deliverables for Zcash `Infrastructure` & `Security`)*

### Project Lead (`team_information_project_lead`)
```yaml
Name: Houssem Aguentil
Role: Principal Investigator & Cryptographic Engineer (Individual / Independent Researcher)
Location & Contact: Alger, Algeria (UTC+01:00) | 2aghous94@gmail.com | https://github.com/Impius-Lab
Background: >
  Independent algebraic complexity and zero-knowledge cryptography researcher (Impius-Lab).
  Creator of zk-bilinear-opt (https://github.com/Impius-Lab/zk-bilinear-opt), certifying 64
  finite-field and non-native limb-carry schedules across 3,706 exact integer/prime-field
  basis pairs and 109,000+ differential fuzz tests, including a working #![no_std] Zcash
  BLS12-381 & Pasta prototype (rust_crates/src/halo2_gadgets.rs). Author of six live open
  upstream PRs across Consensys/gnark (#1950, #1951), Plonky3/Plonky3 (#2600),
  StarkWare proving/stwo (#9, #10), and aleo-labs-protocol/snarkVM (#3908), including the discovery and fix of a malicious-prover
  non-native CRT quotient wrap-around vulnerability (Consensys/gnark#1951).
Responsibilities: >
  End-to-end #![no_std] Rust gadget engineering (halo2-bilinear-opt), PlonKish lookup/FlexGate
  circuit integration for pasta_curves and bls12_381, Zebra / Tachyon proof-aggregation
  benchmarks, zero-sorry Lean 4 CRT soundness proofs, and upstream Zcash PR shepherding.
```

### Additional Team Members (`team_information_members`)
`None / N/A (Solo Individual Applicant)`

---

## 3. Project Details

### Project Summary (`project_details_summary`)
`halo2-bilinear-opt` delivers basis-certified `#![no_std]` Rust extension-tower (`BLS12-381` `Fp6` Rank-11, `Fp12` Rank-23, sparse `mul_by_014` Rank-18, and non-native `CRT-30`) and `Pasta` (`Pallas`/`Vesta`) wrong-field CRT gadgets for Zcash `Halo2`, cutting non-native `Fp12` PlonKish lookup/gate cells by **24.5%–29.9%** and `Pasta` wrong-field reduction cells by **9.9%–13.1%**, backed by zero-`sorry` Lean 4 CRT soundness proofs and Zebra / Tachyon recursive aggregation benchmarks.

### Project Description (`project_details_description`)
Zcash's shielded cryptography spans two core curve families: **`BLS12-381`** (`Sapling`, `zkcrypto/bls12_381`, BLS signatures, cross-chain bridges) and the **`Pasta` 2-cycle** (`Pallas` and `Vesta` in `Orchard`, `zcash/halo2`, and `Tachyon`-class proof-carrying data / recursive aggregation). Whenever Zcash circuits verify `BLS12-381` pairings over `Pasta` scalar fields, bridge Sapling/BLS attestations into Halo2, or perform wrong-field scalar/base reductions across `Pallas` and `Vesta` without full curve-cycle alternation overhead, two bottlenecks dominate prover latency and circuit row counts:

1. **Suboptimal Tower Multiplication Schedules**: Standard implementations (`zkcrypto/bls12_381` and Halo2 pairing chips) evaluate `Fp6` in `18` `Fp` multiplications, `Fp12` in `54` `Fp` multiplications, and sparse Miller-loop `mul_by_014` in `39`–`54` `Fp` multiplications. Worse, naively plugging Winograd's `23`-multiplication Vandermonde schedule (`{-11..10, inf}`) into non-native limbs produces $`77`$-bit intermediate evaluation slack and $`113`$-bit reconstruction constants, breaching the `Pasta` limb-carry ceiling and triggering **22 mandatory pre-multiplication modular reductions**.
2. **Loose Non-Native CRT Quotient & Carry Bounds (Prover Cost + Soundness Risk)**: Existing non-native field chips pad quotient witnesses `k` to full limb multiples (`nbQuoLimbs * limb_bits`) and range-check all carry limbs using loose `+1 bit per term` heuristics. In [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951), our exact integer analysis showed that tight `quoBits = bitLen(maxQuo)` and CRT low-carry certificates simultaneously eliminate redundant range checks **and** close a subtle excess-quotient-bit wrap-around soundness bug when $`2t \ge F_{\mathrm{bits}} - 1`$.

We have **already built and verified** the `#![no_std]` mathematical core and PlonKish cell cost calculator in [`Impius-Lab/zk-bilinear-opt`](https://github.com/Impius-Lab/zk-bilinear-opt) (`rust_crates/src/halo2_gadgets.rs`, passing `cargo +stable test` and `cargo +stable clippy -- -D warnings` with zero external dependencies). This **USD 30,000**, 8-week grant turns that verified engine into a production-ready, `MIT`-licensed Zcash Rust crate (`halo2-bilinear-opt`) wired directly against `zcash/halo2`, `zkcrypto/bls12_381`, and `zcash/pasta_curves`, accompanied by reproducible `Zebra` / `Tachyon` recursive aggregation benchmarks and machine-checked **Lean 4** CRT soundness proofs.

### Proposed Problem (`project_details_problem`)
1. **Non-Native `BLS12-381` & Wrong-Field `Pasta` Cell Overhead in Halo2**: Bridging Sapling (`BLS12-381`), verifying BLS consensus/bridge signatures inside Orchard/Halo2 circuits, and executing wrong-field `Pallas`/`Vesta` ECDSA/Ed25519 or batch-verification gadgets consume tens of thousands of `FlexGate` and `RangeChip` lookup cells per operation, pushing circuits across $`2^k \to 2^{k+1}`$ FFT domain boundaries (which doubles Halo2 IPA prover time and memory).
2. **The Carry-Ceiling Trap**: Cryptographers face a false dichotomy between `54`-mul Karatsuba (low carry slack, too many `Fp` multiplications) and `23`-mul Vandermonde (minimum `Fp` multiplications, catastrophic $`77`$-bit carry blowup in `88`-bit and `64`-bit limbs).
3. **Lack of Machine-Checked Soundness Certificates for Non-Native Limb Gadgets**: Non-native field chips are historically the single highest-risk bug surface in production ZK systems (under-constrained quotient high bits, missing `< p` canonicality checks, and signed carry wrap-around modulo the native scalar field).

### Proposed Solution (`project_details_solution`)
1. **Pareto-Optimal Non-Native & Native Pairing Schedules**:
   - **Native `Fp` & CPU/Scalar Contexts (`zkcrypto/bls12_381` & Deferred Evaluators)**: Division-free unimodular ($`\det = \pm 1`$) basis isomorphisms $`u = v^3 - 1 \implies v^6 - 2v^3 + 2 = 0`$ and $`u = w^6 - 1 \implies w^{12} - 2w^6 + 2 = 0`$ unlock exact **`Fp6` Rank-11** (`18 -> 11`, `-38.89%`), **`Fp12` Rank-23** (`54 -> 23`, `-57.41%`), normalized untwisted-`G1` **`mul_by_014` Rank-18** (`54 -> 18`, `-66.67%`), unit-prepared **`mul_by_014_unit` Rank-19** (`19` muls), and projective **`mul_by_014` Rank-21** (`54 -> 21`, `-61.11%`).
   - **Non-Native Halo2 Limb Contexts (`5x88`-bit & `6x64`-bit over `Pasta`)**: Our cyclotomic/linear **`CRT-30`** schedule (`9` small linear nodes `{-4..3, inf}` + `7` cyclotomic quadratic factors) caps input slack at $`45`$ bits (strictly below both the $`72`$-bit `5x88` `Pasta` carry limit and $`56`$-bit `6x64` 2-limb limit, requiring **zero pre-multiplication reductions**) and caps $`\Vert W_{\mathbb{Z}}\Vert_1 + D`$ at $`52`$ bits (single-limb output constants), cutting total Halo2 PlonKish cells by **`-24.49%` to `-29.85%`** across `lookup_bits` $`\in \{8, 12, 16\}`$.
2. **Exact `quoBits` & `crtLowCarries` Range-Check Tightening**: Porting our [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951) exact integer quotient-width (`packLimbsWithWidth`) and CRT low-carry theorem into Halo2 `RangeChip` cuts `Pallas`-in-`Vesta` and `Vesta`-in-`Pallas` wrong-field multiplication cells by **`-9.94%` to `-13.05%`** while statically forbidding modulo $`q`$ wrap-around.
3. **Zero-`sorry` Lean 4 Proofs & Zebra/Tachyon Benchmarks**: Every algebraic identity (`Fp6` Rank-11, `Fp12` Rank-23, `CRT-30`) and every `Pasta` / `BLS12-381` CRT carry inequality will ship with a self-contained, zero-`sorry` **Lean 4** soundness proof and end-to-end Halo2 IPA prover benchmarks modeled on Zcash's `Orchard` / `Tachyon` recursion workloads.

### Solution Format (`project_details_format`)
1. **Open-Source Rust Crate (`halo2-bilinear-opt`)**: `#![no_std]`-first Rust library with optional `halo2_proofs` (`zcash/halo2`), `bls12_381` (`zkcrypto/bls12_381`), and `pasta_curves` (`Pallas`/`Vesta`) feature flags, `CONTRIBUTING.md` aligned with `librustzcash`, CI-free local deterministic verification scripts, and `cargo bench` Criterion suites.
2. **Formal Verification Suite (`lean4_certs/`)**: Standalone Core Lean 4 package (`lake build` in `< 20s`, zero `sorry`, zero custom `axiom`s) proving exact tower identities and `Pasta`/`BLS12-381` CRT carry soundness.
3. **Technical Benchmark Report & Upstream PRs**: Public benchmark report measuring Halo2 IPA proving time, peak RAM, advice/lookup cell utilization, and $`2^k`$ domain thresholds on recursive `Pasta` + `BLS12-381` circuits, plus targeted upstream PRs to Zcash ecosystem repositories.

### Dependencies (`project_details_dependencies`)
- **Technical Dependencies**: `zcash/halo2` (`halo2_proofs`, `halo2_gadgets`), `zkcrypto/bls12_381`, `zcash/pasta_curves` (`ff`, `group`), Rust stable toolchain (`1.81+`), and Lean 4 (`elan` stable toolchain for formal certificates).
- **External Organizational Blockers**: **Zero**. All work executes independently against public open-source crates; upstream maintainer review is welcomed for optional merge PRs in Milestone 2, while `halo2-bilinear-opt` is immediately usable standalone by any Zcash developer upon Milestone 1 completion.

### Technical Approach (`project_details_technical`)

#### A. Track Record: Six Live Open Upstream PRs & Verified Benchmarks
Unlike speculative proposals, our synthesis methodology is already proven in production compilers and provers across six live open upstream Pull Requests:

| Live Upstream PR | Target Stack & Component | Baseline | Measured (Ours) | Verified Improvement & Security Impact |
| :--- | :--- | :---: | :---: | :--- |
| [`Consensys/gnark#1950`](https://github.com/Consensys/gnark/pull/1950) | Native 2-chain `BLS12-377` `E6.Mul` / `E12.Mul` / `PairingCheck` (`FixedQ`) | `15` / `45` / `6,339` R1CS | **`11` / `23` / `4,257` R1CS** | **`-26.67%` / `-48.89%` / `-32.84%`** (`-14.80%` `1`-pair `Pair`) |
| [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951) | Non-native `BN254` `Pair` (`1`-pair witness / fixed `G2`) | `836,825` / `720,474` R1CS | **`715,060` / `611,184` R1CS** | **`-14.55%` / `-15.17%` R1CS** (`-427,820` PlonK gates) |
| [`Consensys/gnark#1951`](https://github.com/Consensys/gnark/pull/1951) | Non-native `BLS12-381` `Pair` (`1`-pair witness `G2`) + CRT Soundness | `1,323,407` R1CS / `4,881,141` PlonK | **`1,194,960` / `4,402,294`** | **`-9.71%` R1CS / `-9.81%` (`-478,847`) PlonK** + closed BabyBear `2t >= F-1` CRT forgery |
| [`Plonky3/Plonky3#2600`](https://github.com/Plonky3/Plonky3/pull/2600) | `p3-mersenne-31` `QM31` CPU & `p3-air` `ExtensionAlgebra` (`D=4..8`) | `20.331 ns` / `16..64` AIR muls | **`4.768 ns` / `7..15` AIR muls** | **`4.26x` CPU throughput** & **`-56.25%` to `-76.56%`** AIR muls |
| [`starkware-libs/proving#9`](https://github.com/starkware-libs/proving/pull/9) & [`#10`](https://github.com/starkware-libs/proving/pull/10) | StarkWare `stwo` `QM31` CPU, `[AIR-GENERATED]` verifiers & SIMD UB fix | `13.004 ns` / `22` AIR muls | **`4.797 ns` / `9` AIR muls** | **`2.71x` CPU**, **`-59.1%` AIR/Cairo verifier muls**, & `BaseColumn` `align=64->4` UB fix |
| [`aleo-labs-protocol/snarkVM#3908`](https://github.com/aleo-labs-protocol/snarkVM/pull/3908) | Native `BLS12-377` 768-bit lazy tower & Karabina `cyclotomic_exp` | `881.49 us` / `508.02 us` | **`643.82 us` / `340.83 us`** | **`-26.96%` (`1.37x`) full pairing** & **`-32.91%` (`1.49x`) `final_exp`** |

#### B. Completed Zcash Prototype (`rust_crates/src/halo2_gadgets.rs`)
We have already implemented and verified our `#![no_std]` Zcash `BLS12-381` + `Pasta` kernel and cost-estimator prototype in `rust_crates/src/halo2_gadgets.rs` (tested across all $`d^2`$ canonical basis pairs on both a fast irreducible field and Zcash's exact 255-bit `[u64; 4]` `Pallas` base field $`p_P`$):

1. **Exact `BLS12-381` Bilinear Tower Multiplication Counts (`PrimeFieldOps::mul`)**:
   - `Fp2` ($`u^2 + 1 = 0`$): **`3`** muls (`Rank-3` vs `4` schoolbook, `2` muls squaring).
   - `Fp6` ($`v^3 - (u + 1) = 0 \cong \mathbb{F}_p[v]/(v^6 - 2v^3 + 2)`$): **`11`** muls (`Rank-11` vs `18` Karatsuba tower / `15` Toom-3, **`-38.89%`**).
   - `Fp12` ($`w^2 - v = 0 \cong \mathbb{F}_p[w]/(w^{12} - 2w^6 + 2)`$): **`23`** muls (`Rank-23` vs `54` Karatsuba, **`-57.41%`**).
   - Sparse Miller-Loop `mul_by_014`: **`18`** muls for normalized untwisted-`G1` affine lines $`1 + c_1 v + y_P v w`$ (`-66.67%` vs `54`), **`19`** muls for `zkcrypto/bls12_381` `mul_by_014_unit` ($`1 + c_1 v + c_4 v w`$), and **`21`** muls for unnormalized projective `mul_by_014(c0, c1, c4)` (`-61.11%` vs `54`).

2. **Exact Non-Native CRT Quotient & Carry Soundness (`U1024` Exact Arithmetic)**:
   For any integer limb relation $`\mathrm{LHS} = r + s \cdot k \cdot p`$ over a `Pasta` scalar field ($`F_{\mathrm{bits}} = 255`$, $`q \ge 2^{254}`$) with $`t`$-bit limbs ($`t \in \{88, 64\}`$):

```math
\max\mathrm{Quo} = \max\left(\left\lfloor \frac{\mathrm{posMax}}{p} \right\rfloor, \left\lceil \frac{\mathrm{negMax}}{p} \right\rceil\right), \qquad \mathrm{quoBits} = \mathrm{bitLen}(\max\mathrm{Quo}),
```

```math
n_{\mathrm{low}} = \left\lceil \frac{\max(0, w_{\mathrm{bits}} - (F_{\mathrm{bits}} - 1))}{t} \right\rceil, \qquad t + b_{\mathrm{carry}} + 1 \le F_{\mathrm{bits}} - 1.
```

3. **Measured PlonKish Cell Counts (`Halo2LookupCostModel`: `FlexGate` + `RangeChip` over 255-bit `Pasta`)**:

| Halo2 Config (`lookup_bits`, `limb_bits`) | `Pasta` Wrong-Field Mul (Naive -> Exact `quoBits`) | `BLS12-381` `Fp12` `Schoolbook-54` | `BLS12-381` `Fp12` `Karatsuba-36` | `BLS12-381` `Fp12` **`CRT-30` (Winner)** | `BLS12-381` `Fp12` `Rank-23` (`22` pre-reds) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `lookup = 8b`, `5x88b` (`3x88b` Pasta) | `538 -> 482` (**`-10.41%`**) | `52,243` | `41,371` | **`39,451` (`-24.49%`)** | `44,838` |
| `lookup = 8b`, `6x64b` (`4x64b` Pasta) | `613 -> 533` (**`-13.05%`**) | `60,469` | `45,793` | **`43,783` (`-27.59%`)** | `51,155` |
| `lookup = 12b`, `5x88b` (`3x88b` Pasta) | `402 -> 362` (**`-9.95%`**) | `40,483` | `31,675` | **`29,899` (`-26.14%`)** | `37,026` |
| `lookup = 12b`, `6x64b` (`4x64b` Pasta) | `477 -> 421` (**`-11.74%`**) | `48,697` | `36,241` | **`34,159` (`-29.85%`)** | `43,339` |
| `lookup = 16b`, `5x88b` (`3x88b` Pasta) | `322 -> 290` (**`-9.94%`**) | `33,787` | `26,491` | **`24,475` (`-27.56%`)** | `32,438` |
| `lookup = 16b`, `6x64b` (`4x64b` Pasta) | `389 -> 341` (**`-12.34%`**) | `39,049` | `29,425` | **`28,231` (`-27.70%`)** | `37,147` |

### Upstream Merge Opportunities (`project_details_merge`)
- **`zkcrypto/bls12_381`**: Optional PR contributing constant-time scalar/CPU `mul_by_014_unit` / Karatsuba & cyclotomic squaring refinements with Criterion benchmarks, strictly adhering to `librustzcash` constant-time `subtle::Choice` conventions.
- **`zcash/halo2` Ecosystem**: `halo2-bilinear-opt` is structured as a modular companion crate implementing `halo2_proofs::circuit::Chip` for `pasta_curves::Fp` / `Fq` so `Orchard` extensions, `Tachyon` PCD prototypes, and Sapling-to-Halo2 bridge circuits can adopt `CRT-30` and wrong-field `Pasta` gadgets without invasive changes to consensus-frozen `orchard` crates.
- **`ZcashFoundation/zebra`**: Batch/aggregation benchmark harness in Milestone 2 exercises real `Zebra` transaction verification test vectors read-only, requiring zero consensus modifications.

### Open Source License (`project_details_license`)
`MIT` *(dual-licensed `MIT OR Apache-2.0` so all code satisfies the ZCG Grant Agreement `MIT` requirement while remaining 100% compatible with `zcash/librustzcash`, `zcash/halo2`, and `zkcrypto/bls12_381`)*.

---

## 4. Budget Breakdown (`USD 30,000` Total)

- **Hardware/Software Costs (`budget_hardware`)**: `USD 0`
  - *Justification (`budget_hardware_justification`)*: All compilation, Halo2 IPA proving benchmarks, 109,000+ differential fuzz runs, and Lean 4 formal proof builds execute on existing dedicated local multi-core x86_64 workstations at zero cost to ZCG.
- **Service Costs (`budget_service`)**: `USD 0`
  - *Justification (`budget_service_justification`)*: Zero external cloud, contractor, or marketing fees requested.
- **Compensation Costs (`budget_compensation`)**: `USD 30,000`
  - *Justification (`budget_compensation_justification`)*: 8 weeks full-time cryptographic engineering & formal verification by Principal Investigator Houssem Aguentil (`320 hours` at `USD 93.75/hour`), split evenly across two concrete, test-gated milestones (`USD 15,000` + `USD 15,000`) paid strictly upon verified public delivery.
- **Total Budget (`budget_total`)**: `USD 30,000`
- **Previous Funding from ZCG (`budget_previous_funding`)**: `No`
- **Other Funding Sources (`budget_other_sources`)**: `No` *(This Zcash-specific `halo2` / `pasta_curves` / `bls12_381` / `Tachyon` crate and Lean 4 CRT proof scope receives zero overlapping funding; separate non-overlapping ecosystem submissions are pending with Starknet Seed Grants, Aleo SCALE Grants, and EF ESP Office Hours.)*

---

## 5. Risk Assessment & Success Metrics

### Implementation Risks (`risk_implementation`)
1. **Lookup Table Row Overhead on Small Circuits**: A $`16`$-bit fixed range table requires $`2^{16} = 65,536`$ rows, which is suboptimal for small Halo2 circuits ($`k \le 14`$, such as single-action Orchard circuits with $`k = 11`$).
   - *Mitigation*: Already solved in our `Halo2LookupCostModel` design — every gadget is parameterized over `lookup_bits` $`\in \{8, 10, 12, 16\}`$ and limb widths $`\{88, 64\}`$, allowing `small-k` `Orchard`/`Tachyon` circuits ($`k = 11..13`$) to select $`8`$-bit or $`10`$-bit lookup tables while large bridge/aggregation circuits ($`k \ge 17`$) use $`16`$-bit tables.
2. **Constant-Time vs Variable-Time Witness Generation**: Scalar Rust code in `zkcrypto/bls12_381` must remain constant-time (`subtle`) when handling secret scalars, whereas public pairing inputs and in-circuit PlonKish constraints have fixed circuit topology.
   - *Mitigation*: All Halo2 circuit layouts are 100% data-independent (fixed selectors/wiring), and out-of-circuit witness generators avoid secret-dependent branching (`#![forbid(unsafe_code)]`, constant-time `subtle` primitives).

### Potential Side Effects (`risk_side_effects`)
None on Zcash mainnet consensus: `halo2-bilinear-opt` ships as an opt-in, modular `#![no_std]` crate with deterministic basis-complete algebraic equivalence tests (`100%` bit-identical outputs to `zkcrypto/bls12_381` and `pasta_curves`) and zero consensus rule changes.

### Success Metrics (`risk_metrics`)
1. **Verified Cell Reduction**: Achieve $`\ge 24\%`$ PlonKish cell reduction on non-native `BLS12-381` `Fp12` multiplication (`CRT-30` vs `Schoolbook-54`) and $`\ge 9.9\%`$ cell reduction on `Pasta` (`Pallas`/`Vesta`) wrong-field multiplication inside live `zcash/halo2` `MockProver` + real IPA `create_proof` / `verify_proof` circuits.
2. **Zero-`sorry` Formal Soundness**: `lake build` compiles cleanly in `< 20` seconds with **zero `sorry` and zero custom `axiom`s** (`#print axioms` checked) across all `Pasta` and `BLS12-381` CRT carry/quotient theorems.
3. **100% Test & Lint Gate**: `cargo +stable test`, `cargo +stable clippy --all-targets -- -D warnings`, `MockProver::verify` (including negative malicious-witness rejection tests), and `100,000+` differential fuzz iterations against `zkcrypto/bls12_381` and `pasta_curves` exit `0`.

---

## 6. Project Schedule & Milestones (8 Weeks · `USD 0` Startup · `USD 30,000` Total)

- **Startup Funding (`schedule_startup`)**: `USD 0`
  - *Justification (`schedule_startup_justification`)*: `USD 0` upfront requested; our core `#![no_std]` `BLS12-381` & `Pasta` prototype (`rust_crates/src/halo2_gadgets.rs`) is already implemented and passing tests, eliminating startup risk for ZCG.

### Milestone Details (`schedule_milestones`)

```yaml
- Milestone: 1
  Amount (USD): 15000
  Expected Completion Date: Week 4 (4 weeks from grant approval)
  User Stories:
    - "As a Zcash Halo2 circuit engineer, I want drop-in, audited Pasta wrong-field (Pallas/Vesta) and non-native BLS12-381 (Fp2, Fp6 Rank-11, Fp12 CRT-30, sparse mul_by_014) chips parameterized over 8/12/16-bit lookup tables, so that Sapling-to-Halo2 bridges, BLS signature verifiers, and cross-curve gadgets fit into smaller 2^k Halo2 domains."
    - "As a Zcash security reviewer, I want negative MockProver witness-tampering tests (excess quotient bits, non-canonical limbs >= p, boundary p - 1 vectors) on every gadget, so that under-constrained non-native hints are impossible."
  Deliverables:
    - "Open-source `halo2-bilinear-opt` Rust crate (`MIT OR Apache-2.0`, `#![forbid(unsafe_code)]`, `#![no_std]` core + `zcash/halo2` Chip integration, `CONTRIBUTING.md` following `librustzcash` guidelines)."
    - "Complete Halo2 PlonKish chips for `Pasta` wrong-field CRT arithmetic (`3x88`-bit and `4x64`-bit with exact `quoBits` + `crtLowCarries`) and `BLS12-381` pairing towers (`Fp2` Rank-3, `Fp6` Rank-11, `Fp12` `CRT-30`, sparse `mul_by_014`, and Miller-loop + final exponentiation gadget)."
    - "`100,000`-iteration differential fuzz suite against `zkcrypto/bls12_381` and `zcash/pasta_curves` plus adversarial `MockProver` soundness rejection suite (corrupted quotient high bits, carry overflow, and `>= p` aliasing)."
  Acceptance Criteria: >
    `cargo +stable test --all-features` and `cargo +stable clippy --all-targets -- -D warnings`
    exit 0; live `zcash/halo2` `MockProver` + IPA `create_proof`/`verify_proof` tests confirm
    >= 24% cell reduction on `BLS12-381` `Fp12` (`CRT-30` vs `54`-mul baseline) and >= 9.9% cell
    reduction on `Pasta` wrong-field multiplication, with all malicious-witness tests rejected RED.

- Milestone: 2
  Amount (USD): 15000
  Expected Completion Date: Week 8 (8 weeks from grant approval)
  User Stories:
    - "As a Zcash protocol researcher working on Tachyon-style recursive proof aggregation or Zebra batch verification, I want reproducible Halo2 IPA prover wall-clock, RAM, and 2^k row-threshold benchmarks for Pasta wrong-field and BLS12-381 pairing circuits, so that I can size recursive aggregation circuits accurately."
    - "As a cryptographic auditor, I want zero-sorry Lean 4 machine-checked proofs of every unimodular tower isomorphism and non-native CRT quotient/carry soundness bound, so that circuit soundness does not rely on hand-checked inequalities."
  Deliverables:
    - "Zebra / Tachyon recursive proof-aggregation & Sapling/BLS bridge benchmark harness (`cargo bench` Criterion suite + reproducible Markdown/JSON report measuring Halo2 `k`-domain step-downs, IPA proving latency, verifier time, and peak memory)."
    - "Self-contained Core Lean 4 formal verification suite (`lean4_certs/`) proving (i) universal ring equivalence of `BLS12-381` `Fp6` Rank-11, `Fp12` Rank-23, sparse `mul_by_014` Rank-18/19/21, and `CRT-30`, and (ii) exact integer CRT uniqueness `|LHS - (r + s*k*p)| < q_Pasta * 2^(t * n_low)` for `3x88`-bit and `4x64`-bit `Pasta` and `5x88`/`6x64`-bit `BLS12-381` gadgets (`0` `sorry`, `0` custom `axiom`s)."
    - "Published `halo2-bilinear-opt` v0.2.0 crate release, comprehensive developer documentation, and upstream optimization PR(s) submitted to Zcash ecosystem repositories."
  Acceptance Criteria: >
    `lake build` exits 0 in < 20s with `#print axioms` showing only standard Lean kernel axioms;
    `cargo bench` aggregation suite reproduces end-to-end Halo2 IPA wall-clock and cell-count
    tables cleanly from a fresh clone; public benchmark & audit report published on GitHub and
    the Zcash Community Forum thread.
```

---

## 7. Supporting Documents & Live Verification Links (`supporting_documents`)

- **`zk-bilinear-opt` Main Repository & `#![no_std]` Zcash Halo2 Prototype**: [`https://github.com/Impius-Lab/zk-bilinear-opt`](https://github.com/Impius-Lab/zk-bilinear-opt) (`rust_crates/src/halo2_gadgets.rs` & `targets/pairing_towers/bls12_381_fp12_pareto.json`)
- **Live Upstream PR 1 (`Consensys/gnark#1950` — Native 2-Chain `BLS12-377` `-32.84%` `PairingCheck`)**: [`https://github.com/Consensys/gnark/pull/1950`](https://github.com/Consensys/gnark/pull/1950)
- **Live Upstream PR 2 (`Consensys/gnark#1951` — Emulated `BN254`/`BLS12-381` `-478,847` PlonK Gates & CRT Soundness Fix)**: [`https://github.com/Consensys/gnark/pull/1951`](https://github.com/Consensys/gnark/pull/1951)
- **Live Upstream PR 3 (`Plonky3/Plonky3#2600` — `4.26x` `QM31` & `-56.25%..-76.56%` `p3-air` `ExtensionAlgebra`)**: [`https://github.com/Plonky3/Plonky3/pull/2600`](https://github.com/Plonky3/Plonky3/pull/2600)
- **Live Upstream PR 4 (`starkware-libs/proving#9` — `2.71x` `stwo` `QM31` & `-59.1%` AIR/Cairo Verifier Muls)**: [`https://github.com/starkware-libs/proving/pull/9`](https://github.com/starkware-libs/proving/pull/9)
- **Live Upstream PR 5 (`starkware-libs/proving#10` — `stwo` SIMD `BaseColumn` Memory-Safety UB Fix)**: [`https://github.com/starkware-libs/proving/pull/10`](https://github.com/starkware-libs/proving/pull/10)
- **Live Upstream PR 6 (`aleo-labs-protocol/snarkVM#3908` — `BLS12-377` `-26.96%` Pairing & `-32.91%` `FinalExp`)**: [`https://github.com/aleo-labs-protocol/snarkVM/pull/3908`](https://github.com/aleo-labs-protocol/snarkVM/pull/3908)
- **Interactive Prover & Verifier Benchmark Dashboard**: [`https://impius-lab-zk.weight-space-engineering.workers.dev`](https://impius-lab-zk.weight-space-engineering.workers.dev)
