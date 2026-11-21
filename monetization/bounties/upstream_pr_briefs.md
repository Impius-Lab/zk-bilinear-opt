# Upstream GitHub Issue & Pull Request Specifications

Ready-to-open upstream engineering briefs backed by reproducible certificates in `targets/`, `rust_crates/`, and `go_gadgets/`.

---

## 1. `starkware-libs/stwo` — Optimal 7-Mul `QM31` Recursive AIR & Verifier Gadget (`-22.22%`)

### Proposed Issue / PR Title
`perf(qm31): reduce QM31 bilinear constraint rank from 9 to 7 (-22.22%) via unimodular u^4 - 4u^2 + 5 isomorphism`

### Technical Summary for Maintainers
Currently, `QM31` (`CM31[u]/(u^2 - (2 + i))` over $p = 2^{31} - 1$) multiplication in recursive AIR constraints and non-SIMD verifier paths uses 2-level Karatsuba (`3 * 3 = 9` `M31` bilinear multiplications).

Because $u^2 = 2 + i \implies (u^2 - 2)^2 = i^2 = -1$, `QM31` is canonically isomorphic to the simple monic quartic field $\mathbb{M}_{31}[u]/(u^4 - 4u^2 + 5)$ via the **division-free unimodular ($\det = 1$) integer change of basis**:
```text
(a0 + a1*i) + (b0 + b1*i)*u  <-->  (a0 - 2*a1) + (b0 - 2*b1)*u + a1*u^2 + b1*u^3
```
Interpolating on the symmetric projective nodes `{-2, -1, 0, 1, 2, 3, inf}` attains the **exact Winograd / Alder–Strassen lower bound of `7` `M31` multiplications (`-22.22%`)**:
- **Degree-2 AIR / Recursive Verifier Impact**: Cuts degree-2 `M31` bilinear terms per `QM31` multiplication from `9` to `7` (`0` extra degree cost for constant linear combinations).
- **BitVM2 / Bitcoin Script Impact**: Cuts expensive `M31` multiplication opcodes per `QM31` product from `9` to `7` while replacing interpolation divisions by $120^{-1} \bmod p$ (where $2^{-3}$ is a free Mersenne bit-rotation!).
- **Zero `u64` / `i64` Overflow Guarantee**: Across all inputs in $[0, 2^{31}-2]^4$, peak intermediate magnitude in `U*a`, `V*b`, `m_l`, `W_z*m`, and `* INV_120` is **strictly $\le 62$ bits (`< 2^63`)**, verified exhaustively on basis pairs + adversarial sign-aligned vectors + `14,000` fuzz samples (`targets/qm31_stwo/`).

### Files Touched in Proposed PR
- `crates/prover/src/core/fields/qm31.rs` (optional verifier/AirEval helper `mul_bilinear_rank7`)
- `crates/constraint-framework/` (`EvalAtRow` `QM31` degree-2 bilinear expression evaluator)

---

## 2. `Plonky3/Plonky3` — Optimal $2d - 1$ `BinomialExtensionField` AIR Constraint Evaluators (`-22.22%` to `-44.44%`)

### Proposed Issue / PR Title
`feat(field,air): optimal (2D - 1)-mul bilinear evaluators for BabyBear^{4,5}, KoalaBear^{4,8}, and Goldilocks^{4,5}`

### Technical Summary for Maintainers
In recursive STARK verification (`p3-uni-stark` / `SP1` recursion), `BinomialExtensionField<F, D>` expressions over `AB::Expr` treat multiplication by compile-time `F` constants as degree-0 scalar scaling (`0` extra trace columns), while `AB::Expr * AB::Expr` consumes degree budget / auxiliary columns.

Replacing recursive Karatsuba (`9` muls for $D=4$, `15` for $D=5$, `27` for $D=8$) with small-node projective Lagrange interpolation achieves the **provably minimal Winograd / Alder–Strassen rank $2D - 1$** across every `Plonky3` extension:

| `Plonky3` Extension | Polynomial | Current Karatsuba Muls | Certified Optimal Rank | Constraint Reduction | Accumulator Proof |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `BinomialExtensionField<BabyBear, 4>` | $X^4 - 11$ | `9` | **`7`** | **`-22.22%`** | `62b < 2^63` (`i64`/`u64`) |
| `BinomialExtensionField<BabyBear, 5>` | $X^5 - 2$ | `15` | **`9`** | **`-40.00%`** | `62b < 2^63` (`i64`/`u64`) |
| `BinomialExtensionField<KoalaBear, 4>` | $X^4 - 3$ | `9` | **`7`** | **`-22.22%`** | `62b < 2^63` (`i64`/`u64`) |
| `BinomialExtensionField<KoalaBear, 8>` | $X^8 - 3$ | `27` | **`15`** | **`-44.44%`** | `63b < 2^63` (2-term chunked `u64`) |
| `BinomialExtensionField<Goldilocks, 4>` | $X^4 - 7$ | `9` | **`7`** | **`-22.22%`** | `128b < 2^128` (`u128`) |
| `BinomialExtensionField<Goldilocks, 5>` | $X^5 - 3$ | `15` | **`9`** | **`-40.00%`** | `128b < 2^128` (`u128`) |

Reference `#![no_std]` implementation + generic `SymbolicFieldExpr` evaluator is ready in `rust_crates/src/lib.rs` and `targets/plonky3_extensions/`.

---

## 3. `Consensys/gnark` — Carry-Bounded `Rank-11` (`E6`) & `CRT-30` / `Tower-33` (`E12`) Emulated Pairing Gadgets (`-23.6%` to `-32.3%` Net Constraints)

### Proposed Issue / PR Title
`perf(std/algebra/emulated): cut E6 & E12 non-native R1CS/PlonK constraints by 24%-32% via carry-bounded Rank-11 & Cyclotomic CRT-30`

### Technical Summary for Maintainers
In `std/algebra/emulated/fields_bn254` ($4\times 64$-bit limbs) and `fields_bls12381` ($6\times 64$-bit limbs), `E6.Mul` and `E12.Mul` currently perform tower Karatsuba (`18` and `54` emulated `Fp` multiplications, or witnessed polynomial hints with degree-$5$/$11$ evaluations).

A naive attempt to use `23`-mul degree-12 Vandermonde over `Fp` (`[-11..10, inf]`) **backfires** in `gnark` because $|-11|^{11} \approx 2^{38.1}$ creates `77`-bit product slacks — exceeding `gnark`'s `56`-bit 2-limb malicious-witness non-wrap limit (`128 + 64 + 4 + 56 = 252 < 254` bits) on 22 operands and forcing multi-limb `113`-bit reconstruction quotients.

Using our unimodular simple-extension isomorphisms ($v^6 - 18v^3 + 82 = 0$ / $w^{12} - 18w^6 + 82 = 0$ for `BN254`; $v^6 - 2v^3 + 2 = 0$ / $w^{12} - 2w^6 + 2 = 0$ for `BLS12-381`) paired with **Cyclotomic Chinese Remainder Theorem (`CRT-30`)** and **`Toom-6 x Karatsuba-2` (`Tower-33`)**, we stay **100% inside the 56-bit 2-limb carry-packing budget (`0` pre-mul `Reduce()` calls!)** and single-word output quotients:

- **`BN254` ($4\times 64$-bit)**:
  - `E6.Mul`: `Tower-18` (`15,150` R1CS / `2,660` PlonK16) $\to$ **`Rank-11`** (**`11,582` R1CS `-23.55%`** / **`2,037` PlonK16 `-23.42%`**).
  - `E12.Mul`: `Tower-54` (`44,619` R1CS / `8,168` PlonK16) $\to$ **`CRT-30`** (**`31,497` R1CS `-29.41%`** / **`6,171` PlonK16 `-24.45%`**) or **`Tower-33`** (**`32,278` R1CS `-27.66%`** / **`6,229` PlonK16 `-23.74%`**).
- **`BLS12-381` ($6\times 64$-bit)**:
  - `E6.Mul`: `Tower-18` (`23,196` R1CS / `4,791` PlonK16) $\to$ **`Rank-11`** (**`17,081` R1CS `-26.36%`** / **`3,485` PlonK16 `-27.26%`**).
  - `E12.Mul`: `Tower-54` (`68,032` R1CS / `14,586` PlonK16) $\to$ **`CRT-30`** (**`46,078` R1CS `-32.27%`** / **`10,235` PlonK16 `-29.83%`**).

Native Go reference gadgets passing `go test -v ./...` (`d^2` basis proofs + maximal `(p-1)` checks + randomized fuzzing) are included in `go_gadgets/`.
