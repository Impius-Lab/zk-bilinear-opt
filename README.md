# `zk-bilinear-opt` — Certified Optimal Bilinear Extension & Pairing-Tower Gadgets for ZK Circuits

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](./LICENSE-MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB.svg)](./pyproject.toml)
[![Go 1.23+](https://img.shields.io/badge/go-1.23%2B-00ADD8.svg)](./go_gadgets/go.mod)
[![no_std Rust](https://img.shields.io/badge/rust-no__std-DEA584.svg)](./rust_crates/Cargo.toml)

`zk-bilinear-opt` is an exact finite-field bilinear rank certifier, non-native limb-carry Pareto optimizer, and deterministic `#![no_std]` Rust / Go / R1CS code generator for Zero-Knowledge STARK and SNARK extension towers (**StarkWare `stwo`**, **`Plonky3` / `SP1`**, and **`Consensys/gnark`**).

---

## 1. Executive Benchmark Summary

Every schedule in this repository is verified across **100% of canonical $`d^2`$ basis pairs** (which by $`\mathbb{F}_p`$-bilinearity proves exact algebraic identity across all $`p^{2d}`$ field pairs), cross-checked against **102,000 randomized differential fuzz samples**, and bounded under adversarial hardware (`i64`/`u64`/`u128`) and non-native (`4x64` / `6x64`) limb-overflow inputs.

### A. Native STARK / Recursive AIR / R1CS Extension Towers (`stwo` & `Plonky3` / `SP1`)

| Target Extension | Ecosystem | Prime $`p`$ | Deg $`d`$ | Upstream Baseline | Certified Optimal Rank ($`2d-1`$) | Bilinear Gate / R1CS Savings | Peak Native Word Bits |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`QM31`** (`SecureField`) | StarkWare `stwo` | $`2^{31} - 1`$ | `4` | `9` (`3x3` Karatsuba) | **`7`** (`u^4 - 4u^2 + 5`) | **`-22.22%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| **`BabyBear^4`** | `Plonky3` / `SP1` | $`2^{31} - 2^{27} + 1`$ | `4` | `9` (Karatsuba-4) | **`7`** (`X^4 - 11`) | **`-22.22%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| **`BabyBear^5`** | `Plonky3` / `SP1` | $`2^{31} - 2^{27} + 1`$ | `5` | `15` (Karatsuba-5) | **`9`** (`X^5 - 2`) | **`-40.00%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| **`KoalaBear^4`** | `Plonky3` | $`2^{31} - 2^{24} + 1`$ | `4` | `9` (Karatsuba-4) | **`7`** (`X^4 - 3`) | **`-22.22%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| **`KoalaBear^8`** | `Plonky3` | $`2^{31} - 2^{24} + 1`$ | `8` | `27` (`3^3` Karatsuba) | **`15`** (`X^8 - 3`) | **`-44.44%`** | `63b` (`< 2^63` via 2-term `u64`) |
| **`Goldilocks^2`** | `Plonky2` / `Plonky3` | $`2^{64} - 2^{32} + 1`$ | `2` | `3` (Karatsuba-2) | **`3`** (`X^2 - 7`) | Optimal ($`2d-1`$) | `128b` (`< 2^128` in `u128`) |
| **`Goldilocks^4`** | `Plonky3` | $`2^{64} - 2^{32} + 1`$ | `4` | `9` (Karatsuba-4) | **`7`** (`X^4 - 7`) | **`-22.22%`** | `128b` (`< 2^128` in `u128`) |
| **`Goldilocks^5`** | `Plonky3` | $`2^{64} - 2^{32} + 1`$ | `5` | `15` (Karatsuba-5) | **`9`** (`X^5 - 3`) | **`-40.00%`** | `128b` (`< 2^128` in `u128`) |

### B. Non-Native Emulated Pairing Towers (`Consensys/gnark` $`4\times 64`$-bit `BN254` & $`6\times 64`$-bit `BLS12-381`)

*(All constraint counts below are **NET** totals over a 254-bit SNARK scalar field — explicitly counting every Toom-limb product, quotient witness, pre-multiplication `Reduce()`, and 2-limb carry range-check bit!)*

| Pairing Target | Emulated Limbs | Upstream `gnark` Baseline | Certified Pareto Winner | Native $`\mathbb{F}_p`$ Muls | Pre-Mul `Reduce()` | Net Groth16 R1CS (Savings) | Net PlonK16 Gates (Savings) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`BN254` `Fp6`** | $`4 \times 64`$-bit | `Tower-18` (`15,150` R1CS) | **`Rank-11`** (`{-5..4, inf}`) | `18 -> 11` (`-38.89%`) | `0` | **`11,582` (`-23.55%`)** | **`2,037` (`-23.42%`)** |
| **`BN254` `Fp12`** | $`4 \times 64`$-bit | `Tower-54` (`44,619` R1CS) | **`CRT-30`** (`9` lin + `7` quad) | `54 -> 30` (`-44.44%`) | `0` | **`31,497` (`-29.41%`)** | **`6,171` (`-24.45%`)** |
| **`BN254` `Fp12`** *(Tower)* | $`4 \times 64`$-bit | `Tower-54` (`44,619` R1CS) | **`Tower-33`** (`Toom-6 x K-2`) | `54 -> 33` (`-38.89%`) | `0` | **`32,278` (`-27.66%`)** | **`6,229` (`-23.74%`)** |
| **`BLS12-381` `Fp6`** | $`6 \times 64`$-bit | `Tower-18` (`23,196` R1CS) | **`Rank-11`** (`{-5..4, inf}`) | `18 -> 11` (`-38.89%`) | `0` | **`17,081` (`-26.36%`)** | **`3,485` (`-27.26%`)** |
| **`BLS12-381` `Fp12`** | $`6 \times 64`$-bit | `Tower-54` (`68,032` R1CS) | **`CRT-30`** (`9` lin + `7` quad) | `54 -> 30` (`-44.44%`) | `0` | **`46,078` (`-32.27%`)** | **`10,235` (`-29.83%`)** |
| Native $`\mathbb{F}_p`$ `Fp12` | Native wire | `Tower-54` (`54` R1CS) | **`Rank-23`** (`{-11..10, inf}`) | **`54 -> 23` (`-57.41%`)** | N/A | **`23` (`-57.41%`)** | Native R1CS Optimal |

---

## 2. Mathematical Foundations

### 2.1 Why Bounded-Norm Bilinear Rank Beats Karatsuba in ZK Circuits
On a CPU, additions and multiplications both consume ALU cycles, making Karatsuba (`3` muls for quadratic, `9` for quartic, `18` for sextic, `54` for dodecic) a standard default. Inside **R1CS, PlonK custom gates, and degree-2 STARK AIRs**, fixed-constant linear combinations fold into $`(A, B, C)`$ matrices or degree-1 symbolic expressions for **zero multiplicative gates** — **unless** large evaluation constants trigger `u64` register overflow on CPU provers or inflate limb-carry range checks in non-native circuits!

Our engine synthesizes exact integer-rational bilinear decompositions:

```math
a \cdot b = \frac{1}{D} W_{\mathbb{Z}} \Big((U a) \odot (V b)\Big) \pmod{p}, \qquad U, V \in \mathbb{Z}^{r \times d},\; W_{\mathbb{Z}} \in \mathbb{Z}^{d \times r},\; \gcd(D, p) = 1,
```

co-optimizing bilinear rank $`r`$, input row product slack $`\Vert U_\ell\Vert_1 \Vert V_\ell\Vert_1`$, and output denominator/numerator weight $`\Vert W_{\mathbb{Z}, k}\Vert_1 + D`$.

### 2.2 Winograd (1977) / Alder–Strassen (1981) $`2d - 1`$ Lower Bound
Let $`K = \mathbb{F}_p[X]/(f(X))`$ with $`f`$ irreducible of degree $`d`$ over $`\mathbb{F}_p`$ (verified via Rabin's test in `zk_bilinear/fields.py`). Suppose $`m(x, y) = \sum_{\ell=1}^r u_\ell(x) v_\ell(y) w_\ell`$ computes multiplication in $`K`$. Because $`K`$ has zero left-annihilator, $`\mathrm{span}(u_1, \dots, u_r) = K^*`$; reordering so $`u_1, \dots, u_d`$ are linearly independent, $`\bigcap_{\ell=1}^{d-1} \ker(u_\ell) \subset K`$ has dimension $`1`$. Picking $`0 \ne x_0`$ in that intersection gives $`x_0 K \subseteq \mathrm{span}(w_d, \dots, w_r)`$. Since $`K`$ is a field, $`y \mapsto x_0 y`$ has full image $`K`$ of dimension $`d`$, forcing $`r - (d - 1) \ge d \iff \mathbf{r \ge 2d - 1}`$. Because $`\vert \mathbb{P}^1(\mathbb{F}_p)\vert = p + 1 \ge 2d - 1`$ for all ZK primes here, $`R_{\mathbb{F}_p}(K) = 2d - 1`$ is attained exactly.

### 2.3 Division-Free Unimodular ($`\det = \pm 1`$) Tower-to-Simple Isomorphisms
Stacked quadratic/cubic towers hide simple-extension structure. We prove explicit **integer unimodular ($`\det = \pm 1`$) basis transformations** (`T_from * T_to = I_d` over $`\mathbb{Z}`$, zero divisions):
- **`stwo` `QM31`**: $`u^2 = 2 + i \implies i = u^2 - 2 \implies \mathbf{u^4 - 4u^2 + 5 = 0}`$, mapping `(a0 + a1*i) + (b0 + b1*i)*u` $`\mapsto`$ `(a0 - 2*a1) + (b0 - 2*b1)*u + a1*u^2 + b1*u^3`.
- **`BN254` ($`\xi = 9 + u`$)**: $`u = v^3 - 9 = w^6 - 9 \implies \mathbf{v^6 - 18v^3 + 82 = 0}`$ (`Fp6`) and $`\mathbf{w^{12} - 18w^6 + 82 = 0}`$ (`Fp12`).
- **`BLS12-381` ($`\xi = 1 + u`$)**: $`u = v^3 - 1 = w^6 - 1 \implies \mathbf{v^6 - 2v^3 + 2 = 0}`$ (`Fp6`) and $`\mathbf{w^{12} - 2w^6 + 2 = 0}`$ (`Fp12`).

### 2.4 The `56`-Bit Non-Native Limb-Carry Phase Transition (`CRT-30` vs `Rank-23`)
In `gnark`-style non-native arithmetic over a 254-bit SNARK scalar field, packing two adjacent 64-bit limb equations (`128 + 64 = 192` bits, plus `4` bits for signed carry + co-addition) leaves **`56` bits** (`192 + 4 + 56 = 252 < 254`) for $`L \cdot \Vert U_\ell\Vert_1 \cdot \Vert V_\ell\Vert_1`$:
- Naive `Rank-23` Vandermonde (`{-11..10, inf}`) hits $`\vert -11\vert^{11} \approx 2^{38.1}`$ (`77`-bit slack $`> 56`$-bit), triggering **22 mandatory pre-multiplication `Reduce()` gadgets** and `113`-bit 2-limb output quotients (`34,444` R1CS on `BN254`).
- Our **Cyclotomic/Quadratic CRT schedule `CRT-30`** (`9` small linear nodes `{-4..3, inf}` + `7` small/cyclotomic quadratic moduli $`\Phi_4, \Phi_3, \Phi_6, \dots`$) caps slack at **`45` bits (`<= 56`b, `0` pre-reductions!)** and $`D`$ at **`45.2` bits** (single-word output quotients!), slashing net Groth16 R1CS to **`31,497` (`-29.41%`)** on `BN254` and **`46,078` (`-32.27%`)** on `BLS12-381`.

---

## 3. Quickstart & Verification

All Python tools use the zero-external-dependency Python 3.12 stdlib package `zk_bilinear`:

```powershell
# 1. Verify all 51 schedules (2,654 basis-pair identities + irreducibility + overflow bounds)
.\.venv\Scripts\python.exe -m zk_bilinear verify

# 2. Deterministically regenerate all JSON certificates, Rust/Go kernels, and benchmark report
.\.venv\Scripts\python.exe -m zk_bilinear generate-all

# 3. Run the full Python test suite (102,000 fuzz samples + overflow proofs + adversarial mutations)
.\.venv\Scripts\python.exe -m unittest discover -s tests -v

# 4. Run the native Go 1.25 gadget test suite (QM31, Plonky3, BN254 & BLS12-381 Fp6/Fp12)
Set-Location go_gadgets
& "C:\Program Files\Go\bin\go.exe" test -v ./...
```

---

## 4. Repository Architecture

```text
zk-bilinear-opt/
├── zk_bilinear/
│   ├── fields.py           # Exact primes, Rabin irreducibility, reference towers & unimodular isomorphisms
│   ├── tensor_cert.py      # Basis-complete d^2 algebraic verifier + u64/u128 adversarial overflow checker
│   ├── cost_models.py      # Native R1CS/PlonK/AIR + gnark 2-limb carry-packed non-native R1CS/PlonK16 models
│   ├── pareto_search.py    # Vandermonde, Cyclotomic-CRT & Binomial-Tower synthesis (51 certified schedules)
│   ├── codegen.py          # Deterministic #![no_std] Rust, Go math/big & R1CS JSON certificate emitters
│   └── cli.py              # CLI (`verify`, `generate-all`, `report`)
├── targets/
│   ├── qm31_stwo/          # Module A: StarkWare stwo QM31 (9 -> 7 muls, -22.22%, <2^63 u64-safe)
│   ├── plonky3_extensions/ # Module B: BabyBear^{4,5}, KoalaBear^{4,8}, Goldilocks^{2,4,5} JSON + Rust
│   └── pairing_towers/     # Module C: BN254 & BLS12-381 Fp6 (18 -> 11) & Fp12 Pareto curves
├── rust_crates/            # Reference #![no_std] Rust crate (`Cargo.toml` + `src/lib.rs` + `src/generated.rs`)
├── go_gadgets/             # Native Go module (`go.mod` + `gadgets.go` + `gadgets_generated.go` + `gadgets_test.go`)
├── tests/                  # Unittest suite: basis proofs, 102,000 fuzz checks, limb bounds & mutation selftest
└── monetization/           # Reproducible benchmarks, grant proposals (AI4Math & ZK ESP), PR briefs & B2B offer
```

---

## 5. Author & License

**Author**: Houssem Aguentil (`Aguentil H.`) — Impius-Lab (`2aghous94@gmail.com`) · [https://github.com/Impius-Lab/zk-bilinear-opt](https://github.com/Impius-Lab/zk-bilinear-opt)

Dual-licensed under either of **[MIT License](./LICENSE-MIT)** or **[Apache License, Version 2.0](./LICENSE-APACHE)** at your option.
