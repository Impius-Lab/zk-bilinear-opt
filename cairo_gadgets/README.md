# `zk_qm31_opt` — Verified Cairo `QM31` Multiplication & Squaring Gadgets

Standalone Cairo (`edition = "2024_07"`, Scarb `2.21.0`) verifier arithmetic package implementing canonical `u64`-backed Mersenne-31 ($`p = 2^{31} - 1 = 2147483647`$) field operations and three algebraically certified multiplication and squaring schedules for StarkWare's Circle STARK quartic extension field:

```math
\mathrm{CM31} = \mathbb{M}_{31}[i]/(i^2 + 1), \qquad \mathrm{QM31} = \mathrm{CM31}[u]/\big(u^2 - (2 + i)\big).
```

Coordinates follow canonical `stwo` flat order `(c0, c1, c2, c3)` representing $`(c_0 + c_1 i) + (c_2 + c_3 i) u`$.

---

## 1. Implemented Schedules & Backend Cost Duality

| Schedule | Cairo Entrypoints | `M31` Var×Var Muls | Non-Unit `Const * Var` Muls | 64-Iter Cairo VM Steps | 64-Iter `range_check_builtin` | Target Optimal Backend |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Schoolbook-16** | `qm31_mul_schoolbook` / `qm31_square_schoolbook` | `16` / `16` | `0` | `70,019` / `70,067` | `14,013` / `13,920` | Reference tower specification |
| **Unimodular Karatsuba-9 / 6** | `qm31_mul_karatsuba9` / `qm31_square_karatsuba6` | **`9` / `6`** | **`0`** | **`51,641` (`-26.25%`) / `39,738` (`-43.29%`)** | **`10,719` (`-23.51%`) / `8,129` (`-41.60%`)** | **Cairo VM (`stwo_cairo_verifier`, `proving#9`), `stwo-circuits`** |
| **Winograd Rank-7** | `qm31_mul_rank7` / `qm31_square_rank7` | **`7` / `7`** | `26` (`u64` linear + `120^-1`) | `93,404` / `74,782` | `20,106` / `16,219` | **BitVM2 Tapscript, `gnark` R1CS, `Plonky3` `p3-air`** |

### Why Both `Karatsuba-9` and `Rank-7` Are Necessary
- **Explicit `Const * Var` Backends (Cairo Sierra/CASM, `stwo_cairo_verifier`, `stwo-circuits`)**: Every `u64` scaling by $`c \notin \{0, \pm 1\}`$ compiles to a range-checked `u64_wide_mul`. Eliminating all non-unit constants via unimodular $`\{0, +1, -1\}`$ nested Karatsuba cuts Cairo VM execution steps by **`-26.25%`** for multiplication (`qm31_mul_karatsuba9`) and **`-43.29%`** for squaring (`qm31_square_karatsuba6`).
- **Free Linear-Scaling Backends (BitVM2 Tapscript, Native R1CS, Degree-2 STARK AIR)**: When linear combinations and small constant shifts fold into degree-0 constraints or cheap Tapscript shift/adds (`OP_M31_SCALE_SMALL`), Alder–Strassen optimal `Rank-7` (`qm31_mul_rank7`) achieves the theoretical minimum $`2d - 1 = 7`$ variable-variable $`\mathbb{M}_{31}`$ multiplications (**`-22.22%`** vs `Karatsuba-9`, **`-56.25%`** vs `Schoolbook-16`).

---

## 2. Exact Unimodular Simple-Extension Isomorphism (`Rank-7`)

Since $`u^2 = 2 + i`$ in $`\mathrm{QM31}`$, setting $`v = u`$ gives $`i = v^2 - 2`$ and $`(v^2 - 2)^2 = i^2 = -1`$, so $`v^4 - 4v^2 + 5 = 0`$ (irreducible over $`\mathbb{M}_{31}`$). Substituting $`i = v^2 - 2`$ into $`(a_0 + a_1 i) + (a_2 + a_3 i) u`$ yields the unimodular ($`\det T = -1 \in \{\pm 1\}`$) integer basis isomorphism matching [`targets/qm31_stwo/qm31_rank7_cert.json`](../targets/qm31_stwo/qm31_rank7_cert.json):

```math
T = \begin{pmatrix} 1 & -2 & 0 & 0 \\ 0 & 0 & 1 & -2 \\ 0 & 1 & 0 & 0 \\ 0 & 0 & 0 & 1 \end{pmatrix}, \qquad T^{-1} = \begin{pmatrix} 1 & 0 & 2 & 0 \\ 0 & 0 & 1 & 0 \\ 0 & 1 & 0 & 2 \\ 0 & 0 & 0 & 1 \end{pmatrix}, \qquad T \begin{pmatrix} a_0 \\ a_1 \\ a_2 \\ a_3 \end{pmatrix} = \begin{pmatrix} a_0 - 2a_1 \\ a_2 - 2a_3 \\ a_1 \\ a_3 \end{pmatrix}.
```

Evaluating $`P(v) = (a_0 - 2a_1) + (a_2 - 2a_3)v + a_1 v^2 + a_3 v^3`$ at the 7 projective Vandermonde nodes $`\{-2, -1, 0, 1, 2, 3, \infty\}`$ produces the certified $`(U, V, W_{\mathbb{Z}}, D = 120)`$ bilinear decomposition with $`120^{-1} \bmod (2^{31} - 1) = 304226850`$.

### Single-Pass `u64` Mersenne Folding (`m31_fold_u62`)
For any integer $`0 \le x \le (p - 1)^2 = (2^{31} - 2)^2 < 2^{62}`$, writing $`x = q \cdot 2^{31} + r`$ ($`0 \le r \le p`$) satisfies $`0 \le q + r \le 2p - 4 < 2p`$. Thus `m31_fold_u62(x)` reduces $`x \bmod p`$ into canonical $`[0, p - 1]`$ with a single power-of-two split and at most one conditional subtraction of $`p`$.

---

## 3. Running Verification Locally

With Scarb (`>= 2.21.0`) on `PATH`:

```sh
cd cairo_gadgets
scarb build
scarb lint
scarb test --print-resource-usage
```

The `#[cfg(test)]` suite verifies:
- Canonical `M31` arithmetic, `m31_fold_u62` boundary exactness at $`(p - 1)^2`$ and $`q + r = 2p - 4`$, and $`120 \cdot 304226850 \equiv 1 \pmod p`$.
- All `16` canonical basis pairs $`(e_a, e_b)`$ and tower relations $`i^2 = -1`$, $`u^2 = 2 + i`$, $`(iu)^2 = -(2 + i)`$.
- Unimodular isomorphism roundtrip $`T^{-1}(T(x)) = x`$, $`v^4 - 4v^2 + 5 = 0`$, and folded 7-point Vandermonde evaluation equivalence.
- Zero, unit, and worst-case `u64` accumulator boundary vectors `(P - 1, P - 1, P - 1, P - 1)`.
- `200` deterministic SplitMix64 pseudo-random `QM31` pairs across multiplication, squaring, commutativity, and distributivity, plus 64-iteration resource profiling chains.
