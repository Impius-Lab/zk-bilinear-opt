# Module A — StarkWare `stwo` Circle STARK `QM31` (`9 -> 7` Multiplications, `-22.22%`)

## 1. Algebraic Isomorphism: `QM31` $`\cong \mathbb{M}_{31}[u]/(u^4 - 4u^2 + 5)`$

In StarkWare's Circle STARK prover (`starkware-libs/stwo`), the 124-bit security extension field (`SecureField`) is constructed over the Mersenne-31 prime $`p = 2^{31} - 1 = 2147483647`$ as a two-step tower:

```math
\mathrm{CM31} = \mathbb{M}_{31}[i]/(i^2 + 1), \qquad \mathrm{QM31} = \mathrm{CM31}[u]/\big(u^2 - (2 + i)\big),
```

represented in flat coordinate order `[a0, a1, b0, b1]` corresponding to $`(a_0 + a_1 i) + (b_0 + b_1 i) u`$.

Standard double-Karatsuba (`3 x 3`) requires **`9` $`\mathbb{M}_{31}`$ multiplications** (and `9` degree-2 bilinear constraints per `QM31` product inside recursive AIR / R1CS verifiers).

### Explicit Unimodular Simple-Extension Proof
Since $`u^2 = 2 + i`$, we have $`i = u^2 - 2`$, and squaring both sides yields:

```math
(u^2 - 2)^2 = i^2 = -1 \implies g(u) := u^4 - 4u^2 + 5 = 0.
```

Rabin's irreducibility test (`zk_bilinear.fields.is_irreducible_rabin`) certifies that $`g(X) = X^4 - 4X^2 + 5`$ is **irreducible over $`\mathbb{M}_{31}`$**. Substituting $`i = u^2 - 2`$ into `(a0 + a1*i) + (b0 + b1*i)*u` gives the **unimodular ($`\det = 1`$) integer change of basis**:

```math
x = (a_0 - 2a_1) + (b_0 - 2b_1) u + a_1 u^2 + b_1 u^3,
```

with inverse reconstruction $`a_0 = c_0 + 2c_2,\; a_1 = c_2,\; b_0 = c_1 + 2c_3,\; b_1 = c_3`$ requiring **zero divisions** and coefficients in $`\{-2, 0, 1, 2\}`$.

## 2. Certified Optimal Rank-`7` Decomposition & `u64` Zero-Overflow Proof

By Winograd (1977) / Alder–Strassen (1981), any degree-4 field extension over $`\mathbb{F}_p`$ satisfies $`R_{\mathbb{F}_p}(\mathbb{F}_{p^4}) \ge 2(4) - 1 = 7`$. Evaluating at the smallest symmetric integer projective nodes $`\{-2, -1, 0, 1, 2, 3, \infty\}`$ and folding the unimodular basis maps directly into $`(U, V, W_{\mathbb{Z}}, D)`$ (`D = 120`) yields `QM31_Rank7`:

| Metric | `stwo` Baseline (`QM31_Karatsuba9`) | Certified `QM31_Rank7` | Delta |
| :--- | :---: | :---: | :---: |
| Base $`\mathbb{M}_{31}`$ Multiplications / R1CS Constraints | `9` | **`7`** | **`-22.22%`** |
| Degree-2 Recursive AIR Bilinear Terms | `9` | **`7`** | **`-22.22%`** |
| Basis-Complete Identity Checks ($`d^2`$) | `16 / 16` | **`16 / 16`** | Exact |
| Max Input Row $`\ell_1`$ Norm $`\max_\ell \Vert U_\ell\Vert_1`$ | `4` | `32` | $`< 2^{36}`$ in `i64` |
| Peak Hardware Accumulator Bit-Width (`i64` / `u64`) | `62 bits` | **`62 bits`** | **`< 2^63` (0 overflow)** |

### Exact `i64` / `u64` Accumulator Bound
For canonical inputs $`a_k, b_k \in [0, 2^{31} - 2]`$:
1. **Evaluation (`U * a`, `V * b`)**: $`\max_\ell \Vert U_\ell\Vert_1 (p - 1) = 32 \cdot (2^{31} - 2) < 2^{36} \ll 2^{63} - 1`$.
2. **Pointwise Products (`m_l`)**: $`(p - 1)^2 = (2^{31} - 2)^2 < 2^{62} < 2^{63} - 1`$.
3. **Integer Interpolation (`W_z * m`)**: $`\max_k \Vert W_{\mathbb{Z}, k}\Vert_1 (p - 1) = 1210 \cdot (2^{31} - 2) < 2^{41.3} \ll 2^{63} - 1`$.
4. **Denominator Scaling (`* 120^{-1} mod p`)**: $`(p - 1) \cdot \mathrm{INV\_120} \le (p - 1)^2 < 2^{62} < 2^{63} - 1`$.

## 3. Artifacts in This Directory
- [`qm31_rank7_cert.json`](./qm31_rank7_cert.json): Deterministic R1CS + algebraic certificate (`schedule_sha256: 1d9d3c602a89...`).
- [`qm31_stwo.rs`](./qm31_stwo.rs): Zero-overflow `#![no_std]` Rust `mul_qm31_rank7` and `mul_qm31_karatsuba9` kernels.
