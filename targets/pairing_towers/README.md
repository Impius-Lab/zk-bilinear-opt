# Module C — Non-Native Pairing Towers (`BN254` & `BLS12-381` $\mathbb{F}_{p^6}$ and $\mathbb{F}_{p^{12}}$)

## 1. Unimodular Simple-Extension Isomorphisms (`det = +-1`, Zero Divisions)

In `Consensys/gnark` (`std/algebra/emulated/fields_bn254` & `fields_bls12381`) and `arkworks`, pairing towers are defined over $\mathbb{F}_p$ via:
$$\mathbb{F}_{p^2} = \mathbb{F}_p[u]/(u^2 + 1), \qquad \mathbb{F}_{p^6} = \mathbb{F}_{p^2}[v]/(v^3 - \xi), \qquad \mathbb{F}_{p^{12}} = \mathbb{F}_{p^6}[w]/(w^2 - v),$$
where $\xi = \xi_0 + u$ with **$\xi_0 = 9$ for `BN254`** and **$\xi_0 = 1$ for `BLS12-381`**.

Eliminating $u = v^3 - \xi_0$ (on $\mathbb{F}_{p^6}$) and $u = w^6 - \xi_0$ (on $\mathbb{F}_{p^{12}}$) yields **irreducible trinomial simple extensions** over $\mathbb{F}_p$:
- **`BN254` ($\xi_0 = 9$)**: $\mathbb{F}_{p^6} \cong \mathbb{F}_p[v]/(v^6 - 18v^3 + 82)$ and $\mathbb{F}_{p^{12}} \cong \mathbb{F}_p[w]/(w^{12} - 18w^6 + 82)$.
- **`BLS12-381` ($\xi_0 = 1$)**: $\mathbb{F}_{p^6} \cong \mathbb{F}_p[v]/(v^6 - 2v^3 + 2)$ and $\mathbb{F}_{p^{12}} \cong \mathbb{F}_p[w]/(w^{12} - 2w^6 + 2)$.

Crucially, the basis maps $T_{\text{to}}, T_{\text{from}} \in \mathrm{GL}_d(\mathbb{Z})$ between `gnark`'s canonical `[B0.A0..B2.A1]` / `[C0..C1]` coordinates and the power basis have **determinant $\pm 1$ over $\mathbb{Z}$** and entries in $\{-\xi_0, 0, 1, \xi_0\}$, introducing zero rational denominators!

## 2. Exact Non-Native Limb-Carry Pareto Frontier (`4x64` `BN254` & `6x64` `BLS12-381`)

When emulating $\mathbb{F}_p$ over a 254-bit SNARK scalar field (`gnark` 2-limb carry packing: `128 + 64 = 192` bits, leaving **`60` bits** of product slack before mandatory pre-multiplication `Reduce()` gadgets), minimizing base-field multiplications $r$ alone **is a trap** on $\mathbb{F}_{p^{12}}$:

### `BN254` ($4 \times 64$-bit Limbs)
| Target & Schedule | $\mathbb{F}_p$ Muls ($r$) | Pre-Mul `Reduce()` | Range-Check Bits | Net Groth16 R1CS | Net PlonK16 Gates | Verdict |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `BN254_Fp6_Tower18` | `18` | `0` | 14,931 | 15,150 | 2,660 | Baseline |
| **`BN254_Fp6_Rank11`** | **`11` (-38.89%)** | **`0`** | **11,433** | **11,582 (-23.55%)** | **2,037 (-23.42%)** | **Global Winner (Native & Emulated)** |
| `BN254_Fp12_Tower54` | `54` | `0` | 43,971 | 44,619 | 8,168 | Baseline (`3x6x3`) |
| **`BN254_Fp12_Tower33`** | **`33` (-38.89%)** | **`0`** | **31,852** | **32,278 (-27.66%)** | **6,229 (-23.74%)** | **Cleanest Tower Hybrid (`18.5b` $D$)** |
| **`BN254_Fp12_CRT30`** | **`30` (-44.44%)** | **`0`** | **31,102** | **31,497 (-29.41%)** | **6,171 (-24.45%)** | **Global Emulated R1CS & PlonK Winner** |
| `BN254_Fp12_CRT27` | `27` (-50.00%) | `2` | 31,355 | 31,731 (-28.88%) | 6,843 (-16.22%) | Crosses 60b carry-pack cap on 2 nodes |
| `BN254_Fp12_Rank23` | **`23` (-57.41%)** | `18` | 33,382 | 33,750 (-24.36%) | 6,770 (-17.12%) | **Native $\mathbb{F}_p$ Winner**; carry-heavy in limbs |

### `BLS12-381` ($6 \times 64$-bit Limbs)
| Target & Schedule | $\mathbb{F}_p$ Muls ($r$) | Pre-Mul `Reduce()` | Range-Check Bits | Net Groth16 R1CS | Net PlonK16 Gates | Verdict |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `BLS12_381_Fp6_Tower18` | `18` | `0` | 22,863 | 23,196 | 4,791 | Baseline |
| **`BLS12_381_Fp6_Rank11`** | **`11` (-38.89%)** | **`0`** | **16,861** | **17,081 (-26.36%)** | **3,485 (-27.26%)** | **Global Winner (Native & Emulated)** |
| `BLS12_381_Fp12_Tower54` | `54` | `0` | 67,048 | 68,032 | 14,586 | Baseline (`3x6x3`) |
| **`BLS12_381_Fp12_Tower33`** | **`33` (-38.89%)** | **`0`** | **47,669** | **48,305 (-29.00%)** | **10,739 (-26.37%)** | **Cleanest Tower Hybrid (`18.5b` $D$)** |
| **`BLS12_381_Fp12_CRT30`** | **`30` (-44.44%)** | **`0`** | **45,492** | **46,078 (-32.27%)** | **10,235 (-29.83%)** | **Global PlonK16 & 0-Reduce Winner** |
| `BLS12_381_Fp12_CRT27` | `27` (-50.00%) | `2` | 45,522 | **46,073 (-32.28%)** | 11,034 (-24.35%) | Co-optimal Groth16 R1CS (`-32.28%`) |
| `BLS12_381_Fp12_Rank23` | **`23` (-57.41%)** | `18` | 49,092 | 49,627 (-27.05%) | 10,958 (-24.87%) | **Native $\mathbb{F}_p$ Winner**; carry-heavy in limbs |

## 3. Artifacts in This Directory
- [`bn254_fp6_pareto.json`](./bn254_fp6_pareto.json) & [`bn254_fp12_pareto.json`](./bn254_fp12_pareto.json)
- [`bls12_381_fp6_pareto.json`](./bls12_381_fp6_pareto.json) & [`bls12_381_fp12_pareto.json`](./bls12_381_fp12_pareto.json)
