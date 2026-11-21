# Reproducible Benchmark & Constraint-Reduction Report (`zk-bilinear-opt`)

> **Reproducibility Guarantee**: Every figure in this report is computed deterministically
> from basis-certified integer-rational bilinear decompositions $(U, V, W_{\mathbb{Z}}, D)$
> via `.venv\Scripts\python.exe -m zk_bilinear verify` and `.venv\Scripts\python.exe -m zk_bilinear generate-all`.

## 1. Native STARK / AIR / R1CS Extension Towers (`stwo` & `Plonky3` / `SP1`)

| Target Extension | Ecosystem | Prime $p$ | Deg $d$ | Baseline Muls | Certified Optimal Rank ($2d-1$) | Mul / R1CS / Degree-2 AIR Savings | Width-4 PlonK Total Gates | Peak Accumulator Bits (Limit) | Certificate SHA-256 (prefix) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `CM31` | StarkWare stwo | $2^{31}-1$ | 2 | 4 (Schoolbook-2) | **3** | **-25.00%** | 7 | `62b` (`< 2^63`) | `ce5d5bddb6bc` |
| `QM31` | StarkWare stwo (Circle STARKs) | $2^{31}-1$ | 4 | 9 (Double-Karatsuba (3x3)) | **7** | **-22.22%** | 40 | `62b` (`< 2^63`) | `1d9d3c602a89` |
| `BabyBear4` | Plonky3 / SP1 | $2^{31}-2^{27}+1$ | 4 | 9 (Karatsuba-4) | **7** | **-22.22%** | 39 | `62b` (`< 2^63`) | `417459927610` |
| `BabyBear5` | Plonky3 / SP1 | $2^{31}-2^{27}+1$ | 5 | 15 (Karatsuba-5 (2+3 split)) | **9** | **-40.00%** | 57 | `62b` (`< 2^63`) | `42de9c89f805` |
| `KoalaBear4` | Plonky3 | $2^{31}-2^{24}+1$ | 4 | 9 (Karatsuba-4) | **7** | **-22.22%** | 39 | `62b` (`< 2^63`) | `417766cc702f` |
| `KoalaBear8` | Plonky3 | $2^{31}-2^{24}+1$ | 8 | 27 (Triple-Karatsuba (3^3)) | **15** | **-44.44%** | 175 | `63b` (`< 2^63`) | `b918c9045a35` |
| `Goldilocks2` | Plonky2 / Plonky3 | $2^{64}-2^{32}+1$ | 2 | 3 (Karatsuba-2) | **3** | **-0.00%** | 7 | `128b` (`< 2^128`) | `cf9fd4d4b02f` |
| `Goldilocks4` | Plonky3 | $2^{64}-2^{32}+1$ | 4 | 9 (Karatsuba-4) | **7** | **-22.22%** | 39 | `128b` (`< 2^128`) | `031e3b69aa51` |
| `Goldilocks5` | Plonky3 | $2^{64}-2^{32}+1$ | 5 | 15 (Karatsuba-5 (2+3 split)) | **9** | **-40.00%** | 57 | `128b` (`< 2^128`) | `bb0eb3f2621d` |

## 2. Non-Native Emulated Pairing Towers (`Consensys/gnark` $4\times 64$-bit `BN254` & $6\times 64$-bit `BLS12-381`)

In non-native emulated field circuits over a 254-bit SNARK scalar field (such as `gnark`'s `std/algebra/emulated`),
two adjacent 64-bit limb equations are packed per carry constraint (`128 + 64 = 192` bits), leaving a **60-bit overflow ceiling**
(`192 + 60 = 252 < 254` bits) for $L \cdot \|U_\ell\|_1 \cdot \|V_\ell\|_1$ before mandatory pre-multiplication `Reduce()` calls are triggered,
and a **64-bit ceiling** on $\|W_{\mathbb{Z},k}\|_1 + D$ before output modular-reduction quotients split into multi-limb witnesses.

### 2.1 `BN254` $\mathbb{F}_{p^6}$ ($4\times 64$-bit Limbs, $\xi = 9 + u$, Simple Iso $v^6 - 18v^3 + 82 = 0$)

| Schedule | Family | Native $\mathbb{F}_p$ Muls ($r$) | Mul Savings | $\log_2(UV)$ Slack | $\log_2(D)$ | Pre-Mul `Reduce()` | Total Range-Check Bits | Net Groth16 R1CS (vs Baseline) | Net PlonK16 Gates (vs Baseline) | Pareto? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BN254_Fp6_Tower18` | Karatsuba-Baseline | **18** | -0.00% | `4b` | `0.0b` | `0` | 14,931 | **15,150** (-0.00%) | **2,660** (-0.00%) | YES |
| `BN254_Fp6_Toom15` | Tower-Hybrid | **15** | -16.67% | `8b` | `2.6b` | `0` | 13,318 | **13,510** (-10.83%) | **2,356** (-11.43%) | YES |
| `BN254_Fp6_CRT13` | Cyclotomic-CRT | **13** | -27.78% | `18b` | `14.6b` | `0` | 12,710 | **12,883** (-14.96%) | **2,284** (-14.14%) | YES |
| `BN254_Fp6_CRT12` | Cyclotomic-CRT | **12** | -33.33% | `22b` | `19.7b` | `0` | 12,102 | **12,263** (-19.06%) | **2,169** (-18.46%) | YES |
| `BN254_Fp6_Rank11` | Vandermonde | **11** | -38.89% | `25b` | `18.5b` | `0` | 11,433 | **11,582** (-23.55%) | **2,037** (-23.42%) | YES |

### 2.2 `BN254` $\mathbb{F}_{p^{12}}$ ($4\times 64$-bit Limbs, $\xi = 9 + u$, Simple Iso $w^{12} - 18w^6 + 82 = 0$)

| Schedule | Family | Native $\mathbb{F}_p$ Muls ($r$) | Mul Savings | $\log_2(UV)$ Slack | $\log_2(D)$ | Pre-Mul `Reduce()` | Total Range-Check Bits | Net Groth16 R1CS (vs Baseline) | Net PlonK16 Gates (vs Baseline) | Pareto? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BN254_Fp12_Tower54` | Karatsuba-Baseline | **54** | -0.00% | `6b` | `0.0b` | `0` | 43,971 | **44,619** (-0.00%) | **8,168** (-0.00%) | YES |
| `BN254_Fp12_Toom45` | Tower-Hybrid | **45** | -16.67% | `10b` | `2.6b` | `0` | 38,570 | **39,130** (-12.30%) | **7,274** (-10.95%) | YES |
| `BN254_Fp12_Tower33` | Tower-Hybrid | **33** | -38.89% | `26b` | `18.5b` | `0` | 31,852 | **32,278** (-27.66%) | **6,229** (-23.74%) | YES |
| `BN254_Fp12_CRT30` | Cyclotomic-CRT | **30** | -44.44% | `45b` | `45.2b` | `0` | 31,102 | **31,497** (-29.41%) | **6,171** (-24.45%) | YES |
| `BN254_Fp12_CRT27` | Cyclotomic-CRT | **27** | -50.00% | `63b` | `71.2b` | `2` | 31,355 | **31,731** (-28.88%) | **6,843** (-16.22%) | YES |
| `BN254_Fp12_Rank23` | Vandermonde | **23** | -57.41% | `77b` | `65.5b` | `18` | 33,382 | **33,750** (-24.36%) | **6,770** (-17.12%) | YES |

### 2.3 `BLS12-381` $\mathbb{F}_{p^6}$ ($6\times 64$-bit Limbs, $\xi = 1 + u$, Simple Iso $v^6 - 2v^3 + 2 = 0$)

| Schedule | Family | Native $\mathbb{F}_p$ Muls ($r$) | Mul Savings | $\log_2(UV)$ Slack | $\log_2(D)$ | Pre-Mul `Reduce()` | Total Range-Check Bits | Net Groth16 R1CS (vs Baseline) | Net PlonK16 Gates (vs Baseline) | Pareto? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BLS12_381_Fp6_Tower18` | Karatsuba-Baseline | **18** | -0.00% | `4b` | `0.0b` | `0` | 22,863 | **23,196** (-0.00%) | **4,791** (-0.00%) | YES |
| `BLS12_381_Fp6_Toom15` | Tower-Hybrid | **15** | -16.67% | `8b` | `2.6b` | `0` | 20,125 | **20,413** (-12.00%) | **4,173** (-12.90%) | YES |
| `BLS12_381_Fp6_CRT13` | Cyclotomic-CRT | **13** | -27.78% | `18b` | `14.6b` | `0` | 18,393 | **18,647** (-19.61%) | **3,871** (-19.20%) | YES |
| `BLS12_381_Fp6_CRT12` | Cyclotomic-CRT | **12** | -33.33% | `21b` | `19.7b` | `0` | 17,754 | **17,992** (-22.43%) | **3,706** (-22.65%) | YES |
| `BLS12_381_Fp6_Rank11` | Vandermonde | **11** | -38.89% | `24b` | `18.5b` | `0` | 16,861 | **17,081** (-26.36%) | **3,485** (-27.26%) | YES |

### 2.4 `BLS12-381` $\mathbb{F}_{p^{12}}$ ($6\times 64$-bit Limbs, $\xi = 1 + u$, Simple Iso $w^{12} - 2w^6 + 2 = 0$)

| Schedule | Family | Native $\mathbb{F}_p$ Muls ($r$) | Mul Savings | $\log_2(UV)$ Slack | $\log_2(D)$ | Pre-Mul `Reduce()` | Total Range-Check Bits | Net Groth16 R1CS (vs Baseline) | Net PlonK16 Gates (vs Baseline) | Pareto? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BLS12_381_Fp12_Tower54` | Karatsuba-Baseline | **54** | -0.00% | `6b` | `0.0b` | `0` | 67,048 | **68,032** (-0.00%) | **14,586** (-0.00%) | YES |
| `BLS12_381_Fp12_Toom45` | Tower-Hybrid | **45** | -16.67% | `10b` | `2.6b` | `0` | 58,241 | **59,083** (-13.15%) | **12,769** (-12.46%) | YES |
| `BLS12_381_Fp12_Tower33` | Tower-Hybrid | **33** | -38.89% | `26b` | `18.5b` | `0` | 47,669 | **48,305** (-29.00%) | **10,739** (-26.37%) | YES |
| `BLS12_381_Fp12_CRT30` | Cyclotomic-CRT | **30** | -44.44% | `45b` | `47.5b` | `0` | 45,492 | **46,078** (-32.27%) | **10,235** (-29.83%) | YES |
| `BLS12_381_Fp12_CRT27` | Cyclotomic-CRT | **27** | -50.00% | `63b` | `71.2b` | `2` | 45,522 | **46,073** (-32.28%) | **11,034** (-24.35%) | YES |
| `BLS12_381_Fp12_Rank23` | Vandermonde | **23** | -57.41% | `77b` | `65.5b` | `18` | 49,092 | **49,627** (-27.05%) | **10,958** (-24.87%) | YES |

## 3. Key Architectural Takeaway: Why Naive `23`-Mul Vandermonde Loses to `CRT-30` & `Tower-33` in Non-Native Limbs

1. **Native $\mathbb{F}_p$ Circuits (e.g., BW6-761 / Pasta 2-chains / Native R1CS)**: Scalar multiplications by $D^{-1} W_{\mathbb{Z}} \bmod p$ fold into linear combinations for **zero** multiplicative gates, so `Rank-23` Vandermonde achieves the exact Winograd / Alder–Strassen global minimum of **23 R1CS constraints** (`-57.41%` vs `54`).
2. **Emulated $L\times 64$-bit Non-Native Circuits (`gnark` Groth16 / PlonK)**: `Vandermonde-Rank23` evaluates at nodes up to $\alpha = -11$, where $|-11|^{11} \approx 2^{38.1}$ pushes $\|U_\ell\|_1 \|V_\ell\|_1$ to **`77` bits** (`> 60`-bit 2-limb packing limit), triggering **18 mandatory pre-multiplication `Reduce()` gadgets**, while $D = \operatorname{lcm}(\dots) \approx 2^{65.5}$ and $\|W_{\mathbb{Z}}\|_1 \approx 2^{113}$ force 2-limb output reduction quotients.
3. **The Certified Non-Native Sweet Spots**:
   - **On $\mathbb{F}_{p^6}$**: `Rank-11` (`{-5..4, inf}`) stays strictly inside the 2-limb packing envelope (`0` pre-reductions, `18.5`-bit $D$), achieving **both** optimal native rank (`18 -> 11`, `-38.89%`) **and** the global minimum net Groth16 R1CS (`-23.55%` on BN254, `-26.36%` on BLS12-381) and PlonK16 (`-23.42%` / `-27.26%`) constraint counts!
   - **On $\mathbb{F}_{p^{12}}$**: `CRT-30` (`9` small linear nodes `{-4..3, inf}` + `7` cyclotomic/small quadratic moduli, `0` pre-reductions, single-word output quotients) and `Tower-33` (`Toom-6` over $\mathbb{F}_{p^2}$ $\times$ `Karatsuba-2`, `18.5`-bit $D$, `0` pre-reductions) eliminate 100% of pre-multiplication reductions and beat `Tower-54` by **`-29.41%` (BN254) and `-32.27%` (BLS12-381) net Groth16 R1CS constraints AFTER counting every carry & range-check bit**, cleanly outperforming `Vandermonde-23`!
