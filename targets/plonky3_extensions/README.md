# Module B — `Plonky3` / `SP1` Binomial Extensions (`BabyBear`, `KoalaBear`, `Goldilocks`)

## 1. Certified Optimal Bilinear Ranks ($R_{\mathbb{F}_p} = 2d - 1$)

In `Plonky3` (`p3-field`) and Succinct `SP1`, challenge fields are constructed as binomial extensions $\mathbb{F}_p[X]/(X^d - W)$. Inside recursive STARK verifiers (`AirBuilder`) and R1CS wrappers, linear combinations by compile-time constants in $\mathbb{F}_p$ have algebraic degree $1$ (`0` multiplicative gates), so verifier complexity scales directly with **bilinear rank** $r$.

Every polynomial below is verified irreducible over $\mathbb{F}_p$ via Rabin's test, making Winograd / Alder–Strassen's $2d - 1$ lower bound exact:

| Extension | Prime $p$ | Polynomial | Karatsuba Baseline | Certified Optimal Rank | Savings | Peak Native Word Bits |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `BabyBear^4` | $2^{31} - 2^{27} + 1$ | $X^4 - 11$ | `9` | **`7`** | **`-22.22%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| `BabyBear^5` | $2^{31} - 2^{27} + 1$ | $X^5 - 2$ | `15` | **`9`** | **`-40.00%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| `KoalaBear^4` | $2^{31} - 2^{24} + 1$ | $X^4 - 3$ | `9` | **`7`** | **`-22.22%`** | `62b` (`< 2^63` in `i64`/`u64`) |
| `KoalaBear^8` | $2^{31} - 2^{24} + 1$ | $X^8 - 3$ | `27` | **`15`** | **`-44.44%`** | `63b` (`< 2^63` via 2-term chunked `u64`) |
| `Goldilocks^2` | $2^{64} - 2^{32} + 1$ | $X^2 - 7$ | `3` | **`3`** | Optimal ($2d-1$) | `128b` (`< 2^128` in `u128`) |
| `Goldilocks^4` | $2^{64} - 2^{32} + 1$ | $X^4 - 7$ | `9` | **`7`** | **`-22.22%`** | `128b` (`< 2^128` in `u128`) |
| `Goldilocks^5` | $2^{64} - 2^{32} + 1$ | $X^5 - 3$ | `15` | **`9`** | **`-40.00%`** | `128b` (`< 2^128` in `u128`) |

## 2. Accumulator Safety Highlights
- **`KoalaBear^8` (`15` muls on `{-7..6, inf}`)**: Unreduced $\|W_{\mathbb{Z}}\|_1 \approx 2^{54.9}$ would overflow `u64` if multiplied by $p \approx 2^{31}$ before reduction. Our emitter pre-reduces $W_{\mathbb{F}_p} = D^{-1} W_{\mathbb{Z}} \bmod p$ into canonical `u32` constants and accumulates **2 products per step**:
  $$(p - 1) + 2(p - 1)^2 = 2130706432 + 2 \times 2130706432^2 = 9,079,820,180,294,664,192 < 9,223,372,036,854,775,807 = 2^{63} - 1,$$
  staying strictly inside both `i64` and `u64` with **zero `u128` instructions**!
- **`Goldilocks` (`u128` safety)**: Because $p - 1 = 2^{64} - 2^{32}$, the maximal product satisfies $(p - 1)^2 = 2^{128} - 2^{97} + 2^{64} < 2^{128} - 1 = \text{u128::MAX}$, guaranteeing zero unsigned `u128` overflow even on the all-$(p-1)$ vector.

## 3. Artifacts in This Directory
- Certificate JSONs: [`babybear4_rank7_cert.json`](./babybear4_rank7_cert.json), [`babybear5_rank9_cert.json`](./babybear5_rank9_cert.json), [`koalabear4_rank7_cert.json`](./koalabear4_rank7_cert.json), [`koalabear8_rank15_cert.json`](./koalabear8_rank15_cert.json), [`goldilocks2_rank3_cert.json`](./goldilocks2_rank3_cert.json), [`goldilocks4_rank7_cert.json`](./goldilocks4_rank7_cert.json), [`goldilocks5_rank9_cert.json`](./goldilocks5_rank9_cert.json).
- `#![no_std]` Rust kernels: [`plonky3_extensions.rs`](./plonky3_extensions.rs).
