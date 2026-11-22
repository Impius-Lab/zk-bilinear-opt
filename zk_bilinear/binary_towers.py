"""Exact `GF(2)` Bilinear Synthesis & Basis-Pair Certifier for Binary Towers (`Binius` & `AES`).

Covers two foundational characteristic-2 polynomial/tower architectures in modern ZK & symmetric
cryptography:

  1. **Wiedemann (1988) / Binius (Diamond & Posen 2023) Multilinear Binary Towers**:
       T_0 = F_2
       T_1 = T_0[X_0] / (X_0^2 + X_0 + 1)
       T_{k+1} = T_k[X_k] / (X_k^2 + X_{k-1} X_k + 1)   for k >= 1.
     - Standard recursive Karatsuba-Wiedemann achieves exact `GF(2)` multiplicative rank `3^k`
       (`0` AND gates for `X_{k-1}` scaling and `0` AND gates for Frobenius squaring):
         k=1 (`GF(2^2)`):   Rank    3 vs      4 schoolbook (-25.00%)
         k=2 (`GF(2^4)`):   Rank    9 vs     16 schoolbook (-43.75%)
         k=3 (`GF(2^8)`):   Rank   27 vs     64 schoolbook (-57.81%)
         k=4 (`GF(2^16)`):  Rank   81 vs    256 schoolbook (-68.36%)
         k=5 (`GF(2^32)`):  Rank  243 vs  1,024 schoolbook (-76.27%)
         k=6 (`GF(2^64)`):  Rank  729 vs  4,096 schoolbook (-82.20%)
         k=7 (`GF(2^128)`): Rank 2187 vs 16,384 schoolbook (-86.65%)
     - **Extension-Interpolated `GF(4)` / `GF(16)` Toom & Chudnovsky-CRT Schedules**:
       Viewing `T_3 = GF(2^8)` as degree 4 over `T_1 = GF(4)` and interpolating across all 5
       degree-1 projective places `{0, 1, omega, omega^2, inf}` plus 1 degree-2 irreducible
       place `Y^2 + omega*Y + 1` yields **Rank 24** (`5*3 + 1*9 = 24` AND gates, `-62.50%` vs
       64 schoolbook and `-11.11%` vs Rank-27 Wiedemann).
       Viewing `T_4 = GF(2^16)` as degree 4 over `T_2 = GF(16)` yields **Rank 63** (`7*9`), and
       viewing `T_4` as degree 8 over `T_1 = GF(4)` across 5 degree-1 places + 5 degree-2
       irreducible places yields **Rank 60** (`5*3 + 5*9 = 60` AND gates, `-76.56%` vs 256
       schoolbook and `-25.93%` vs Rank-81 Wiedemann; `1,620` AND gates at `GF(2^128)`, `-90.11%`).

  2. **AES / Rijndael `GF(2^8) = F_2[x] / (x^8 + x^4 + x^3 + x + 1)` (`0x11b`)**:
     - Explicit `8 x 8` invertible `GF(2)` basis isomorphism `M_{AES -> T_3}` (`det = 1 mod 2`)
       and inverse `M_{T_3 -> AES}`, pulling back both **Rank-27** (`-57.81%`) and **Rank-24**
       (`-62.50%`) exact `GF(2)` bilinear schedules to native AES polynomial coordinates,
       algebraically certified across all `64` (`8 x 8`) `GF(2)` basis pairs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# AES / Rijndael irreducible polynomial x^8 + x^4 + x^3 + x + 1 = 0x11b
AES_POLY: int = 0x11B

# Complete prime factorization of 2^128 - 1 = prod_{j=0}^6 (2^(2^j) + 1)
# F_0=3, F_1=5, F_2=17, F_3=257, F_4=65537,
# F_5 = 641 * 6700417, F_6 = 274177 * 67280421310721.
FERMAT_PRIME_FACTORS_BY_LEVEL: Dict[int, Tuple[int, ...]] = {
    1: (3,),
    2: (3, 5),
    3: (3, 5, 17),
    4: (3, 5, 17, 257),
    5: (3, 5, 17, 257, 65537),
    6: (3, 5, 17, 257, 65537, 641, 6700417),
    7: (3, 5, 17, 257, 65537, 641, 6700417, 274177, 67280421310721),
}


# ============================================================================
# 1. Exact GF(2) Linear Algebra Primitives
# ============================================================================


def gf2_identity(n: int) -> Tuple[Tuple[int, ...], ...]:
    return tuple(tuple(1 if i == j else 0 for j in range(n)) for i in range(n))


def gf2_mat_mul(
    a: Sequence[Sequence[int]], b: Sequence[Sequence[int]]
) -> Tuple[Tuple[int, ...], ...]:
    rows = len(a)
    inner = len(b)
    cols = len(b[0]) if inner > 0 else 0
    out: List[Tuple[int, ...]] = []
    for i in range(rows):
        row = [0] * cols
        for k in range(inner):
            if a[i][k] & 1:
                for j in range(cols):
                    row[j] ^= b[k][j] & 1
        out.append(tuple(row))
    return tuple(out)


def gf2_mat_vec(mat: Sequence[Sequence[int]], vec_int: int, ncols: int) -> int:
    """Apply an `m x ncols` binary matrix `mat` to packed bit-vector `vec_int` over `GF(2)`."""
    res = 0
    for i, row in enumerate(mat):
        acc = 0
        for j in range(ncols):
            if (row[j] & 1) and ((vec_int >> j) & 1):
                acc ^= 1
        if acc:
            res |= 1 << i
    return res


def int_to_gf2_bits(x: int, width: int) -> Tuple[int, ...]:
    return tuple((x >> i) & 1 for i in range(width))


def gf2_bits_to_int(bits: Sequence[int]) -> int:
    acc = 0
    for i, b in enumerate(bits):
        if b & 1:
            acc |= 1 << i
    return acc


def gf2_det_and_inv(
    mat: Sequence[Sequence[int]],
) -> Tuple[int, Optional[Tuple[Tuple[int, ...], ...]]]:
    """Exact Gauss-Jordan elimination over `GF(2)`. Returns `(det_mod_2, inv_or_None)`."""
    n = len(mat)
    if any(len(row) != n for row in mat):
        raise ValueError("Matrix must be square for GF(2) determinant/inversion")
    aug = [[(mat[i][j] & 1) for j in range(n)] + [1 if i == j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        pivot = None
        for r in range(col, n):
            if aug[r][col] == 1:
                pivot = r
                break
        if pivot is None:
            return 0, None
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(n):
            if r != col and aug[r][col] == 1:
                aug[r] = [aug[r][c] ^ aug[col][c] for c in range(2 * n)]
    inv = tuple(tuple(aug[i][n + j] for j in range(n)) for i in range(n))
    return 1, inv


# ============================================================================
# 2. Wiedemann / Binius Multilinear Binary Tower T_0 .. T_7 (GF(2) .. GF(2^128))
# ============================================================================


def binius_mul_alpha(a: int, k: int) -> int:
    """Multiply `a in T_k` (`k >= 0`, `2^k`-bit integer) by `X_{k-1}` (with `X_{-1} := 1` in `T_0`).
    Purely `F_2`-linear: `0` AND gates and `2^k - 1` XOR gates.
    """
    if k < 0:
        raise ValueError(f"binius_mul_alpha requires k >= 0, got {k}")
    if k == 0:
        return a & 1
    half_bits = 1 << (k - 1)
    mask = (1 << half_bits) - 1
    a0 = a & mask
    a1 = (a >> half_bits) & mask
    if k == 1:
        # X_0 * (a0 + a1 * X_0) = a1 + (a0 ^ a1) * X_0 since X_0^2 = X_0 + 1
        return a1 | ((a0 ^ a1) << 1)
    # X_{k-1} * (a0 + a1 * X_{k-1}) = a1 + (a0 ^ (X_{k-2} * a1)) * X_{k-1}
    hi = a0 ^ binius_mul_alpha(a1, k - 1)
    return a1 | (hi << half_bits)


def binius_mul(a: int, b: int, k: int) -> int:
    """Recursive Karatsuba-Wiedemann multiplication in `T_k = GF(2^{2^k})` (`3^k` AND gates)."""
    if k == 0:
        return (a & 1) & (b & 1)
    half_bits = 1 << (k - 1)
    mask = (1 << half_bits) - 1
    a0, a1 = a & mask, (a >> half_bits) & mask
    b0, b1 = b & mask, (b >> half_bits) & mask

    p0 = binius_mul(a0, b0, k - 1)
    p1 = binius_mul(a1, b1, k - 1)
    pm = binius_mul(a0 ^ a1, b0 ^ b1, k - 1)

    c0 = p0 ^ p1
    c1 = pm ^ c0 ^ binius_mul_alpha(p1, k - 1)
    return c0 | (c1 << half_bits)


def binius_square(a: int, k: int) -> int:
    """Pure `F_2`-linear Frobenius squaring in `T_k` (`0` AND gates for all `k`)."""
    if k == 0:
        return a & 1
    half_bits = 1 << (k - 1)
    mask = (1 << half_bits) - 1
    a0, a1 = a & mask, (a >> half_bits) & mask
    s0 = binius_square(a0, k - 1)
    s1 = binius_square(a1, k - 1)
    c0 = s0 ^ s1
    c1 = binius_mul_alpha(s1, k - 1)
    return c0 | (c1 << half_bits)


def binius_inv(a: int, k: int) -> int:
    """Itoh-Tsujii recursive norm-descent multiplicative inverse in `T_k`."""
    mask = (1 << (1 << k)) - 1
    a &= mask
    if a == 0:
        raise ZeroDivisionError("0 has no multiplicative inverse in binary tower")
    if k == 0:
        return 1
    half_bits = 1 << (k - 1)
    hmask = (1 << half_bits) - 1
    a0, a1 = a & hmask, (a >> half_bits) & hmask
    # Conjugate over T_{k-1}: conj(a0 + a1*X_{k-1}) = (a0 ^ X_{k-2}*a1) + a1*X_{k-1}
    t = a0 ^ (a1 if k == 1 else binius_mul_alpha(a1, k - 1))
    # Norm N(a) = a0 * t ^ a1^2 in T_{k-1}
    norm = binius_mul(a0, t, k - 1) ^ binius_square(a1, k - 1)
    norm_inv = binius_inv(norm, k - 1)
    c0 = binius_mul(t, norm_inv, k - 1)
    c1 = binius_mul(a1, norm_inv, k - 1)
    return c0 | (c1 << half_bits)


def binius_pow(a: int, exp: int, k: int) -> int:
    """Binary square-and-multiply in `T_k`."""
    if exp < 0:
        a = binius_inv(a, k)
        exp = -exp
    res = 1
    base = a & ((1 << (1 << k)) - 1)
    while exp > 0:
        if exp & 1:
            res = binius_mul(res, base, k)
        exp >>= 1
        if exp > 0:
            base = binius_square(base, k)
    return res


def verify_wiedemann_tower_irreducibility(max_k: int = 7) -> Dict[int, Dict[str, object]]:
    """Prove `T_k = GF(2^{2^k})` is a field for every `k = 1 .. max_k` by exhibiting a concrete
    primitive element `g_k in T_k^*` of exact multiplicative order `2^{2^k} - 1` verified against
    the complete prime factorization of `2^128 - 1`.
    """
    if not (1 <= max_k <= 7):
        raise ValueError(f"max_k must be in [1, 7], got {max_k}")
    report: Dict[int, Dict[str, object]] = {}
    for k in range(1, max_k + 1):
        bits = 1 << k
        order = (1 << bits) - 1
        primes = FERMAT_PRIME_FACTORS_BY_LEVEL[k]
        # Verify prod of prime factors divides order and covers all distinct prime divisors of order
        rem = order
        for p in primes:
            if rem % p != 0:
                raise AssertionError(f"Factor {p} does not divide 2^{bits}-1")
            while rem % p == 0:
                rem //= p
        if rem != 1:
            raise AssertionError(f"Incomplete prime factorization at k={k}, leftover={rem}")

        # Deterministically locate first primitive element of form X_{k-1} + offset in T_k \ T_{k-1}
        generator = None
        top_gen = 1 << (1 << (k - 1))
        for offset in range(0, 512):
            cand = top_gen ^ offset
            if cand == 0 or cand >= (1 << bits):
                continue
            if binius_pow(cand, order, k) != 1:
                continue
            if all(binius_pow(cand, order // p, k) != 1 for p in primes):
                generator = cand
                break
        if generator is None:
            raise RuntimeError(f"Failed to find primitive generator in T_{k}")

        report[k] = {
            "level": k,
            "degree_bits": bits,
            "multiplicative_order": order,
            "prime_factors": primes,
            "primitive_generator": generator,
            "is_field": True,
        }
    return report


# ============================================================================
# 3. Exact GF(2) Bilinear Schedule Certifier & Wiedemann Gate-Count Engine
# ============================================================================


@dataclass(frozen=True)
class GF2BilinearSchedule:
    """Exact `GF(2)` bilinear decomposition `c_k = XOR_{l=0}^{r-1} W[k][l] * ((U[l] . a) & (V[l] . b))`."""

    name: str
    target_name: str
    degree: int
    rank: int
    U: Tuple[Tuple[int, ...], ...]
    V: Tuple[Tuple[int, ...], ...]
    W: Tuple[Tuple[int, ...], ...]
    dag_xor_gates: Optional[int] = None
    description: str = ""

    @property
    def and_gates(self) -> int:
        return self.rank

    @property
    def schoolbook_and_gates(self) -> int:
        return self.degree * self.degree

    @property
    def and_reduction_vs_schoolbook_pct(self) -> float:
        sb = self.schoolbook_and_gates
        return round((1.0 - self.rank / sb) * 100.0, 2)

    @property
    def naive_matrix_xor_gates(self) -> int:
        xu = sum(max(0, sum(x & 1 for x in row) - 1) for row in self.U)
        xv = sum(max(0, sum(x & 1 for x in row) - 1) for row in self.V)
        xw = sum(max(0, sum(x & 1 for x in row) - 1) for row in self.W)
        return xu + xv + xw


@dataclass(frozen=True)
class GF2CertificateReport:
    schedule_name: str
    target_name: str
    degree: int
    rank: int
    basis_pairs_checked: int
    dimensions_ok: bool
    binary_entries_ok: bool
    basis_identity_ok: bool
    errors: Tuple[str, ...]

    @property
    def passed(self) -> bool:
        return (
            len(self.errors) == 0
            and self.dimensions_ok
            and self.binary_entries_ok
            and self.basis_identity_ok
        )

    def __bool__(self) -> bool:
        return self.passed


def evaluate_gf2_schedule(sched: GF2BilinearSchedule, a: int, b: int) -> int:
    """Evaluate binary bilinear schedule `(U, V, W)` on packed `degree`-bit integers `a, b`."""
    d = sched.degree
    r = sched.rank
    m = [0] * r
    for l in range(r):
        ua = 0
        vb = 0
        u_row = sched.U[l]
        v_row = sched.V[l]
        for i in range(d):
            if (u_row[i] & 1) and ((a >> i) & 1):
                ua ^= 1
            if (v_row[i] & 1) and ((b >> i) & 1):
                vb ^= 1
        m[l] = ua & vb

    out = 0
    for k in range(d):
        acc = 0
        w_row = sched.W[k]
        for l in range(r):
            if (w_row[l] & 1) and m[l]:
                acc ^= 1
        if acc:
            out |= 1 << k
    return out


def certify_gf2_schedule(
    sched: GF2BilinearSchedule, ref_mul: Callable[[int, int], int]
) -> GF2CertificateReport:
    """Verify exact `GF(2)` bilinearity across all `d^2` canonical basis pairs `(1 << i, 1 << j)`."""
    d = sched.degree
    r = sched.rank
    errors: List[str] = []

    dims_ok = (
        len(sched.U) == r
        and len(sched.V) == r
        and len(sched.W) == d
        and all(len(row) == d for row in sched.U)
        and all(len(row) == d for row in sched.V)
        and all(len(row) == r for row in sched.W)
    )
    if not dims_ok:
        errors.append(f"Invalid U/V/W matrix dimensions for degree={d}, rank={r}")

    bin_ok = (
        all(x in (0, 1) for row in sched.U for x in row)
        and all(x in (0, 1) for row in sched.V for x in row)
        and all(x in (0, 1) for row in sched.W for x in row)
    )
    if not bin_ok:
        errors.append("Non-binary entry outside {0, 1} found in U, V, or W")

    checked = 0
    basis_ok = True
    if dims_ok and bin_ok:
        for i in range(d):
            ea = 1 << i
            for j in range(d):
                eb = 1 << j
                got = evaluate_gf2_schedule(sched, ea, eb)
                want = ref_mul(ea, eb)
                checked += 1
                if got != want:
                    basis_ok = False
                    if len(errors) < 8:
                        errors.append(
                            f"Basis mismatch at (e_{i}, e_{j}): got 0x{got:x}, want 0x{want:x}"
                        )
    else:
        basis_ok = False

    return GF2CertificateReport(
        schedule_name=sched.name,
        target_name=sched.target_name,
        degree=d,
        rank=r,
        basis_pairs_checked=checked,
        dimensions_ok=dims_ok,
        binary_entries_ok=bin_ok,
        basis_identity_ok=basis_ok,
        errors=tuple(errors),
    )


def wiedemann_mul_alpha_matrix(k: int) -> Tuple[Tuple[int, ...], ...]:
    """Return the exact `2^k x 2^k` `GF(2)` linear matrix of `x -> X_{k-1} * x` on `T_k`."""
    d = 1 << k
    cols = [int_to_gf2_bits(binius_mul_alpha(1 << j, k), d) for j in range(d)]
    return tuple(tuple(cols[j][i] for j in range(d)) for i in range(d))


def wiedemann_karatsuba_gate_counts(k: int) -> Dict[str, object]:
    """Exact recursive gate counts for Wiedemann `T_k = GF(2^{2^k})` (`k = 0 .. 7`):
      - `and_gates(0) = 1`, `and_gates(k) = 3^k`
      - `mul_alpha_xors(k) = 2^k - 1` (`k >= 1`)
      - `dag_xor_gates(0) = 0`,
        `dag_xor_gates(k) = 3 * dag_xor_gates(k - 1) + 4 * 2^{k-1} + (2^{k-1} - 1)`
        (since `a0^a1`, `b0^b1`, `c0 = p0^p1`, `t = pm^c0`, `c1 = t ^ mul_alpha(p1)` use
        `4 * 2^{k-1} + (2^{k-1} - 1) = 5 * 2^{k-1} - 1` XORs at level `k`).
    """
    if k < 0:
        raise ValueError("k must be >= 0")
    if k == 0:
        return {
            "level": 0,
            "field": "GF(2)",
            "degree": 1,
            "and_gates": 1,
            "dag_xor_gates": 0,
            "schoolbook_and_gates": 1,
            "schoolbook_xor_gates": 0,
            "and_reduction_pct": 0.0,
        }
    xor_k = 0
    for lvl in range(1, k + 1):
        half = 1 << (lvl - 1)
        xor_k = 3 * xor_k + 4 * half + (half - 1)
    d = 1 << k
    ands = 3**k
    sb_ands = d * d
    return {
        "level": k,
        "field": f"GF(2^{d})",
        "degree": d,
        "and_gates": ands,
        "dag_xor_gates": xor_k,
        "schoolbook_and_gates": sb_ands,
        "and_reduction_pct": round((1.0 - ands / sb_ands) * 100.0, 2),
        "and_reduction_exact_pct": (1.0 - ands / sb_ands) * 100.0,
    }


def synthesize_wiedemann_schedule(k: int) -> GF2BilinearSchedule:
    """Recursively synthesize explicit `GF(2)` matrices `(U, V, W)` of rank `3^k` for `T_k`."""
    if k == 0:
        return GF2BilinearSchedule(
            name="Binius_T0_Rank1",
            target_name="Binius_T0",
            degree=1,
            rank=1,
            U=((1,),),
            V=((1,),),
            W=((1,),),
            dag_xor_gates=0,
            description="Base field GF(2) single AND gate",
        )
    sub = synthesize_wiedemann_schedule(k - 1)
    d_sub = sub.degree
    r_sub = sub.rank
    d = 2 * d_sub
    r = 3 * r_sub
    alpha_mat = wiedemann_mul_alpha_matrix(k - 1)

    # 3 blocks of r_sub products:
    #   Block 0: p0 = a0 * b0
    #   Block 1: p1 = a1 * b1
    #   Block 2: pm = (a0 ^ a1) * (b0 ^ b1)
    u_rows: List[Tuple[int, ...]] = []
    v_rows: List[Tuple[int, ...]] = []
    for row in sub.U:
        u_rows.append(tuple(row) + (0,) * d_sub)
    for row in sub.U:
        u_rows.append((0,) * d_sub + tuple(row))
    for row in sub.U:
        u_rows.append(tuple(row) + tuple(row))

    for row in sub.V:
        v_rows.append(tuple(row) + (0,) * d_sub)
    for row in sub.V:
        v_rows.append((0,) * d_sub + tuple(row))
    for row in sub.V:
        v_rows.append(tuple(row) + tuple(row))

    # Output c0 = p0 ^ p1, c1 = p0 ^ p1 ^ pm ^ alpha(p1)
    alpha_w = gf2_mat_mul(alpha_mat, sub.W)
    w_rows: List[Tuple[int, ...]] = []
    for i in range(d_sub):
        w_rows.append(tuple(sub.W[i]) + tuple(sub.W[i]) + (0,) * r_sub)
    for i in range(d_sub):
        p1_hi = tuple(sub.W[i][l] ^ alpha_w[i][l] for l in range(r_sub))
        w_rows.append(tuple(sub.W[i]) + p1_hi + tuple(sub.W[i]))

    counts = wiedemann_karatsuba_gate_counts(k)
    return GF2BilinearSchedule(
        name=f"Binius_T{k}_Wiedemann_Rank{r}",
        target_name=f"Binius_T{k}_GF2_{d}",
        degree=d,
        rank=r,
        U=tuple(u_rows),
        V=tuple(v_rows),
        W=tuple(w_rows),
        dag_xor_gates=int(counts["dag_xor_gates"]),
        description=f"Wiedemann T_{k} = GF(2^{d}) recursive Karatsuba schedule (Rank {r})",
    )


# ============================================================================
# 4. Extension-Interpolated GF(4) / GF(16) Chudnovsky-CRT & Toom Schedules
# ============================================================================


def _gf4_add(a: int, b: int) -> int:
    return (a ^ b) & 3


def _gf4_mul(a: int, b: int) -> int:
    return binius_mul(a & 3, b & 3, 1)


def _gf4_inv(a: int) -> int:
    return binius_inv(a & 3, 1)


def _gf4_poly_trim(p: Sequence[int]) -> Tuple[int, ...]:
    lst = [c & 3 for c in p]
    while len(lst) > 1 and lst[-1] == 0:
        lst.pop()
    return tuple(lst) if lst else (0,)


def _gf4_poly_add(a: Sequence[int], b: Sequence[int]) -> Tuple[int, ...]:
    n = max(len(a), len(b))
    out = [((a[i] if i < len(a) else 0) ^ (b[i] if i < len(b) else 0)) & 3 for i in range(n)]
    return _gf4_poly_trim(out)


def _gf4_poly_mul(a: Sequence[int], b: Sequence[int]) -> Tuple[int, ...]:
    out = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        if ca & 3:
            for j, cb in enumerate(b):
                if cb & 3:
                    out[i + j] ^= _gf4_mul(ca, cb)
    return _gf4_poly_trim(out)


def _gf4_poly_divmod(
    num: Sequence[int], den: Sequence[int]
) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    rem = list(_gf4_poly_trim(num))
    den_t = _gf4_poly_trim(den)
    if den_t == (0,):
        raise ZeroDivisionError("Polynomial division by zero over GF(4)")
    d_deg = len(den_t) - 1
    if len(rem) - 1 < d_deg:
        return (0,), tuple(rem)
    inv_lead = _gf4_inv(den_t[-1])
    quo = [0] * (len(rem) - d_deg)
    for shift in range(len(rem) - d_deg - 1, -1, -1):
        coeff = rem[shift + d_deg]
        if coeff != 0:
            q = _gf4_mul(coeff, inv_lead)
            quo[shift] = q
            for j in range(d_deg + 1):
                rem[shift + j] ^= _gf4_mul(q, den_t[j])
    return _gf4_poly_trim(quo), _gf4_poly_trim(rem[:d_deg] if d_deg > 0 else [0])


def _gf4_poly_egcd(
    a: Sequence[int], b: Sequence[int]
) -> Tuple[Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]:
    """Extended GCD over `GF(4)[Y]`: returns `(g, s, t)` with `g` monic and `s*a + t*b = g`."""
    r0, r1 = _gf4_poly_trim(a), _gf4_poly_trim(b)
    s0, s1 = (1,), (0,)
    t0, t1 = (0,), (1,)
    while r1 != (0,):
        q, r2 = _gf4_poly_divmod(r0, r1)
        r0, r1 = r1, r2
        s0, s1 = s1, _gf4_poly_add(s0, _gf4_poly_mul(q, s1))
        t0, t1 = t1, _gf4_poly_add(t0, _gf4_poly_mul(q, t1))
    inv_l = _gf4_inv(r0[-1])
    g = tuple(_gf4_mul(c, inv_l) for c in r0)
    s = tuple(_gf4_mul(c, inv_l) for c in s0)
    t = tuple(_gf4_mul(c, inv_l) for c in t0)
    return _gf4_poly_trim(g), _gf4_poly_trim(s), _gf4_poly_trim(t)


def _all_monic_quadratic_irreducibles_gf4() -> Tuple[Tuple[int, int, int], ...]:
    """Return all `(4^2 - 4)/2 = 6` monic degree-2 irreducible polynomials `(c0, c1, 1)` over `GF(4)`."""
    irreducibles: List[Tuple[int, int, int]] = []
    for c1 in range(4):
        for c0 in range(1, 4):
            # Irreducible over GF(4) iff no root x in {0, 1, 2, 3}
            has_root = False
            for x in range(4):
                val = _gf4_add(_gf4_add(_gf4_mul(x, x), _gf4_mul(c1, x)), c0)
                if val == 0:
                    has_root = True
                    break
            if not has_root:
                irreducibles.append((c0, c1, 1))
    assert len(irreducibles) == 6
    return tuple(irreducibles)


def _synthesize_quadratic_mod_gf4_schedule(mod_poly: Tuple[int, int, int]) -> GF2BilinearSchedule:
    """Synthesize a Rank-9 `GF(2)` schedule for `GF(4)[Y] / (Y^2 + c1*Y + c0)` (4 bits over `GF(2)`)
    via Karatsuba over `T_1 = GF(4)` (`3 * 3 = 9` AND gates).
    """
    c0, c1, lead = mod_poly
    assert lead == 1
    t1_sched = synthesize_wiedemann_schedule(1)  # 3x2

    def gf4_const_mat(alpha: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        col0 = int_to_gf2_bits(_gf4_mul(alpha, 1), 2)
        col1 = int_to_gf2_bits(_gf4_mul(alpha, 2), 2)
        return ((col0[0], col1[0]), (col0[1], col1[1]))

    m_c0 = gf4_const_mat(c0)
    m_c1 = gf4_const_mat(c1)

    # p0 = a0 * b0, p1 = a1 * b1, pm = (a0 + a1) * (b0 + b1)
    # In GF(4)[Y]/(Y^2 + c1*Y + c0), Y^2 = c0 + c1*Y:
    #   out0 = p0 + c0 * p1
    #   out1 = p0 + p1 + pm + c1 * p1
    u_rows: List[Tuple[int, ...]] = []
    v_rows: List[Tuple[int, ...]] = []
    for row in t1_sched.U:
        u_rows.append(tuple(row) + (0, 0))
    for row in t1_sched.U:
        u_rows.append((0, 0) + tuple(row))
    for row in t1_sched.U:
        u_rows.append(tuple(row) + tuple(row))

    for row in t1_sched.V:
        v_rows.append(tuple(row) + (0, 0))
    for row in t1_sched.V:
        v_rows.append((0, 0) + tuple(row))
    for row in t1_sched.V:
        v_rows.append(tuple(row) + tuple(row))

    c0_w = gf2_mat_mul(m_c0, t1_sched.W)
    c1_w = gf2_mat_mul(m_c1, t1_sched.W)
    w_rows: List[Tuple[int, ...]] = []
    for i in range(2):
        w_rows.append(tuple(t1_sched.W[i]) + tuple(c0_w[i]) + (0, 0, 0))
    for i in range(2):
        p1_hi = tuple(t1_sched.W[i][l] ^ c1_w[i][l] for l in range(3))
        w_rows.append(tuple(t1_sched.W[i]) + p1_hi + tuple(t1_sched.W[i]))

    return GF2BilinearSchedule(
        name=f"GF4_Quad_{c0}_{c1}_Rank9",
        target_name="GF16_over_GF4",
        degree=4,
        rank=9,
        U=tuple(u_rows),
        V=tuple(v_rows),
        W=tuple(w_rows),
    )


def _chudnovsky_gf4_poly_product_schedule(
    deg_d: int, num_quad_places: int
) -> Tuple[Tuple[Tuple[int, ...], ...], Tuple[Tuple[int, ...], ...], Tuple[Tuple[int, ...], ...]]:
    """Construct exact `GF(2)` matrices `(U_poly, V_poly, W_poly)` computing the unreduced degree
    `2*deg_d - 2` Cauchy product `C(Y) = A(Y) * B(Y)` in `GF(4)[Y]` (where `deg A, deg B < deg_d`),
    using:
      - all 4 finite `GF(4)` points `{0, 1, 2, 3}` (`4 * 3 = 12` ANDs)
      - the point at infinity `A_{d-1} * B_{d-1}` (`1 * 3 = 3` ANDs)
      - `num_quad_places` distinct monic quadratic irreducibles over `GF(4)` (`9 * q` ANDs),
    requiring `5 + 2 * num_quad_places == 2 * deg_d - 1`.
    Input bit layout: `2 * deg_d` bits (`2` bits per `GF(4)` coefficient `A_0 .. A_{d-1}`).
    Output bit layout: `2 * (2 * deg_d - 1)` bits (`C_0 .. C_{2*deg_d - 2}`).
    """
    ncoeffs_out = 2 * deg_d - 1
    if 5 + 2 * num_quad_places != ncoeffs_out:
        raise ValueError(
            f"Degree mismatch: 5 + 2*{num_quad_places} != {ncoeffs_out} for deg_d={deg_d}"
        )
    quads = _all_monic_quadratic_irreducibles_gf4()[:num_quad_places]
    moduli: List[Tuple[int, ...]] = [(0, 1), (1, 1), (2, 1), (3, 1)] + [tuple(q) for q in quads]

    # Product modulus M(Y) of degree 4 + 2*num_quad_places == ncoeffs_out - 1
    m_total: Tuple[int, ...] = (1,)
    for m_i in moduli:
        m_total = _gf4_poly_mul(m_total, m_i)
    assert len(m_total) - 1 == ncoeffs_out - 1

    t1_sched = synthesize_wiedemann_schedule(1)  # 3x2
    in_bits = 2 * deg_d
    out_bits = 2 * ncoeffs_out

    def gf4_const_mat(alpha: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        col0 = int_to_gf2_bits(_gf4_mul(alpha, 1), 2)
        col1 = int_to_gf2_bits(_gf4_mul(alpha, 2), 2)
        return ((col0[0], col1[0]), (col0[1], col1[1]))

    u_all: List[Tuple[int, ...]] = []
    v_all: List[Tuple[int, ...]] = []
    w_cols_by_block: List[Tuple[Tuple[int, ...], ...]] = []

    # Helper: for modulus m_i of degree k_i in {1, 2}, compute:
    #   1) Evaluation map E_i: (2*deg_d) -> (2*k_i) mapping A(Y) -> A(Y) mod m_i
    #   2) CRT lift map L_i: (2*k_i) -> (2*ncoeffs_out) mapping r_i(Y) -> (r_i(Y) * B_i(Y)) mod M(Y),
    #      where B_i(Y) = (M(Y)/m_i(Y)) * ((M/m_i)^{-1} mod m_i).
    for idx, m_i in enumerate(moduli):
        k_i = len(m_i) - 1
        m_other, rem_zero = _gf4_poly_divmod(m_total, m_i)
        assert rem_zero == (0,)
        g_poly, inv_m_other, _ = _gf4_poly_egcd(m_other, m_i)
        assert g_poly == (1,)
        crt_idem_i = _gf4_poly_mul(m_other, inv_m_other)

        # Build E_i (2*k_i x 2*deg_d) over GF(2) by reducing basis monomials Y^j (alpha in {1, 2})
        e_cols: List[Tuple[int, ...]] = []
        for coeff_idx in range(deg_d):
            for bit_idx in range(2):
                alpha = 1 << bit_idx
                mon = [0] * (coeff_idx + 1)
                mon[coeff_idx] = alpha
                _, rem = _gf4_poly_divmod(mon, m_i)
                bits: List[int] = []
                for c_pos in range(k_i):
                    c_val = rem[c_pos] if c_pos < len(rem) else 0
                    bits.extend((c_val & 1, (c_val >> 1) & 1))
                e_cols.append(tuple(bits))
        e_mat = tuple(tuple(e_cols[col][row] for col in range(in_bits)) for row in range(2 * k_i))

        # Local multiplier on GF(4)[Y]/(m_i): Rank 3 if k_i == 1 else Rank 9
        loc_sched = t1_sched if k_i == 1 else _synthesize_quadratic_mod_gf4_schedule(m_i)  # type: ignore[arg-type]
        u_block = gf2_mat_mul(loc_sched.U, e_mat)
        v_block = gf2_mat_mul(loc_sched.V, e_mat)

        # Build CRT lift L_i (out_bits x 2*k_i) mapping r_i(Y) -> (r_i(Y) * crt_idem_i(Y)) mod M(Y)
        l_cols: List[Tuple[int, ...]] = []
        for r_pos in range(k_i):
            for bit_idx in range(2):
                alpha = 1 << bit_idx
                r_poly = [0] * (r_pos + 1)
                r_poly[r_pos] = alpha
                _, lifted = _gf4_poly_divmod(_gf4_poly_mul(r_poly, crt_idem_i), m_total)
                bits = []
                for c_pos in range(ncoeffs_out):
                    c_val = lifted[c_pos] if c_pos < len(lifted) else 0
                    bits.extend((c_val & 1, (c_val >> 1) & 1))
                l_cols.append(tuple(bits))
        l_mat = tuple(tuple(l_cols[col][row] for col in range(2 * k_i)) for row in range(out_bits))

        w_block = gf2_mat_mul(l_mat, loc_sched.W)
        u_all.extend(u_block)
        v_all.extend(v_block)
        w_cols_by_block.append(w_block)

    # Point at infinity: m_inf = A_{deg_d - 1} * B_{deg_d - 1} in GF(4)
    # Since C(Y) = (C(Y) mod M(Y)) + C_{ncoeffs_out - 1} * M(Y) and M(Y) is monic of degree ncoeffs_out - 1,
    # C(Y) = R_crt(Y) ^ (m_inf * M(Y))!
    e_inf = tuple(
        tuple(1 if col == 2 * (deg_d - 1) + row else 0 for col in range(in_bits))
        for row in range(2)
    )
    u_inf = gf2_mat_mul(t1_sched.U, e_inf)
    v_inf = gf2_mat_mul(t1_sched.V, e_inf)

    # Lift map for m_inf * M(Y):
    l_inf_cols: List[Tuple[int, ...]] = []
    for bit_idx in range(2):
        alpha = 1 << bit_idx
        scaled_m = tuple(_gf4_mul(alpha, c) for c in m_total)
        bits = []
        for c_pos in range(ncoeffs_out):
            c_val = scaled_m[c_pos] if c_pos < len(scaled_m) else 0
            bits.extend((c_val & 1, (c_val >> 1) & 1))
        l_inf_cols.append(tuple(bits))
    l_inf_mat = tuple(tuple(l_inf_cols[col][row] for col in range(2)) for row in range(out_bits))
    w_inf = gf2_mat_mul(l_inf_mat, t1_sched.W)

    u_all.extend(u_inf)
    v_all.extend(v_inf)
    w_cols_by_block.append(w_inf)

    # Concatenate W blocks horizontally -> out_bits x total_rank
    w_all: List[Tuple[int, ...]] = []
    for row_idx in range(out_bits):
        merged_row: List[int] = []
        for blk in w_cols_by_block:
            merged_row.extend(blk[row_idx])
        w_all.append(tuple(merged_row))

    return tuple(u_all), tuple(v_all), tuple(w_all)


def _embed_tower_over_gf4(k: int) -> Tuple[Tuple[Tuple[int, ...], ...], Tuple[Tuple[int, ...], ...], int]:
    """Find a canonical element `theta in T_k` (`k in {3, 4}`) such that `(1, theta, ..., theta^{d_4-1})`
    is a `T_1 = GF(4)`-basis of `T_k` (`d_4 = 2^{k-1}`), returning `(M_poly_to_tk, M_tk_to_poly, theta)`.
    """
    bits = 1 << k
    d_4 = bits // 2
    for theta in range(4, 1 << bits):
        cols: List[Tuple[int, ...]] = []
        cur = 1
        for _ in range(d_4):
            # Coefficient c0 + c1 * X_0 at power theta^j:
            cols.append(int_to_gf2_bits(cur, bits))
            cols.append(int_to_gf2_bits(binius_mul(2, cur, k), bits))
            cur = binius_mul(cur, theta, k)
        m_poly_to_tk = tuple(tuple(cols[col][row] for col in range(bits)) for row in range(bits))
        det, m_tk_to_poly = gf2_det_and_inv(m_poly_to_tk)
        if det == 1 and m_tk_to_poly is not None:
            return m_poly_to_tk, m_tk_to_poly, theta
    raise RuntimeError(f"No GF(4) primitive generator found in T_{k}")


def synthesize_binius_t3_chudnovsky_rank24() -> GF2BilinearSchedule:
    """Synthesize the **Rank-24** (`24` AND gates vs `27` Wiedemann and `64` schoolbook = `-62.50%`)
    `GF(4)`-interpolated Chudnovsky-CRT schedule on `T_3 = GF(2^8)`.
    """
    u_poly, v_poly, w_poly = _chudnovsky_gf4_poly_product_schedule(deg_d=4, num_quad_places=1)
    _, m_tk_to_poly, theta = _embed_tower_over_gf4(3)

    # Reduction map R_red: 14 bits (C_0 .. C_6 over GF(4)) -> 8 bits in T_3
    # Maps (c_pos, bit_idx) -> (X_0^{bit_idx} * theta^{c_pos}) in T_3
    r_cols: List[Tuple[int, ...]] = []
    cur = 1
    for _ in range(7):
        r_cols.append(int_to_gf2_bits(cur, 8))
        r_cols.append(int_to_gf2_bits(binius_mul(2, cur, 3), 8))
        cur = binius_mul(cur, theta, 3)
    r_red = tuple(tuple(r_cols[col][row] for col in range(14)) for row in range(8))

    u_t3 = gf2_mat_mul(u_poly, m_tk_to_poly)
    v_t3 = gf2_mat_mul(v_poly, m_tk_to_poly)
    w_t3 = gf2_mat_mul(r_red, w_poly)
    return GF2BilinearSchedule(
        name="Binius_T3_Chudnovsky_GF4_Rank24",
        target_name="Binius_T3_GF2_8",
        degree=8,
        rank=24,
        U=u_t3,
        V=v_t3,
        W=w_t3,
        description=(
            "Chudnovsky-CRT over GF(4) (5 deg-1 places + 1 deg-2 place) for T_3 = GF(2^8): "
            "24 AND gates (-62.50% vs 64 schoolbook, -11.11% vs 27 Wiedemann)"
        ),
    )


def synthesize_binius_t4_toom_gf16_rank63() -> GF2BilinearSchedule:
    """Synthesize the **Rank-63** (`7 * 9 = 63` AND gates vs `81` Wiedemann and `256` schoolbook)
    7-point `GF(16)` Lagrange/Toom-4 schedule on `T_4 = GF(2^16)`.
    """
    t2_sched = synthesize_wiedemann_schedule(2)  # Rank 9 on T_2 = GF(16)
    # T_4 has degree 4 over T_2 with generator theta = X_3 = 1 << 8 in T_4
    theta = 1 << 8
    cols: List[Tuple[int, ...]] = []
    cur = 1
    for _ in range(4):
        for b in range(4):
            cols.append(int_to_gf2_bits(binius_mul(1 << b, cur, 4), 16))
        cur = binius_mul(cur, theta, 4)
    m_poly_to_t4 = tuple(tuple(cols[col][row] for col in range(16)) for row in range(16))
    det, m_t4_to_poly = gf2_det_and_inv(m_poly_to_t4)
    assert det == 1 and m_t4_to_poly is not None

    # 6 finite evaluation points in GF(16): 0, 1, 2, 3, 4, 5 plus infinity!
    pts = (0, 1, 2, 3, 4, 5)

    def gf16_inv(x: int) -> int:
        return binius_inv(x, 2)

    def gf16_mul(x: int, y: int) -> int:
        return binius_mul(x, y, 2)

    def gf16_mat(alpha: int) -> Tuple[Tuple[int, ...], ...]:
        c_list = [int_to_gf2_bits(gf16_mul(alpha, 1 << b), 4) for b in range(4)]
        return tuple(tuple(c_list[col][row] for col in range(4)) for row in range(4))

    # Build 7x7 Vandermonde matrix over GF(16) for C_0 .. C_6
    # Rows 0..5: [1, alpha, alpha^2, ..., alpha^6], Row 6 (inf): [0, 0, 0, 0, 0, 0, 1]
    vand = [[0] * 7 for _ in range(7)]
    for r_i, alpha in enumerate(pts):
        p_val = 1
        for c_j in range(7):
            vand[r_i][c_j] = p_val
            p_val = gf16_mul(p_val, alpha)
    vand[6][6] = 1

    # Invert 7x7 Vandermonde over GF(16)
    aug = [vand[r_i][:] + [1 if r_i == c_j else 0 for c_j in range(7)] for r_i in range(7)]
    for col in range(7):
        piv = next(r_i for r_i in range(col, 7) if aug[r_i][col] != 0)
        aug[col], aug[piv] = aug[piv], aug[col]
        inv_p = gf16_inv(aug[col][col])
        aug[col] = [gf16_mul(v, inv_p) for v in aug[col]]
        for r_i in range(7):
            if r_i != col and aug[r_i][col] != 0:
                fac = aug[r_i][col]
                aug[r_i] = [aug[r_i][c_j] ^ gf16_mul(fac, aug[col][c_j]) for c_j in range(14)]
    vand_inv = [aug[r_i][7:] for r_i in range(7)]

    # Assemble U_poly (63 x 16), V_poly (63 x 16), and W_poly (28 x 63)
    u_blocks: List[Tuple[int, ...]] = []
    v_blocks: List[Tuple[int, ...]] = []
    for r_i in range(7):
        # 4 x 16 evaluation matrix over GF(2)
        eval_mat = [[0] * 16 for _ in range(4)]
        for c_j in range(4):
            coeff = vand[r_i][c_j] if r_i < 6 else (1 if c_j == 3 else 0)
            blk = gf16_mat(coeff)
            for rr in range(4):
                for cc in range(4):
                    eval_mat[rr][4 * c_j + cc] = blk[rr][cc]
        eval_t = tuple(tuple(row) for row in eval_mat)
        u_blocks.extend(gf2_mat_mul(t2_sched.U, eval_t))
        v_blocks.extend(gf2_mat_mul(t2_sched.V, eval_t))

    w_poly_rows = [[0] * 63 for _ in range(28)]
    for c_out in range(7):
        for r_i in range(7):
            coeff = vand_inv[c_out][r_i]
            if coeff != 0:
                blk = gf2_mat_mul(gf16_mat(coeff), t2_sched.W)  # 4 x 9
                for rr in range(4):
                    for ll in range(9):
                        w_poly_rows[4 * c_out + rr][9 * r_i + ll] ^= blk[rr][ll]

    # Reduction map R_red: 28 bits (C_0..C_6 over GF(16)) -> 16 bits in T_4
    r_cols2: List[Tuple[int, ...]] = []
    cur = 1
    for _ in range(7):
        for b in range(4):
            r_cols2.append(int_to_gf2_bits(binius_mul(1 << b, cur, 4), 16))
        cur = binius_mul(cur, theta, 4)
    r_red = tuple(tuple(r_cols2[col][row] for col in range(28)) for row in range(16))

    u_t4 = gf2_mat_mul(u_blocks, m_t4_to_poly)
    v_t4 = gf2_mat_mul(v_blocks, m_t4_to_poly)
    w_t4 = gf2_mat_mul(r_red, tuple(tuple(row) for row in w_poly_rows))
    return GF2BilinearSchedule(
        name="Binius_T4_Toom4_GF16_Rank63",
        target_name="Binius_T4_GF2_16",
        degree=16,
        rank=63,
        U=u_t4,
        V=v_t4,
        W=w_t4,
        description=(
            "7-point GF(16) Lagrange/Toom-4 interpolation on T_4 = GF(2^16): "
            "63 AND gates (-75.39% vs 256 schoolbook, -22.22% vs 81 Wiedemann)"
        ),
    )


def synthesize_binius_t4_chudnovsky_rank60() -> GF2BilinearSchedule:
    """Synthesize the **Rank-60** (`5*3 + 5*9 = 60` AND gates vs `81` Wiedemann and `256` schoolbook
    = `-76.56%`) `GF(4)` Chudnovsky-CRT schedule on `T_4 = GF(2^16)`.
    """
    u_poly, v_poly, w_poly = _chudnovsky_gf4_poly_product_schedule(deg_d=8, num_quad_places=5)
    _, m_tk_to_poly, theta = _embed_tower_over_gf4(4)

    r_cols: List[Tuple[int, ...]] = []
    cur = 1
    for _ in range(15):
        r_cols.append(int_to_gf2_bits(cur, 16))
        r_cols.append(int_to_gf2_bits(binius_mul(2, cur, 4), 16))
        cur = binius_mul(cur, theta, 4)
    r_red = tuple(tuple(r_cols[col][row] for col in range(30)) for row in range(16))

    u_t4 = gf2_mat_mul(u_poly, m_tk_to_poly)
    v_t4 = gf2_mat_mul(v_poly, m_tk_to_poly)
    w_t4 = gf2_mat_mul(r_red, w_poly)
    return GF2BilinearSchedule(
        name="Binius_T4_Chudnovsky_GF4_Rank60",
        target_name="Binius_T4_GF2_16",
        degree=16,
        rank=60,
        U=u_t4,
        V=v_t4,
        W=w_t4,
        description=(
            "Chudnovsky-CRT over GF(4) (5 deg-1 places + 5 deg-2 places) for T_4 = GF(2^16): "
            "60 AND gates (-76.56% vs 256 schoolbook, -25.93% vs 81 Wiedemann)"
        ),
    )


# ============================================================================
# 5. AES / Rijndael GF(2^8) = F_2[x] / (x^8 + x^4 + x^3 + x + 1) Isomorphism
# ============================================================================


def aes_gf256_mul_ref(a: int, b: int) -> int:
    """Reference schoolbook multiplication in AES `GF(2^8) = F_2[x]/(x^8 + x^4 + x^3 + x + 1)`."""
    a &= 0xFF
    b &= 0xFF
    acc = 0
    for _ in range(8):
        if b & 1:
            acc ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= AES_POLY & 0xFF
        b >>= 1
    return acc


def build_aes_to_binius_t3_isomorphism() -> Tuple[
    Tuple[Tuple[int, ...], ...], Tuple[Tuple[int, ...], ...], int
]:
    """Construct the canonical `8 x 8` invertible `GF(2)` linear isomorphism
    `M_{AES -> T_3}` (`det == 1 mod 2`) mapping the AES generator `x` (`0x02`) to the smallest
    root `gamma in T_3` satisfying `gamma^8 + gamma^4 + gamma^3 + gamma + 1 == 0`, along with
    its exact `GF(2)` inverse `M_{T_3 -> AES}`.
    """
    gamma_root = None
    for cand in range(2, 256):
        g2 = binius_square(cand, 3)
        g3 = binius_mul(g2, cand, 3)
        g4 = binius_square(g2, 3)
        g8 = binius_square(g4, 3)
        if (g8 ^ g4 ^ g3 ^ cand ^ 1) == 0:
            gamma_root = cand
            break
    if gamma_root is None:
        raise RuntimeError("No root of AES polynomial x^8 + x^4 + x^3 + x + 1 found in T_3")

    cols: List[Tuple[int, ...]] = []
    cur = 1
    for _ in range(8):
        cols.append(int_to_gf2_bits(cur, 8))
        cur = binius_mul(cur, gamma_root, 3)
    m_aes_to_t3 = tuple(tuple(cols[col][row] for col in range(8)) for row in range(8))
    det, m_t3_to_aes = gf2_det_and_inv(m_aes_to_t3)
    if det != 1 or m_t3_to_aes is None:
        raise RuntimeError("AES -> T_3 map failed invertibility over GF(2)")
    return m_aes_to_t3, m_t3_to_aes, gamma_root


def aes_to_binius_t3(a_aes: int) -> int:
    m_to, _, _ = _AES_ISO_CACHE
    return gf2_mat_vec(m_to, a_aes & 0xFF, 8)


def binius_t3_to_aes(a_t3: int) -> int:
    _, m_from, _ = _AES_ISO_CACHE
    return gf2_mat_vec(m_from, a_t3 & 0xFF, 8)


def aes_gf256_mul_isomorphic(a_aes: int, b_aes: int) -> int:
    """Multiply two AES `GF(2^8)` bytes via `GF(2)` basis isomorphism into Wiedemann `T_3`."""
    return binius_t3_to_aes(binius_mul(aes_to_binius_t3(a_aes), aes_to_binius_t3(b_aes), 3))


def synthesize_aes_wiedemann_rank27() -> GF2BilinearSchedule:
    """Pull back Wiedemann `T_3` Rank-27 (`27` AND gates, `-57.81%` vs `64`) directly into
    native AES `GF(2^8)` coordinates (`U_aes = U_t3 @ M`, `V_aes = V_t3 @ M`, `W_aes = M^{-1} @ W_t3`).
    """
    m_to, m_from, _ = _AES_ISO_CACHE
    t3 = synthesize_wiedemann_schedule(3)
    # Isomorphism conjugation adds <= 2*8*(<8) input/output XORs if unmerged, or merges into U, V, W!
    return GF2BilinearSchedule(
        name="AES_GF256_Wiedemann_Rank27",
        target_name="AES_GF256",
        degree=8,
        rank=27,
        U=gf2_mat_mul(t3.U, m_to),
        V=gf2_mat_mul(t3.V, m_to),
        W=gf2_mat_mul(m_from, t3.W),
        description=(
            "AES/Rijndael GF(2^8) exact GF(2) bilinear schedule pulled back via Wiedemann T_3 "
            "isomorphism (27 AND gates, -57.81% vs 64 schoolbook)"
        ),
    )


def synthesize_aes_chudnovsky_rank24() -> GF2BilinearSchedule:
    """Pull back Chudnovsky-`GF(4)` `T_3` Rank-24 (`24` AND gates, `-62.50%` vs `64`) directly
    into native AES `GF(2^8)` coordinates.
    """
    m_to, m_from, _ = _AES_ISO_CACHE
    t3_24 = synthesize_binius_t3_chudnovsky_rank24()
    return GF2BilinearSchedule(
        name="AES_GF256_Chudnovsky_Rank24",
        target_name="AES_GF256",
        degree=8,
        rank=24,
        U=gf2_mat_mul(t3_24.U, m_to),
        V=gf2_mat_mul(t3_24.V, m_to),
        W=gf2_mat_mul(m_from, t3_24.W),
        description=(
            "AES/Rijndael GF(2^8) exact GF(2) bilinear schedule via GF(4) Chudnovsky-CRT + T_3 "
            "isomorphism (24 AND gates <= 26, -62.50% vs 64 schoolbook)"
        ),
    )


_AES_ISO_CACHE = build_aes_to_binius_t3_isomorphism()


def summarize_binary_tower_benchmarks() -> Dict[str, object]:
    """Return complete summary table of Wiedemann `T_1..T_7`, Chudnovsky-`GF(4)` / Toom-`GF(16)`
    schedules, and AES `GF(2^8)` schedules for reproducible reporting.
    """
    wiedemann_levels = {k: wiedemann_karatsuba_gate_counts(k) for k in range(1, 8)}
    t3_r24 = synthesize_binius_t3_chudnovsky_rank24()
    t4_r63 = synthesize_binius_t4_toom_gf16_rank63()
    t4_r60 = synthesize_binius_t4_chudnovsky_rank60()
    aes_r27 = synthesize_aes_wiedemann_rank27()
    aes_r24 = synthesize_aes_chudnovsky_rank24()
    m_to, m_from, gamma = _AES_ISO_CACHE

    # Hybrid Chudnovsky-GF(4) base at T_4 (Rank 60) + 3 Wiedemann Karatsuba doublings to T_7:
    hybrid_t7_ands = 60 * (3**3)  # 1,620 AND gates vs 16,384 schoolbook (-90.11%)

    return {
        "wiedemann_karatsuba": wiedemann_levels,
        "extension_interpolated": {
            "T3_Chudnovsky_Rank24": {
                "degree": 8,
                "and_gates": t3_r24.rank,
                "schoolbook_and_gates": 64,
                "and_reduction_vs_schoolbook_pct": t3_r24.and_reduction_vs_schoolbook_pct,
                "and_reduction_vs_wiedemann_pct": round((1.0 - 24 / 27) * 100.0, 2),
                "matrix_xor_gates": t3_r24.naive_matrix_xor_gates,
            },
            "T4_Toom4_GF16_Rank63": {
                "degree": 16,
                "and_gates": t4_r63.rank,
                "schoolbook_and_gates": 256,
                "and_reduction_vs_schoolbook_pct": t4_r63.and_reduction_vs_schoolbook_pct,
                "and_reduction_vs_wiedemann_pct": round((1.0 - 63 / 81) * 100.0, 2),
                "matrix_xor_gates": t4_r63.naive_matrix_xor_gates,
            },
            "T4_Chudnovsky_GF4_Rank60": {
                "degree": 16,
                "and_gates": t4_r60.rank,
                "schoolbook_and_gates": 256,
                "and_reduction_vs_schoolbook_pct": t4_r60.and_reduction_vs_schoolbook_pct,
                "and_reduction_vs_wiedemann_pct": round((1.0 - 60 / 81) * 100.0, 2),
                "matrix_xor_gates": t4_r60.naive_matrix_xor_gates,
            },
            "T7_Hybrid_Chudnovsky_Wiedemann_Rank1620": {
                "degree": 128,
                "and_gates": hybrid_t7_ands,
                "schoolbook_and_gates": 16384,
                "and_reduction_vs_schoolbook_pct": round((1.0 - hybrid_t7_ands / 16384) * 100.0, 2),
                "and_reduction_vs_wiedemann_pct": round((1.0 - hybrid_t7_ands / 2187) * 100.0, 2),
            },
        },
        "aes_gf256": {
            "gamma_root_in_t3": gamma,
            "aes_to_t3_row_masks": tuple(gf2_bits_to_int(row) for row in m_to),
            "t3_to_aes_row_masks": tuple(gf2_bits_to_int(row) for row in m_from),
            "AES_Wiedemann_Rank27": {
                "and_gates": aes_r27.rank,
                "schoolbook_and_gates": 64,
                "and_reduction_vs_schoolbook_pct": aes_r27.and_reduction_vs_schoolbook_pct,
                "matrix_xor_gates": aes_r27.naive_matrix_xor_gates,
            },
            "AES_Chudnovsky_Rank24": {
                "and_gates": aes_r24.rank,
                "schoolbook_and_gates": 64,
                "and_reduction_vs_schoolbook_pct": aes_r24.and_reduction_vs_schoolbook_pct,
                "matrix_xor_gates": aes_r24.naive_matrix_xor_gates,
            },
        },
    }
