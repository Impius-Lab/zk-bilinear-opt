"""Exact finite-field & extension-tower arithmetic for ZK STARK and SNARK targets.

Covers:
  - M31 (p = 2^31 - 1), CM31 = M31[i]/(i^2 + 1), QM31 = CM31[u]/(u^2 - (2 + i)) (StarkWare stwo)
  - BabyBear (p = 2^31 - 2^27 + 1 = 2013265921): X^4 - 11, X^5 - 2 (Plonky3 / SP1)
  - KoalaBear (p = 2^31 - 2^24 + 1 = 2130706433): X^4 - 3, X^8 - 3 (Plonky3)
  - Goldilocks (p = 2^64 - 2^32 + 1): X^2 - 7, X^4 - 7, X^5 - 3
  - BN254 & BLS12-381 pairing towers: Fp2 = Fp[u]/(u^2 + 1),
    Fp6 = Fp2[v]/(v^3 - xi) (xi = 9 + u for BN254, xi = 1 + u for BLS12-381),
    Fp12 = Fp6[w]/(w^2 - v) (Consensys gnark / arkworks canonical coordinates).
"""

from __future__ import annotations

from dataclasses import dataclass
import functools
from typing import Callable, Dict, List, Optional, Sequence, Tuple

M31_PRIME: int = (1 << 31) - 1  # 2147483647
BABYBEAR_PRIME: int = (1 << 31) - (1 << 27) + 1  # 2013265921
KOALABEAR_PRIME: int = (1 << 31) - (1 << 24) + 1  # 2130706433
GOLDILOCKS_PRIME: int = (1 << 64) - (1 << 32) + 1  # 18446744069414584321
BN254_PRIME: int = (
    21888242871839275222246405745257275088696311157297823662689037894645226208583
)
BLS12_381_PRIME: int = (
    0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
)

_ISOMORPHISM_CACHE: Dict[Tuple[object, ...], bool] = {}

PRIMES: Dict[str, int] = {
    "M31": M31_PRIME,
    "BabyBear": BABYBEAR_PRIME,
    "KoalaBear": KOALABEAR_PRIME,
    "Goldilocks": GOLDILOCKS_PRIME,
    "BN254": BN254_PRIME,
    "BLS12-381": BLS12_381_PRIME,
}


# ---------------------------------------------------------------------------
# Primality & Exact Rabin Polynomial Irreducibility over F_p
# ---------------------------------------------------------------------------

def is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin primality check (exact < 2^64, strong bases >= 2^64)."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43)
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d = n - 1
    s = 0
    while (d & 1) == 0:
        s += 1
        d >>= 1
    for a in small_primes:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _poly_strip_fp(a: Sequence[int], p: int) -> List[int]:
    out = [c % p for c in a]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def poly_mod_fp(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    """Exact univariate polynomial remainder a(X) mod b(X) over F_p."""
    rem = _poly_strip_fp(a, p)
    mod = _poly_strip_fp(b, p)
    if len(mod) == 1 and mod[0] == 0:
        raise ZeroDivisionError("Zero polynomial modulus")
    db = len(mod) - 1
    if db == 0:
        return [0]
    inv_lead = pow(mod[-1], p - 2, p)
    while len(rem) - 1 >= db and not (len(rem) == 1 and rem[0] == 0):
        shift = len(rem) - 1 - db
        factor = (rem[-1] * inv_lead) % p
        for i in range(db + 1):
            rem[shift + i] = (rem[shift + i] - factor * mod[i]) % p
        rem = _poly_strip_fp(rem, p)
    return rem


def poly_mul_mod_fp(a: Sequence[int], b: Sequence[int], f: Sequence[int], p: int) -> List[int]:
    """Multiply polynomials a(X)*b(X) modulo f(X) over F_p (variable length, stripped)."""
    prod = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        ai_mod = ai % p
        if ai_mod:
            for j, bj in enumerate(b):
                prod[i + j] = (prod[i + j] + ai_mod * (bj % p)) % p
    return poly_mod_fp(prod, f, p)


def textbook_poly_mul_fixed(
    a: Sequence[int], b: Sequence[int], f_monic: Sequence[int], p: int
) -> List[int]:
    """Reference schoolbook multiplication in F_p[X]/(f_monic(X)), returning length d."""
    d = len(f_monic) - 1
    if len(a) != d or len(b) != d or f_monic[-1] != 1:
        raise ValueError(f"Expected degree-{d} operands and monic degree-{d} modulus")
    rem = poly_mul_mod_fp(a, b, f_monic, p)
    if len(rem) < d:
        rem.extend([0] * (d - len(rem)))
    return rem[:d]


def poly_pow_mod_fp(base: Sequence[int], exp: int, f: Sequence[int], p: int) -> List[int]:
    """Binary exponentiation base(X)^exp mod f(X) over F_p."""
    result = [1]
    cur = poly_mod_fp(base, f, p)
    e = exp
    while e > 0:
        if e & 1:
            result = poly_mul_mod_fp(result, cur, f, p)
        cur = poly_mul_mod_fp(cur, cur, f, p)
        e >>= 1
    return result


def poly_gcd_fp(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    """Monic GCD of univariate polynomials over F_p."""
    x = _poly_strip_fp(a, p)
    y = _poly_strip_fp(b, p)
    while not (len(y) == 1 and y[0] == 0):
        x, y = y, poly_mod_fp(x, y, p)
    inv_lead = pow(x[-1], p - 2, p)
    return [(c * inv_lead) % p for c in x]


@functools.lru_cache(maxsize=256)
def _is_irreducible_rabin_cached(f_tup: Tuple[int, ...], p: int) -> bool:
    poly = _poly_strip_fp(f_tup, p)
    d = len(poly) - 1
    if d < 1 or poly[-1] != 1:
        return False
    prime_divs: List[int] = []
    n = d
    for q in range(2, d + 1):
        if n % q == 0:
            prime_divs.append(q)
            while n % q == 0:
                n //= q
    x_poly = [0, 1]
    for q in prime_divs:
        xp = poly_pow_mod_fp(x_poly, p ** (d // q), poly, p)
        diff = list(xp)
        if len(diff) < 2:
            diff.extend([0] * (2 - len(diff)))
        diff[1] = (diff[1] - 1) % p
        g = poly_gcd_fp(poly, diff, p)
        if len(g) - 1 > 0:
            return False
    xp_full = poly_pow_mod_fp(x_poly, p ** d, poly, p)
    return xp_full == [0, 1]


def is_irreducible_rabin(f: Sequence[int], p: int) -> bool:
    """Exact Rabin irreducibility test for monic polynomial f in F_p[X]."""
    return _is_irreducible_rabin_cached(tuple(int(c) for c in f), int(p))


# ---------------------------------------------------------------------------
# Independent Reference Tower Arithmetic (Zero Shared Code with Simple Basis)
# ---------------------------------------------------------------------------

def cm31_mul_ref(a: Sequence[int], b: Sequence[int], p: int = M31_PRIME) -> List[int]:
    """Reference schoolbook multiplication in F_p[i]/(i^2 + 1), basis [1, i]."""
    a0, a1 = a[0] % p, a[1] % p
    b0, b1 = b[0] % p, b[1] % p
    return [(a0 * b0 - a1 * b1) % p, (a0 * b1 + a1 * b0) % p]


def qm31_tower_mul_ref(a: Sequence[int], b: Sequence[int], p: int = M31_PRIME) -> List[int]:
    """Reference StarkWare stwo QM31 = CM31[u]/(u^2 - (2 + i)) multiplication.

    Canonical stwo coordinates: [a0, a1, b0, b1] <-> (a0 + a1*i) + (b0 + b1*i)*u.
    """
    ar, br_u = [a[0], a[1]], [a[2], a[3]]
    cr, dr_u = [b[0], b[1]], [b[2], b[3]]
    ac = cm31_mul_ref(ar, cr, p)
    bd = cm31_mul_ref(br_u, dr_u, p)
    # (2 + i) * (bd0 + bd1*i) = (2*bd0 - bd1) + (bd0 + 2*bd1)*i
    bd_xi = [(2 * bd[0] - bd[1]) % p, (bd[0] + 2 * bd[1]) % p]
    ad = cm31_mul_ref(ar, dr_u, p)
    bc = cm31_mul_ref(br_u, cr, p)
    return [
        (ac[0] + bd_xi[0]) % p,
        (ac[1] + bd_xi[1]) % p,
        (ad[0] + bc[0]) % p,
        (ad[1] + bc[1]) % p,
    ]


def fp2_mul_ref(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    """Reference Fp2 = Fp[u]/(u^2 + 1) multiplication, basis [1, u]."""
    return cm31_mul_ref(a, b, p)


def _fp2_mul_by_xi(x: Sequence[int], xi0: int, p: int) -> List[int]:
    """Multiply x0 + x1*u by xi = xi0 + u in Fp[u]/(u^2 + 1)."""
    return [(xi0 * x[0] - x[1]) % p, (x[0] + xi0 * x[1]) % p]


def fp6_tower_mul_ref(a: Sequence[int], b: Sequence[int], xi0: int, p: int) -> List[int]:
    """Reference gnark/arkworks Fp6 = Fp2[v]/(v^3 - (xi0 + u)) schoolbook multiplication.

    Canonical coordinates: [B0.A0, B0.A1, B1.A0, B1.A1, B2.A0, B2.A1].
    """
    A = [[a[0], a[1]], [a[2], a[3]], [a[4], a[5]]]
    B = [[b[0], b[1]], [b[2], b[3]], [b[4], b[5]]]
    C = [[0, 0] for _ in range(5)]
    for i in range(3):
        for j in range(3):
            prod = fp2_mul_ref(A[i], B[j], p)
            C[i + j][0] = (C[i + j][0] + prod[0]) % p
            C[i + j][1] = (C[i + j][1] + prod[1]) % p
    for k in (3, 4):
        shifted = _fp2_mul_by_xi(C[k], xi0, p)
        C[k - 3][0] = (C[k - 3][0] + shifted[0]) % p
        C[k - 3][1] = (C[k - 3][1] + shifted[1]) % p
    return [C[0][0], C[0][1], C[1][0], C[1][1], C[2][0], C[2][1]]


def _fp6_mul_by_v(x: Sequence[int], xi0: int, p: int) -> List[int]:
    """Multiply B0 + B1*v + B2*v^2 by v in Fp6: v*(B0 + B1*v + B2*v^2) = xi*B2 + B0*v + B1*v^2."""
    b2_xi = _fp2_mul_by_xi([x[4], x[5]], xi0, p)
    return [b2_xi[0], b2_xi[1], x[0] % p, x[1] % p, x[2] % p, x[3] % p]


def fp12_tower_mul_ref(a: Sequence[int], b: Sequence[int], xi0: int, p: int) -> List[int]:
    """Reference gnark/arkworks Fp12 = Fp6[w]/(w^2 - v) schoolbook multiplication.

    Canonical coordinates: [C0 (6 coords), C1 (6 coords)].
    """
    a0, a1 = a[:6], a[6:]
    b0, b1 = b[:6], b[6:]
    c00 = fp6_tower_mul_ref(a0, b0, xi0, p)
    c11 = fp6_tower_mul_ref(a1, b1, xi0, p)
    c11_v = _fp6_mul_by_v(c11, xi0, p)
    c01 = fp6_tower_mul_ref(a0, b1, xi0, p)
    c10 = fp6_tower_mul_ref(a1, b0, xi0, p)
    out0 = [(c00[i] + c11_v[i]) % p for i in range(6)]
    out1 = [(c01[i] + c10[i]) % p for i in range(6)]
    return out0 + out1


# ---------------------------------------------------------------------------
# Unimodular Integer Basis Isomorphisms: Tower <-> Simple Extension F_p[X]/(f)
# ---------------------------------------------------------------------------

def identity_int_matrix(d: int) -> List[List[int]]:
    return [[1 if i == j else 0 for j in range(d)] for i in range(d)]


def mat_mul_int(A: Sequence[Sequence[int]], B: Sequence[Sequence[int]]) -> List[List[int]]:
    rows = len(A)
    mid = len(B)
    cols = len(B[0])
    out = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        for k in range(mid):
            aik = A[i][k]
            if aik:
                for j in range(cols):
                    out[i][j] += aik * B[k][j]
    return out


def mat_vec_mod(M: Sequence[Sequence[int]], v: Sequence[int], p: int) -> List[int]:
    return [sum(M[i][j] * v[j] for j in range(len(v))) % p for i in range(len(M))]


def _qm31_basis_pair() -> Tuple[List[List[int]], List[List[int]]]:
    """Isomorphism QM31 <-> M31[u]/(u^4 - 4u^2 + 5).

    Since u^2 = 2 + i => i = u^2 - 2:
    (a0 + a1*i) + (b0 + b1*i)*u = (a0 - 2*a1) + (b0 - 2*b1)*u + a1*u^2 + b1*u^3.
    """
    to_poly = [
        [1, -2, 0, 0],
        [0, 0, 1, -2],
        [0, 1, 0, 0],
        [0, 0, 0, 1],
    ]
    from_poly = [
        [1, 0, 2, 0],
        [0, 0, 1, 0],
        [0, 1, 0, 2],
        [0, 0, 0, 1],
    ]
    return to_poly, from_poly


def _fp6_basis_pair(xi0: int) -> Tuple[List[List[int]], List[List[int]]]:
    """Unimodular isomorphism Fp6 = Fp2[v]/(v^3 - (xi0 + u)) <-> Fp[v]/(v^6 - 2*xi0*v^3 + xi0^2 + 1).

    Since v^3 = xi0 + u => u = v^3 - xi0:
    sum_{j=0}^2 (a_j + b_j*u)*v^j = sum_{j=0}^2 (a_j - xi0*b_j)*v^j + sum_{j=0}^2 b_j*v^{j+3}.
    """
    to_poly = [[0] * 6 for _ in range(6)]
    from_poly = [[0] * 6 for _ in range(6)]
    for j in range(3):
        # Canonical indices: a_j = 2*j, b_j = 2*j + 1
        to_poly[j][2 * j] = 1
        to_poly[j][2 * j + 1] = -xi0
        to_poly[j + 3][2 * j + 1] = 1

        from_poly[2 * j][j] = 1
        from_poly[2 * j][j + 3] = xi0
        from_poly[2 * j + 1][j + 3] = 1
    return to_poly, from_poly


def _fp12_basis_pair(xi0: int) -> Tuple[List[List[int]], List[List[int]]]:
    """Unimodular isomorphism Fp12 = Fp6[w]/(w^2 - v) <-> Fp[w]/(w^12 - 2*xi0*w^6 + xi0^2 + 1).

    In gnark E12:
      w^0 = C0.B0 (0,1), w^2 = C0.B1 (2,3), w^4 = C0.B2 (4,5),
      w^1 = C1.B0 (6,7), w^3 = C1.B1 (8,9), w^5 = C1.B2 (10,11).
    And u = w^6 - xi0.
    """
    w_power_to_gnark_pair = [
        (0, 1),    # w^0
        (6, 7),    # w^1
        (2, 3),    # w^2 = v
        (8, 9),    # w^3 = v*w
        (4, 5),    # w^4 = v^2
        (10, 11),  # w^5 = v^2*w
    ]
    to_poly = [[0] * 12 for _ in range(12)]
    from_poly = [[0] * 12 for _ in range(12)]
    for j, (idx_a, idx_b) in enumerate(w_power_to_gnark_pair):
        to_poly[j][idx_a] = 1
        to_poly[j][idx_b] = -xi0
        to_poly[j + 6][idx_b] = 1

        from_poly[idx_a][j] = 1
        from_poly[idx_a][j + 6] = xi0
        from_poly[idx_b][j + 6] = 1
    return to_poly, from_poly


# ---------------------------------------------------------------------------
# Complete Target Extension Registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExtensionSpec:
    name: str
    ecosystem: str
    prime_name: str
    prime: int
    degree: int
    simple_poly: Tuple[int, ...]  # Monic polynomial [c_0, ..., c_{d-1}, 1] over Z
    basis_labels: Tuple[str, ...]
    to_simple_basis: Tuple[Tuple[int, ...], ...]
    from_simple_basis: Tuple[Tuple[int, ...], ...]
    baseline_muls: int
    baseline_name: str
    optimal_rank: int
    native_accumulator_bits: Optional[int]  # 64 for 31-bit fields, 128 for Goldilocks, None for emulated
    emulated_limbs: Optional[Tuple[int, int]]  # (num_limbs, limb_bits) for pairing fields
    xi0: Optional[int]
    reference_mul: Callable[[Sequence[int], Sequence[int]], List[int]]

    def verify_isomorphism(self) -> bool:
        """Prove T_from * T_to == I_d over Z AND homomorphism on all d^2 basis pairs."""
        cache_key = (
            self.name,
            self.prime,
            self.degree,
            self.simple_poly,
            self.to_simple_basis,
            self.from_simple_basis,
        )
        if cache_key in _ISOMORPHISM_CACHE:
            return _ISOMORPHISM_CACHE[cache_key]
        d = self.degree
        ident = identity_int_matrix(d)
        if mat_mul_int(self.from_simple_basis, self.to_simple_basis) != ident:
            _ISOMORPHISM_CACHE[cache_key] = False
            return False
        if mat_mul_int(self.to_simple_basis, self.from_simple_basis) != ident:
            _ISOMORPHISM_CACHE[cache_key] = False
            return False
        if not is_irreducible_rabin(self.simple_poly, self.prime):
            _ISOMORPHISM_CACHE[cache_key] = False
            return False
        for i in range(d):
            ei = [1 if k == i else 0 for k in range(d)]
            pi = mat_vec_mod(self.to_simple_basis, ei, self.prime)
            for j in range(d):
                ej = [1 if k == j else 0 for k in range(d)]
                pj = mat_vec_mod(self.to_simple_basis, ej, self.prime)
                prod_poly = textbook_poly_mul_fixed(pi, pj, self.simple_poly, self.prime)
                mapped_back = mat_vec_mod(self.from_simple_basis, prod_poly, self.prime)
                ref = self.reference_mul(ei, ej)
                if mapped_back != ref:
                    _ISOMORPHISM_CACHE[cache_key] = False
                    return False
        _ISOMORPHISM_CACHE[cache_key] = True
        return True


def _tuple2d(mat: Sequence[Sequence[int]]) -> Tuple[Tuple[int, ...], ...]:
    return tuple(tuple(int(x) for x in row) for row in mat)


def _make_binomial_spec(
    name: str,
    ecosystem: str,
    prime_name: str,
    prime: int,
    degree: int,
    w_nonresidue: int,
    baseline_muls: int,
    baseline_name: str,
    acc_bits: int,
) -> ExtensionSpec:
    poly = [-w_nonresidue] + [0] * (degree - 1) + [1]
    ident = _tuple2d(identity_int_matrix(degree))
    labels = tuple("1" if i == 0 else (f"X^{i}" if i > 1 else "X") for i in range(degree))
    return ExtensionSpec(
        name=name,
        ecosystem=ecosystem,
        prime_name=prime_name,
        prime=prime,
        degree=degree,
        simple_poly=tuple(poly),
        basis_labels=labels,
        to_simple_basis=ident,
        from_simple_basis=ident,
        baseline_muls=baseline_muls,
        baseline_name=baseline_name,
        optimal_rank=2 * degree - 1,
        native_accumulator_bits=acc_bits,
        emulated_limbs=None,
        xi0=None,
        reference_mul=lambda a, b, f=tuple(poly), p=prime: textbook_poly_mul_fixed(a, b, f, p),
    )


def build_extension_registry() -> Dict[str, ExtensionSpec]:
    reg: Dict[str, ExtensionSpec] = {}

    # 1. StarkWare stwo M31 tower
    ident2 = _tuple2d(identity_int_matrix(2))
    reg["CM31"] = ExtensionSpec(
        name="CM31",
        ecosystem="StarkWare stwo",
        prime_name="M31",
        prime=M31_PRIME,
        degree=2,
        simple_poly=(1, 0, 1),
        basis_labels=("1", "i"),
        to_simple_basis=ident2,
        from_simple_basis=ident2,
        baseline_muls=4,
        baseline_name="Schoolbook-2",
        optimal_rank=3,
        native_accumulator_bits=64,
        emulated_limbs=None,
        xi0=None,
        reference_mul=lambda a, b: cm31_mul_ref(a, b, M31_PRIME),
    )

    qm_to, qm_from = _qm31_basis_pair()
    reg["QM31"] = ExtensionSpec(
        name="QM31",
        ecosystem="StarkWare stwo (Circle STARKs)",
        prime_name="M31",
        prime=M31_PRIME,
        degree=4,
        simple_poly=(5, 0, -4, 0, 1),  # u^4 - 4u^2 + 5 = 0
        basis_labels=("1", "i", "u", "i*u"),
        to_simple_basis=_tuple2d(qm_to),
        from_simple_basis=_tuple2d(qm_from),
        baseline_muls=9,
        baseline_name="Double-Karatsuba (3x3)",
        optimal_rank=7,
        native_accumulator_bits=64,
        emulated_limbs=None,
        xi0=2,
        reference_mul=lambda a, b: qm31_tower_mul_ref(a, b, M31_PRIME),
    )

    # 2. Plonky3 / SP1 Binomial Extensions
    reg["BabyBear4"] = _make_binomial_spec(
        "BabyBear4", "Plonky3 / SP1", "BabyBear", BABYBEAR_PRIME, 4, 11, 9, "Karatsuba-4", 64
    )
    reg["BabyBear5"] = _make_binomial_spec(
        "BabyBear5", "Plonky3 / SP1", "BabyBear", BABYBEAR_PRIME, 5, 2, 15, "Karatsuba-5 (2+3 split)", 64
    )
    reg["KoalaBear4"] = _make_binomial_spec(
        "KoalaBear4", "Plonky3", "KoalaBear", KOALABEAR_PRIME, 4, 3, 9, "Karatsuba-4", 64
    )
    reg["KoalaBear8"] = _make_binomial_spec(
        "KoalaBear8", "Plonky3", "KoalaBear", KOALABEAR_PRIME, 8, 3, 27, "Triple-Karatsuba (3^3)", 64
    )

    # 3. Goldilocks Extensions
    reg["Goldilocks2"] = _make_binomial_spec(
        "Goldilocks2", "Plonky2 / Plonky3", "Goldilocks", GOLDILOCKS_PRIME, 2, 7, 3, "Karatsuba-2", 128
    )
    reg["Goldilocks4"] = _make_binomial_spec(
        "Goldilocks4", "Plonky3", "Goldilocks", GOLDILOCKS_PRIME, 4, 7, 9, "Karatsuba-4", 128
    )
    reg["Goldilocks5"] = _make_binomial_spec(
        "Goldilocks5", "Plonky3", "Goldilocks", GOLDILOCKS_PRIME, 5, 3, 15, "Karatsuba-5 (2+3 split)", 128
    )

    # 4. BN254 & BLS12-381 Pairing Towers (Consensys gnark / arkworks)
    for curve_key, prime_name, p_val, xi0, limbs in [
        ("BN254", "BN254", BN254_PRIME, 9, (4, 64)),
        ("BLS12_381", "BLS12-381", BLS12_381_PRIME, 1, (6, 64)),
    ]:
        reg[f"{curve_key}_Fp2"] = ExtensionSpec(
            name=f"{curve_key}_Fp2",
            ecosystem=f"Consensys gnark / arkworks ({prime_name})",
            prime_name=prime_name,
            prime=p_val,
            degree=2,
            simple_poly=(1, 0, 1),
            basis_labels=("A0", "A1"),
            to_simple_basis=ident2,
            from_simple_basis=ident2,
            baseline_muls=3,
            baseline_name="Karatsuba-2",
            optimal_rank=3,
            native_accumulator_bits=None,
            emulated_limbs=limbs,
            xi0=xi0,
            reference_mul=lambda a, b, pv=p_val: fp2_mul_ref(a, b, pv),
        )

        to6, from6 = _fp6_basis_pair(xi0)
        c_const = xi0 * xi0 + 1
        c_mid = -2 * xi0
        reg[f"{curve_key}_Fp6"] = ExtensionSpec(
            name=f"{curve_key}_Fp6",
            ecosystem=f"Consensys gnark / arkworks ({prime_name})",
            prime_name=prime_name,
            prime=p_val,
            degree=6,
            simple_poly=(c_const, 0, 0, c_mid, 0, 0, 1),
            basis_labels=("B0.A0", "B0.A1", "B1.A0", "B1.A1", "B2.A0", "B2.A1"),
            to_simple_basis=_tuple2d(to6),
            from_simple_basis=_tuple2d(from6),
            baseline_muls=18,
            baseline_name="Karatsuba-3 x Karatsuba-2 (6x3)",
            optimal_rank=11,
            native_accumulator_bits=None,
            emulated_limbs=limbs,
            xi0=xi0,
            reference_mul=lambda a, b, x0=xi0, pv=p_val: fp6_tower_mul_ref(a, b, x0, pv),
        )

        to12, from12 = _fp12_basis_pair(xi0)
        reg[f"{curve_key}_Fp12"] = ExtensionSpec(
            name=f"{curve_key}_Fp12",
            ecosystem=f"Consensys gnark / arkworks ({prime_name})",
            prime_name=prime_name,
            prime=p_val,
            degree=12,
            simple_poly=(c_const, 0, 0, 0, 0, 0, c_mid, 0, 0, 0, 0, 0, 1),
            basis_labels=(
                "C0.B0.A0", "C0.B0.A1", "C0.B1.A0", "C0.B1.A1", "C0.B2.A0", "C0.B2.A1",
                "C1.B0.A0", "C1.B0.A1", "C1.B1.A0", "C1.B1.A1", "C1.B2.A0", "C1.B2.A1",
            ),
            to_simple_basis=_tuple2d(to12),
            from_simple_basis=_tuple2d(from12),
            baseline_muls=54,
            baseline_name="Karatsuba Tower (3x6x3)",
            optimal_rank=23,
            native_accumulator_bits=None,
            emulated_limbs=limbs,
            xi0=xi0,
            reference_mul=lambda a, b, x0=xi0, pv=p_val: fp12_tower_mul_ref(a, b, x0, pv),
        )

    return reg


EXTENSION_SPECS: Dict[str, ExtensionSpec] = build_extension_registry()
