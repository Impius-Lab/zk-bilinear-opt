"""Basis-Complete Bilinear Rank & Overflow Verifier for Finite-Field Extensions.

Mathematical Guarantee:
  Given an extension K / F_p of degree d and matrices U (r x d), V (r x d),
  W = (1 / D) * W_z (d x r) over F_p (with gcd(D, p) = 1), multiplication in K
  is an F_p-bilinear map K x K -> K. By bilinearity, verifying
      sum_{l=0}^{r-1} U[l, i] * V[l, j] * W[k, l] == (e_i * e_j)_k  (mod p)
  for ALL d^2 canonical basis pairs (e_i, e_j) (0 <= i, j < d) constitutes a
  100% complete algebraic proof that the rank-r formula computes exact K-multiplication
  across all p^{2d} element pairs (a, b) in K x K.

  Optimality Lower Bound (Winograd 1977 / Alder-Strassen 1981):
  When K ~= F_p[X]/(f(X)) with f irreducible of degree d over F_p, K is a division
  algebra over F_p (every nonzero element induces a bijection K -> K of rank d).
  Intersecting d - 1 kernels of independent functionals u_1, ..., u_{d-1} leaves a
  nonzero x_0 != 0 whose left-multiplication image x_0 * K = K must lie in
  span(w_d, ..., w_r), forcing r - (d - 1) >= d <=> r >= 2d - 1.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import List, Optional, Sequence, Tuple

from .fields import (
    EXTENSION_SPECS,
    ExtensionSpec,
    bls12_377_fp2_mul_z,
    bls12_377_fp6_tower_mul_z,
    bls12_377_fp12_tower_mul_z,
    det_int_exact,
    identity_int_matrix,
    is_irreducible_rabin,
    mat_mul_int,
    mat_vec_int,
    textbook_poly_mul_fixed_z,
)


@dataclass(frozen=True)
class BilinearSchedule:
    name: str
    target_name: str
    family: str
    rank: int
    degree: int
    U: Tuple[Tuple[int, ...], ...]
    V: Tuple[Tuple[int, ...], ...]
    W_z: Tuple[Tuple[int, ...], ...]
    D: int
    declared_acc_bound_bits: Optional[int]
    declared_max_limb_slack_bits: int
    description: str

    @property
    def max_u_l1(self) -> int:
        return max(sum(abs(x) for x in row) for row in self.U)

    @property
    def max_v_l1(self) -> int:
        return max(sum(abs(x) for x in row) for row in self.V)

    @property
    def max_uv_l1_product(self) -> int:
        return max(
            sum(abs(x) for x in self.U[l]) * sum(abs(y) for y in self.V[l])
            for l in range(self.rank)
        )

    @property
    def actual_limb_slack_bits(self) -> int:
        prod = max(1, self.max_uv_l1_product)
        return 0 if prod == 1 else math.ceil(math.log2(prod))

    @property
    def max_wz_l1(self) -> int:
        return max(sum(abs(x) for x in row) for row in self.W_z)

    @property
    def nnz_total(self) -> int:
        nu = sum(1 for row in self.U for x in row if x != 0)
        nv = sum(1 for row in self.V for x in row if x != 0)
        nw = sum(1 for row in self.W_z for x in row if x != 0)
        return nu + nv + nw


@dataclass(frozen=True)
class ZCertificateReport:
    schedule_name: str
    target_name: str
    degree: int
    rank: int
    D: int
    basis_det_to: int
    basis_det_from: int
    basis_pairs_checked: int
    unimodular_basis_ok: bool
    exact_z_identity_ok: bool
    denominator_coprime_ok: bool
    errors: Tuple[str, ...]

    @property
    def passed(self) -> bool:
        return (
            len(self.errors) == 0
            and self.unimodular_basis_ok
            and self.exact_z_identity_ok
            and self.denominator_coprime_ok
        )

    def __bool__(self) -> bool:
        return self.passed


@dataclass(frozen=True)
class CertificateReport:
    schedule_name: str
    target_name: str
    prime: int
    degree: int
    rank: int
    alder_strassen_lower_bound: int
    is_alder_strassen_optimal: bool
    basis_pairs_checked: int
    basis_identity_ok: bool
    over_z_identity_ok: bool
    isomorphism_ok: bool
    irreducibility_ok: bool
    denominator_invertible_ok: bool
    accumulator_bound_ok: bool
    limb_slack_bound_ok: bool
    peak_native_bits: Optional[int]
    actual_limb_slack_bits: int
    errors: Tuple[str, ...]

    @property
    def passed(self) -> bool:
        return (
            len(self.errors) == 0
            and self.basis_identity_ok
            and self.over_z_identity_ok
            and self.isomorphism_ok
            and self.irreducibility_ok
            and self.denominator_invertible_ok
            and self.accumulator_bound_ok
            and self.limb_slack_bound_ok
        )


_BLS12_377_Z_TOWER_REFS = {
    "BLS12_377_Fp2": bls12_377_fp2_mul_z,
    "BLS12_377_Fp6": bls12_377_fp6_tower_mul_z,
    "BLS12_377_Fp12": bls12_377_fp12_tower_mul_z,
}


def certify_over_Z(
    schedule: BilinearSchedule, spec: Optional[ExtensionSpec] = None
) -> ZCertificateReport:
    """Certify exact integer bilinear identity over Z (characteristic-free, zero mod-p wrap):

        sum_{l=0}^{r-1} U[l, i] * V[l, j] * W_z[k, l] == D * (e_i *_Z e_j)_k   in Z

    for ALL d^2 canonical basis pairs (e_i, e_j), plus unimodular basis checks det(T) == +-1.
    """
    if spec is None:
        if schedule.target_name not in EXTENSION_SPECS:
            raise KeyError(f"Unknown target extension: {schedule.target_name}")
        spec = EXTENSION_SPECS[schedule.target_name]

    errors: List[str] = []
    d = spec.degree
    r = schedule.rank
    D = schedule.D

    if schedule.degree != d:
        errors.append(f"Schedule degree {schedule.degree} != target degree {d}")
    if len(schedule.U) != r or any(len(row) != d for row in schedule.U):
        errors.append(f"Malformed U dimensions (expected {r}x{d})")
    if len(schedule.V) != r or any(len(row) != d for row in schedule.V):
        errors.append(f"Malformed V dimensions (expected {r}x{d})")
    if len(schedule.W_z) != d or any(len(row) != r for row in schedule.W_z):
        errors.append(f"Malformed W_z dimensions (expected {d}x{r})")

    denom_ok = D > 0 and math.gcd(D, spec.prime) == 1
    if not denom_ok:
        errors.append(f"Denominator D={D} invalid or not coprime to prime p={spec.prime}")

    ident = identity_int_matrix(d)
    det_to = det_int_exact(spec.to_simple_basis)
    det_from = det_int_exact(spec.from_simple_basis)
    unimod_ok = (
        abs(det_to) == 1
        and abs(det_from) == 1
        and mat_mul_int(spec.from_simple_basis, spec.to_simple_basis) == ident
        and mat_mul_int(spec.to_simple_basis, spec.from_simple_basis) == ident
    )
    if not unimod_ok:
        errors.append(
            f"Non-unimodular basis transform for {spec.name}: det_to={det_to}, det_from={det_from}"
        )

    z_ok = False
    pairs_checked = 0
    z_tower_ref = _BLS12_377_Z_TOWER_REFS.get(spec.name)
    if not errors and unimod_ok:
        z_ok = True
        basis_polys = [
            mat_vec_int(spec.to_simple_basis, [1 if k == idx else 0 for k in range(d)])
            for idx in range(d)
        ]
        for i in range(d):
            ei = [1 if k == i else 0 for k in range(d)]
            pi = basis_polys[i]
            for j in range(d):
                ej = [1 if k == j else 0 for k in range(d)]
                pj = basis_polys[j]
                pairs_checked += 1
                prod_poly_z = textbook_poly_mul_fixed_z(pi, pj, spec.simple_poly)
                expected_z = mat_vec_int(spec.from_simple_basis, prod_poly_z)
                if z_tower_ref is not None:
                    tower_z = z_tower_ref(ei, ej)
                    if expected_z != tower_z:
                        z_ok = False
                        errors.append(
                            f"Z-tower isomorphism mismatch at (e_{i}, e_{j}): poly={expected_z}, tower={tower_z}"
                        )
                        break
                m_vec_z = [int(schedule.U[l][i]) * int(schedule.V[l][j]) for l in range(r)]
                got_scaled_z = [
                    sum(int(schedule.W_z[k][l]) * m_vec_z[l] for l in range(r))
                    for k in range(d)
                ]
                want_scaled_z = [D * expected_z[k] for k in range(d)]
                if got_scaled_z != want_scaled_z:
                    z_ok = False
                    errors.append(
                        f"Exact Z identity mismatch at (e_{i}, e_{j}): got {got_scaled_z}, expected {want_scaled_z}"
                    )
                    break
            if not z_ok:
                break

    return ZCertificateReport(
        schedule_name=schedule.name,
        target_name=spec.name,
        degree=d,
        rank=r,
        D=D,
        basis_det_to=det_to,
        basis_det_from=det_from,
        basis_pairs_checked=pairs_checked,
        unimodular_basis_ok=unimod_ok,
        exact_z_identity_ok=z_ok,
        denominator_coprime_ok=denom_ok,
        errors=tuple(errors),
    )


def compute_w_fp(schedule: BilinearSchedule, p: int) -> List[List[int]]:
    """Compute canonical F_p reconstruction matrix W_fp = D^{-1} * W_z mod p."""
    if schedule.D <= 0 or math.gcd(schedule.D, p) != 1:
        raise ValueError(f"Denominator D={schedule.D} is not invertible modulo p={p}")
    inv_d = pow(schedule.D, p - 2, p)
    return [[((val % p) * inv_d) % p for val in row] for row in schedule.W_z]


def evaluate_schedule_fp(
    schedule: BilinearSchedule, a: Sequence[int], b: Sequence[int], p: int
) -> List[int]:
    """Evaluate bilinear schedule (U, V, W) on elements a, b in (F_p)^d."""
    d = schedule.degree
    r = schedule.rank
    if len(a) != d or len(b) != d:
        raise ValueError(f"Expected vectors of length {d}")
    inv_d = pow(schedule.D, p - 2, p)
    m = [0] * r
    for l in range(r):
        ul = sum(schedule.U[l][i] * a[i] for i in range(d)) % p
        vl = sum(schedule.V[l][j] * b[j] for j in range(d)) % p
        m[l] = (ul * vl) % p
    out = [0] * d
    for k in range(d):
        acc = sum(schedule.W_z[k][l] * m[l] for l in range(r)) % p
        out[k] = (acc * inv_d) % p
    return out


def execute_native_word_checked(
    schedule: BilinearSchedule,
    a: Sequence[int],
    b: Sequence[int],
    p: int,
    word_bits: int,
) -> Tuple[List[int], int]:
    """Execute schedule using exact hardware-width accumulators (64-bit or 128-bit) and return (out, peak_bits).

    - For 64-bit targets (31-bit primes M31, BabyBear, KoalaBear):
      Every signed linear combination |acc| and every unsigned modular product is checked
      against < 2^63 (fits strictly inside BOTH i64 and u64 with zero overflow).
      When max_wz_l1 * (p - 1) >= 2^62 (e.g. KoalaBear^8 rank-15), reconstruction uses
      exact 2-term chunked u64 accumulation on W_fp, keeping 2*(p-1)^2 + (p-1) < 2^63.
    - For 128-bit targets (64-bit Goldilocks):
      Every intermediate value is checked against < 2^128 (u128::MAX), and signed sums < 2^127.
    """
    if word_bits not in (64, 128):
        raise ValueError(f"Unsupported native word_bits={word_bits}")
    d = schedule.degree
    r = schedule.rank
    signed_limit = (1 << 63) if word_bits == 64 else (1 << 127)
    unsigned_limit = (1 << 63) if word_bits == 64 else (1 << 128)

    peak_mag = 0

    for x in a:
        if not (0 <= x < p):
            raise ValueError(f"Input coordinate {x} out of canonical range [0, {p - 1}]")
    for y in b:
        if not (0 <= y < p):
            raise ValueError(f"Input coordinate {y} out of canonical range [0, {p - 1}]")

    m = [0] * r
    for l in range(r):
        u_acc = 0
        for i in range(d):
            u_acc += schedule.U[l][i] * a[i]
            peak_mag = max(peak_mag, abs(u_acc))
            if abs(u_acc) >= signed_limit:
                raise OverflowError(f"U accumulator overflow at row {l}: |{u_acc}| >= 2^{signed_limit.bit_length()-1}")
        v_acc = 0
        for j in range(d):
            v_acc += schedule.V[l][j] * b[j]
            peak_mag = max(peak_mag, abs(v_acc))
            if abs(v_acc) >= signed_limit:
                raise OverflowError(f"V accumulator overflow at row {l}: |{v_acc}| >= 2^{signed_limit.bit_length()-1}")
        u_mod = u_acc % p
        v_mod = v_acc % p
        prod = u_mod * v_mod
        peak_mag = max(peak_mag, prod)
        if prod >= unsigned_limit:
            raise OverflowError(f"Product overflow at mul {l}: {prod} >= {unsigned_limit}")
        m[l] = prod % p

    inv_d = pow(schedule.D, p - 2, p)
    use_direct_wz = schedule.max_wz_l1 * (p - 1) < (signed_limit >> 1)
    out = [0] * d

    if use_direct_wz:
        for k in range(d):
            w_acc = 0
            for l in range(r):
                w_acc += schedule.W_z[k][l] * m[l]
                peak_mag = max(peak_mag, abs(w_acc))
                if abs(w_acc) >= signed_limit:
                    raise OverflowError(f"W_z accumulator overflow at output {k}")
            w_rem = w_acc % p
            scaled = w_rem * inv_d
            peak_mag = max(peak_mag, scaled)
            if scaled >= unsigned_limit:
                raise OverflowError(f"Final inv_D scaling overflow at output {k}")
            out[k] = scaled % p
    else:
        w_fp = compute_w_fp(schedule, p)
        for k in range(d):
            rem = 0
            l = 0
            while l < r:
                if l + 1 < r:
                    chunk = rem + w_fp[k][l] * m[l] + w_fp[k][l + 1] * m[l + 1]
                    l += 2
                else:
                    chunk = rem + w_fp[k][l] * m[l]
                    l += 1
                peak_mag = max(peak_mag, chunk)
                if chunk >= unsigned_limit:
                    raise OverflowError(f"Chunked W_fp overflow at output {k}: {chunk}")
                rem = chunk % p
            out[k] = rem

    peak_bits = 0 if peak_mag == 0 else peak_mag.bit_length()
    return out, peak_bits


def theoretical_peak_native_bits(schedule: BilinearSchedule, p: int, word_bits: int) -> int:
    """Compute exact worst-case bit-width over ALL inputs a, b in [0, p-1]^d."""
    signed_limit = (1 << 63) if word_bits == 64 else (1 << 127)
    max_u_abs = max(
        max(sum(x for x in row if x > 0), sum(-x for x in row if x < 0)) * (p - 1)
        for row in schedule.U
    )
    max_v_abs = max(
        max(sum(x for x in row if x > 0), sum(-x for x in row if x < 0)) * (p - 1)
        for row in schedule.V
    )
    max_mul_prod = (p - 1) * (p - 1)
    use_direct_wz = schedule.max_wz_l1 * (p - 1) < (signed_limit >> 1)
    if use_direct_wz:
        max_w_abs = max(
            max(sum(x for x in row if x > 0), sum(-x for x in row if x < 0)) * (p - 1)
            for row in schedule.W_z
        )
        peak = max(max_u_abs, max_v_abs, max_mul_prod, max_w_abs)
    else:
        max_chunk = (p - 1) + 2 * (p - 1) * (p - 1)
        peak = max(max_u_abs, max_v_abs, max_mul_prod, max_chunk)
    return 0 if peak == 0 else peak.bit_length()


def verify_schedule_certificate(
    schedule: BilinearSchedule, spec: Optional[ExtensionSpec] = None
) -> CertificateReport:
    """Perform basis-complete algebraic identity, optimality, and overflow verification."""
    if spec is None:
        if schedule.target_name not in EXTENSION_SPECS:
            raise KeyError(f"Unknown target extension: {schedule.target_name}")
        spec = EXTENSION_SPECS[schedule.target_name]

    errors: List[str] = []
    d = spec.degree
    r = schedule.rank
    p = spec.prime
    as_lb = 2 * d - 1

    if schedule.degree != d:
        errors.append(f"Schedule degree {schedule.degree} != target degree {d}")
    if len(schedule.U) != r or any(len(row) != d for row in schedule.U):
        errors.append(f"Malformed U dimensions (expected {r}x{d})")
    if len(schedule.V) != r or any(len(row) != d for row in schedule.V):
        errors.append(f"Malformed V dimensions (expected {r}x{d})")
    if len(schedule.W_z) != d or any(len(row) != r for row in schedule.W_z):
        errors.append(f"Malformed W_z dimensions (expected {d}x{r})")

    denom_ok = schedule.D > 0 and math.gcd(schedule.D, p) == 1
    if not denom_ok:
        errors.append(f"Denominator D={schedule.D} is not invertible mod p={p}")

    irred_ok = is_irreducible_rabin(spec.simple_poly, p)
    if not irred_ok:
        errors.append(f"Extension polynomial {spec.simple_poly} is reducible mod p={p}")

    iso_ok = spec.verify_isomorphism() if irred_ok else False
    if not iso_ok:
        errors.append(f"Basis isomorphism check failed for {spec.name}")

    z_rep = certify_over_Z(schedule, spec)
    over_z_ok = z_rep.passed
    if not over_z_ok:
        errors.extend(z_rep.errors)

    basis_ok = False
    pairs_checked = 0
    if not errors and denom_ok:
        w_fp = compute_w_fp(schedule, p)
        u_fp = [[schedule.U[l][i] % p for i in range(d)] for l in range(r)]
        v_fp = [[schedule.V[l][j] % p for j in range(d)] for l in range(r)]
        basis_ok = True
        for i in range(d):
            ei = [1 if idx == i else 0 for idx in range(d)]
            for j in range(d):
                ej = [1 if idx == j else 0 for idx in range(d)]
                pairs_checked += 1
                m_vec = [(u_fp[l][i] * v_fp[l][j]) % p for l in range(r)]
                got = [
                    sum(w_fp[k][l] * m_vec[l] for l in range(r)) % p
                    for k in range(d)
                ]
                expected = spec.reference_mul(ei, ej)
                if got != expected:
                    basis_ok = False
                    errors.append(
                        f"Basis identity mismatch at (e_{i}, e_{j}): got {got}, expected {expected}"
                    )
                    break
            if not basis_ok:
                break

    if basis_ok and irred_ok and r < as_lb:
        errors.append(
            f"Impossible rank {r} < Alder-Strassen lower bound {as_lb} for irreducible degree-{d} field"
        )

    is_optimal = basis_ok and irred_ok and (r == as_lb) and (p + 1 >= as_lb)

    # Check limb-slack declaration
    actual_slack = schedule.actual_limb_slack_bits
    slack_ok = actual_slack <= schedule.declared_max_limb_slack_bits
    if not slack_ok:
        errors.append(
            f"Limb-slack bound violated: actual {actual_slack}b > declared {schedule.declared_max_limb_slack_bits}b"
        )

    # Check native accumulator bit-width if applicable
    peak_bits: Optional[int] = None
    acc_ok = True
    if spec.native_accumulator_bits is not None:
        word_bits = spec.native_accumulator_bits
        hard_cap = 63 if word_bits == 64 else 128
        signed_limit = (1 << 63) if word_bits == 64 else (1 << 127)
        max_u_abs = max(
            max(sum(x for x in row if x > 0), sum(-x for x in row if x < 0)) * (p - 1)
            for row in schedule.U
        )
        max_v_abs = max(
            max(sum(x for x in row if x > 0), sum(-x for x in row if x < 0)) * (p - 1)
            for row in schedule.V
        )
        use_direct_wz = schedule.max_wz_l1 * (p - 1) < (signed_limit >> 1)
        max_w_abs = (
            max(
                max(sum(x for x in row if x > 0), sum(-x for x in row if x < 0)) * (p - 1)
                for row in schedule.W_z
            )
            if use_direct_wz
            else 0
        )
        peak_bits = theoretical_peak_native_bits(schedule, p, word_bits)
        decl = schedule.declared_acc_bound_bits if schedule.declared_acc_bound_bits is not None else hard_cap
        if max(max_u_abs, max_v_abs, max_w_abs) >= signed_limit:
            acc_ok = False
            errors.append(
                f"Signed i{word_bits} accumulator overflow: max signed magnitude >= 2^{word_bits - 1}"
            )
        elif peak_bits > decl or peak_bits > hard_cap:
            acc_ok = False
            errors.append(
                f"Native accumulator bound violated: peak {peak_bits}b > min(declared={decl}b, cap={hard_cap}b)"
            )
        else:
            # Also execute on maximal adversarial vector (p-1, ..., p-1)
            max_vec = [p - 1] * d
            try:
                got_max, obs_bits = execute_native_word_checked(schedule, max_vec, max_vec, p, word_bits)
                ref_max = spec.reference_mul(max_vec, max_vec)
                if got_max != ref_max:
                    acc_ok = False
                    errors.append("Adversarial (p-1,...,p-1) execution mismatched reference_mul")
                peak_bits = max(peak_bits, obs_bits)
                if peak_bits > decl:
                    acc_ok = False
                    errors.append(f"Observed adversarial bits {peak_bits}b > declared {decl}b")
            except OverflowError as exc:
                acc_ok = False
                errors.append(str(exc))

    return CertificateReport(
        schedule_name=schedule.name,
        target_name=spec.name,
        prime=p,
        degree=d,
        rank=r,
        alder_strassen_lower_bound=as_lb,
        is_alder_strassen_optimal=is_optimal,
        basis_pairs_checked=pairs_checked,
        basis_identity_ok=basis_ok,
        over_z_identity_ok=over_z_ok,
        isomorphism_ok=iso_ok,
        irreducibility_ok=irred_ok,
        denominator_invertible_ok=denom_ok,
        accumulator_bound_ok=acc_ok,
        limb_slack_bound_ok=slack_ok,
        peak_native_bits=peak_bits,
        actual_limb_slack_bits=actual_slack,
        errors=tuple(errors),
    )
