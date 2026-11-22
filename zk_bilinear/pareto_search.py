"""Exact Vandermonde, Cyclotomic-CRT & Tower-Hybrid Bilinear Pareto Engine.

Constructs basis-certified integer-rational bilinear schedules (U, V, W_z, D) across
all STARK and SNARK extension targets, and computes the exact Pareto frontier trading
off base-field multiplications r against coefficient l_1 norm and non-native limb-carry
range-check constraints.
"""

from __future__ import annotations

from fractions import Fraction
import math
from typing import Dict, List, Optional, Sequence, Tuple

from .cost_models import FullScheduleCost, evaluate_full_cost
from .fields import EXTENSION_SPECS, ExtensionSpec, mat_mul_int
from .tensor_cert import BilinearSchedule


# ---------------------------------------------------------------------------
# Exact Q-Linear Algebra & Polynomial Helpers
# ---------------------------------------------------------------------------

def _mat_zeros_q(rows: int, cols: int) -> List[List[Fraction]]:
    return [[Fraction(0) for _ in range(cols)] for _ in range(rows)]


def _mat_inv_q(mat: Sequence[Sequence[Fraction]]) -> List[List[Fraction]]:
    n = len(mat)
    aug = [
        list(mat[i]) + [Fraction(1 if i == j else 0) for j in range(n)]
        for i in range(n)
    ]
    for col in range(n):
        piv = None
        for r in range(col, n):
            if aug[r][col] != 0:
                piv = r
                break
        if piv is None:
            raise ValueError("Singular CRT/Vandermonde interpolation matrix over Q")
        aug[col], aug[piv] = aug[piv], aug[col]
        pv = aug[col][col]
        for j in range(2 * n):
            aug[col][j] /= pv
        for r in range(n):
            if r != col and aug[r][col] != 0:
                fac = aug[r][col]
                for j in range(2 * n):
                    aug[r][j] -= fac * aug[col][j]
    return [row[n:] for row in aug]


def _poly_rem_q(a: Sequence[Fraction | int], mod_poly: Sequence[Fraction | int]) -> List[Fraction]:
    rem = [Fraction(c) for c in a]
    m = [Fraction(c) for c in mod_poly]
    assert m[-1] == 1
    dm = len(m) - 1
    while len(rem) - 1 >= dm:
        if rem[-1] != 0:
            coef = rem[-1]
            shift = len(rem) - 1 - dm
            for i in range(dm + 1):
                rem[shift + i] -= coef * m[i]
        rem.pop()
    if len(rem) < dm:
        rem.extend([Fraction(0)] * (dm - len(rem)))
    return rem


def _clear_denominators(W_q: Sequence[Sequence[Fraction]]) -> Tuple[List[List[int]], int]:
    d = len(W_q)
    r = len(W_q[0])
    denom = 1
    for i in range(d):
        for j in range(r):
            denom = math.lcm(denom, W_q[i][j].denominator)
    W_z = [[int(W_q[i][j] * denom) for j in range(r)] for i in range(d)]
    # Reduce by overall GCD if > 1
    g = denom
    for row in W_z:
        for val in row:
            g = math.gcd(g, abs(val))
    if g > 1:
        denom //= g
        W_z = [[val // g for val in row] for row in W_z]
    return W_z, denom


def _reduce_poly_W_mod_f(
    W_poly: Sequence[Sequence[Fraction]], f_monic: Sequence[int]
) -> List[List[Fraction]]:
    d = len(f_monic) - 1
    target_len = len(W_poly)
    r = len(W_poly[0])
    W_mod = _mat_zeros_q(d, r)
    for k in range(target_len):
        mon = [0] * (k + 1)
        mon[k] = 1
        rem = _poly_rem_q(mon, f_monic)
        for l in range(r):
            w_kl = W_poly[k][l]
            if w_kl != 0:
                for i in range(d):
                    if rem[i] != 0:
                        W_mod[i][l] += rem[i] * w_kl
    return W_mod


def _apply_basis_transform(
    U_poly: Sequence[Sequence[int]],
    V_poly: Sequence[Sequence[int]],
    W_poly_mod: Sequence[Sequence[Fraction]],
    to_simple: Sequence[Sequence[int]],
    from_simple: Sequence[Sequence[int]],
) -> Tuple[List[List[int]], List[List[int]], List[List[Fraction]]]:
    U_can = mat_mul_int(U_poly, to_simple)
    V_can = mat_mul_int(V_poly, to_simple)
    d = len(from_simple)
    r = len(W_poly_mod[0])
    W_can = _mat_zeros_q(d, r)
    for i in range(d):
        for k in range(d):
            f_ik = from_simple[i][k]
            if f_ik != 0:
                for l in range(r):
                    if W_poly_mod[k][l] != 0:
                        W_can[i][l] += Fraction(f_ik) * W_poly_mod[k][l]
    return U_can, V_can, W_can


# ---------------------------------------------------------------------------
# Polynomial Product Builders (Schoolbook, Karatsuba, Vandermonde, CRT, Tower)
# ---------------------------------------------------------------------------

def build_schoolbook_poly_alg(deg_a: int) -> Tuple[List[List[int]], List[List[int]], List[List[Fraction]]]:
    target_len = 2 * deg_a - 1
    r = deg_a * deg_a
    U: List[List[int]] = []
    V: List[List[int]] = []
    W = _mat_zeros_q(target_len, r)
    col = 0
    for i in range(deg_a):
        for j in range(deg_a):
            u_row = [0] * deg_a
            v_row = [0] * deg_a
            u_row[i] = 1
            v_row[j] = 1
            U.append(u_row)
            V.append(v_row)
            W[i + j][col] = Fraction(1)
            col += 1
    return U, V, W


def build_karatsuba_poly_alg(deg_a: int) -> Tuple[List[List[int]], List[List[int]], List[List[Fraction]]]:
    """Exact recursive Karatsuba polynomial product (deg < deg_a -> 2*deg_a - 1 coeffs):
    deg 1 -> 1 mul, deg 2 -> 3 muls, deg 3 -> 6 muls, deg 4 -> 9 muls, deg 5 -> 15 muls, deg 8 -> 27 muls.
    """
    if deg_a == 1:
        return [[1]], [[1]], [[Fraction(1)]]
    if deg_a == 3:
        U3 = [
            [1, 0, 0],
            [0, 1, 0],
            [0, 0, 1],
            [1, 1, 0],
            [0, 1, 1],
            [1, 0, 1],
        ]
        V3 = [row[:] for row in U3]
        W3 = [
            [Fraction(1), Fraction(0), Fraction(0), Fraction(0), Fraction(0), Fraction(0)],
            [Fraction(-1), Fraction(-1), Fraction(0), Fraction(1), Fraction(0), Fraction(0)],
            [Fraction(-1), Fraction(1), Fraction(-1), Fraction(0), Fraction(0), Fraction(1)],
            [Fraction(0), Fraction(-1), Fraction(-1), Fraction(0), Fraction(1), Fraction(0)],
            [Fraction(0), Fraction(0), Fraction(1), Fraction(0), Fraction(0), Fraction(0)],
        ]
        return U3, V3, W3

    m0 = deg_a // 2
    m1 = deg_a - m0  # m0 <= m1
    U_lo, V_lo, W_lo = build_karatsuba_poly_alg(m0)
    U_hi, V_hi, W_hi = build_karatsuba_poly_alg(m1)
    r0 = len(U_lo)
    r1 = len(U_hi)
    r_tot = r0 + 2 * r1
    target_len = 2 * deg_a - 1

    U: List[List[int]] = []
    V: List[List[int]] = []
    # P0 = A_lo * B_lo
    for l in range(r0):
        U.append(U_lo[l] + [0] * m1)
        V.append(V_lo[l] + [0] * m1)
    # P1 = A_hi * B_hi
    for l in range(r1):
        U.append([0] * m0 + U_hi[l])
        V.append([0] * m0 + V_hi[l])
    # P2 = (pad(A_lo) + A_hi) * (pad(B_lo) + B_hi)
    for l in range(r1):
        u_sum = [0] * deg_a
        v_sum = [0] * deg_a
        for i in range(m1):
            if i < m0:
                u_sum[i] += U_hi[l][i]
                v_sum[i] += V_hi[l][i]
            u_sum[m0 + i] += U_hi[l][i]
            v_sum[m0 + i] += V_hi[l][i]
        U.append(u_sum)
        V.append(v_sum)

    W = _mat_zeros_q(target_len, r_tot)
    # C(X) = P0(X) + X^m0 * (P2(X) - P0(X) - P1(X)) + X^(2*m0) * P1(X)
    for k in range(len(W_lo)):
        for l in range(r0):
            W[k][l] += W_lo[k][l]
            W[m0 + k][l] -= W_lo[k][l]
    for k in range(len(W_hi)):
        for l in range(r1):
            W[2 * m0 + k][r0 + l] += W_hi[k][l]
            W[m0 + k][r0 + l] -= W_hi[k][l]
            W[m0 + k][r0 + r1 + l] += W_hi[k][l]
    return U, V, W


def build_vandermonde_poly_alg(
    deg_a: int, nodes: Sequence[int], use_infty: bool = True
) -> Tuple[List[List[int]], List[List[int]], List[List[Fraction]]]:
    target_len = 2 * deg_a - 1
    r = len(nodes) + (1 if use_infty else 0)
    if r != target_len:
        raise ValueError(f"Expected {target_len} evaluation nodes, got {r}")

    U: List[List[int]] = []
    V: List[List[int]] = []
    eval_mat: List[List[Fraction]] = []
    for alpha in nodes:
        row_in = [alpha ** i for i in range(deg_a)]
        U.append(row_in)
        V.append(row_in[:])
        eval_mat.append([Fraction(alpha ** k) for k in range(target_len)])
    if use_infty:
        u_inf = [0] * deg_a
        u_inf[-1] = 1
        U.append(u_inf)
        V.append(u_inf[:])
        row_inf = [Fraction(0)] * target_len
        row_inf[-1] = Fraction(1)
        eval_mat.append(row_inf)

    W_poly = _mat_inv_q(eval_mat)
    return U, V, W_poly


def _karatsuba_deg2_mod(
    mod_poly: Sequence[int],
) -> Tuple[List[List[int]], List[List[int]], List[List[Fraction]]]:
    assert len(mod_poly) == 3 and mod_poly[2] == 1
    m0, m1 = Fraction(mod_poly[0]), Fraction(mod_poly[1])
    U = [[1, 0], [0, 1], [1, 1]]
    V = [[1, 0], [0, 1], [1, 1]]
    W = [
        [Fraction(1), -m0, Fraction(0)],
        [Fraction(-1), Fraction(-1) - m1, Fraction(1)],
    ]
    return U, V, W


def build_crt_poly_alg(
    deg_a: int,
    linear_nodes: Sequence[int],
    quad_moduli: Sequence[Sequence[int]],
    use_infty: bool = True,
) -> Tuple[List[List[int]], List[List[int]], List[List[Fraction]]]:
    """Exact Chinese Remainder Theorem polynomial product over pairwise coprime linear & quadratic moduli."""
    target_len = 2 * deg_a - 1
    conds = len(linear_nodes) + 2 * len(quad_moduli) + (1 if use_infty else 0)
    if conds != target_len:
        raise ValueError(f"CRT condition count {conds} != {target_len}")

    U: List[List[int]] = []
    V: List[List[int]] = []
    obs_from_c: List[List[Fraction]] = []
    blocks: List[List[List[Fraction]]] = []

    for alpha in linear_nodes:
        row_in = [alpha ** i for i in range(deg_a)]
        U.append(row_in)
        V.append(row_in[:])
        obs_from_c.append([Fraction(alpha ** k) for k in range(target_len)])
        blocks.append([[Fraction(1)]])

    for qmod in quad_moduli:
        red_in: List[List[Fraction]] = []
        for i in range(deg_a):
            mon = [0] * (i + 1)
            mon[i] = 1
            red_in.append(_poly_rem_q(mon, qmod))
        Uq, Vq, Wq = _karatsuba_deg2_mod(qmod)
        for r_idx in range(3):
            u_row: List[int] = []
            v_row: List[int] = []
            for i in range(deg_a):
                vu = Uq[r_idx][0] * red_in[i][0] + Uq[r_idx][1] * red_in[i][1]
                vv = Vq[r_idx][0] * red_in[i][0] + Vq[r_idx][1] * red_in[i][1]
                assert vu.denominator == 1 and vv.denominator == 1
                u_row.append(int(vu))
                v_row.append(int(vv))
            U.append(u_row)
            V.append(v_row)
        blocks.append(Wq)

        row0: List[Fraction] = []
        row1: List[Fraction] = []
        for k in range(target_len):
            mon = [0] * (k + 1)
            mon[k] = 1
            rk = _poly_rem_q(mon, qmod)
            row0.append(rk[0])
            row1.append(rk[1])
        obs_from_c.append(row0)
        obs_from_c.append(row1)

    if use_infty:
        u_inf = [0] * deg_a
        u_inf[-1] = 1
        U.append(u_inf)
        V.append(u_inf[:])
        row_inf = [Fraction(0)] * target_len
        row_inf[-1] = Fraction(1)
        obs_from_c.append(row_inf)
        blocks.append([[Fraction(1)]])

    r_tot = len(U)
    obs_from_m = _mat_zeros_q(conds, r_tot)
    r_off = 0
    c_off = 0
    for blk in blocks:
        br = len(blk)
        bc = len(blk[0])
        for i in range(br):
            for j in range(bc):
                obs_from_m[r_off + i][c_off + j] = blk[i][j]
        r_off += br
        c_off += bc

    inv_c = _mat_inv_q(obs_from_c)
    W_poly = _mat_zeros_q(target_len, r_tot)
    for i in range(target_len):
        for k in range(conds):
            ick = inv_c[i][k]
            if ick != 0:
                for j in range(r_tot):
                    om = obs_from_m[k][j]
                    if om != 0:
                        W_poly[i][j] += ick * om
    return U, V, W_poly


def compose_binomial_tower(
    U_out: Sequence[Sequence[int]],
    V_out: Sequence[Sequence[int]],
    W_poly_out: Sequence[Sequence[Fraction]],
    U_in: Sequence[Sequence[int]],
    V_in: Sequence[Sequence[int]],
    W_in: Sequence[Sequence[Fraction]],
    L_xi: Sequence[Sequence[int]],
) -> Tuple[List[List[int]], List[List[int]], List[List[Fraction]]]:
    """Compose outer polynomial product mod (Y^d_out - xi) with inner algebra multiplication."""
    r_out = len(U_out)
    d_out = len(U_out[0])
    target_out = len(W_poly_out)
    r_in = len(U_in)
    d_in = len(U_in[0])
    r_tot = r_out * r_in
    d_tot = d_out * d_in

    U_tot: List[List[int]] = []
    V_tot: List[List[int]] = []
    for lo in range(r_out):
        for li in range(r_in):
            u_row: List[int] = []
            v_row: List[int] = []
            for jo in range(d_out):
                for ji in range(d_in):
                    u_row.append(U_out[lo][jo] * U_in[li][ji])
                    v_row.append(V_out[lo][jo] * V_in[li][ji])
            U_tot.append(u_row)
            V_tot.append(v_row)

    W_tot = _mat_zeros_q(d_tot, r_tot)
    for k in range(target_out):
        dest = k if k < d_out else k - d_out
        use_xi = k >= d_out
        for lo in range(r_out):
            w_s = W_poly_out[k][lo]
            if w_s == 0:
                continue
            for li in range(r_in):
                col = lo * r_in + li
                for i_in in range(d_in):
                    if not use_xi:
                        W_tot[dest * d_in + i_in][col] += w_s * W_in[i_in][li]
                    else:
                        acc = Fraction(0)
                        for t in range(d_in):
                            if L_xi[i_in][t] != 0 and W_in[t][li] != 0:
                                acc += Fraction(L_xi[i_in][t]) * W_in[t][li]
                        W_tot[dest * d_in + i_in][col] += w_s * acc
    return U_tot, V_tot, W_tot


def _make_schedule_from_q(
    name: str,
    spec: ExtensionSpec,
    family: str,
    U: Sequence[Sequence[int]],
    V: Sequence[Sequence[int]],
    W_q: Sequence[Sequence[Fraction]],
    description: str,
) -> BilinearSchedule:
    W_z, D = _clear_denominators(W_q)
    r = len(U)
    u_tup = tuple(tuple(int(x) for x in row) for row in U)
    v_tup = tuple(tuple(int(x) for x in row) for row in V)
    wz_tup = tuple(tuple(int(x) for x in row) for row in W_z)

    max_uv = max(
        sum(abs(x) for x in u_tup[l]) * sum(abs(y) for y in v_tup[l])
        for l in range(r)
    )
    slack_b = 0 if max_uv <= 1 else math.ceil(math.log2(max_uv))
    acc_bound: Optional[int] = None
    if spec.native_accumulator_bits == 64:
        acc_bound = 63
    elif spec.native_accumulator_bits == 128:
        acc_bound = 128

    return BilinearSchedule(
        name=name,
        target_name=spec.name,
        family=family,
        rank=r,
        degree=spec.degree,
        U=u_tup,
        V=v_tup,
        W_z=wz_tup,
        D=D,
        declared_acc_bound_bits=acc_bound,
        declared_max_limb_slack_bits=slack_b,
        description=description,
    )


def _make_simple_poly_schedule(
    name: str,
    spec: ExtensionSpec,
    family: str,
    U_poly: Sequence[Sequence[int]],
    V_poly: Sequence[Sequence[int]],
    W_poly: Sequence[Sequence[Fraction]],
    description: str,
) -> BilinearSchedule:
    W_mod = _reduce_poly_W_mod_f(W_poly, spec.simple_poly)
    U_can, V_can, W_can = _apply_basis_transform(
        U_poly, V_poly, W_mod, spec.to_simple_basis, spec.from_simple_basis
    )
    return _make_schedule_from_q(name, spec, family, U_can, V_can, W_can, description)


# ---------------------------------------------------------------------------
# Complete Pareto Schedule Suite per Target
# ---------------------------------------------------------------------------

def build_all_schedules() -> Dict[str, List[BilinearSchedule]]:
    suite: Dict[str, List[BilinearSchedule]] = {}

    # 1. CM31 (d = 2)
    spec_cm31 = EXTENSION_SPECS["CM31"]
    Us2, Vs2, Ws2 = build_schoolbook_poly_alg(2)
    Uk2, Vk2, Wk2 = build_karatsuba_poly_alg(2)
    suite["CM31"] = [
        _make_simple_poly_schedule("CM31_Schoolbook4", spec_cm31, "Schoolbook-Baseline", Us2, Vs2, Ws2, "Naive 4-mul complex schoolbook"),
        _make_simple_poly_schedule("CM31_Rank3", spec_cm31, "Vandermonde", Uk2, Vk2, Wk2, "Alder-Strassen optimal 3-mul Karatsuba {0, 1, inf}"),
    ]

    # 2. QM31 (d = 4, StarkWare stwo)
    spec_qm31 = EXTENSION_SPECS["QM31"]
    # Baseline 9-mul double-Karatsuba on CM31[u]/(u^2 - (2 + i)):
    L_2pi = [[2, -1], [1, 2]]
    W_cm31_3 = _reduce_poly_W_mod_f(Wk2, [1, 0, 1])
    U_qm9, V_qm9, W_qm9 = compose_binomial_tower(Uk2, Vk2, Wk2, Uk2, Vk2, W_cm31_3, L_2pi)
    U_qm8, V_qm8, Wp_qm8 = build_crt_poly_alg(4, [-1, 0, 1, 2], [[1, 0, 1]], True)
    U_qm7, V_qm7, Wp_qm7 = build_vandermonde_poly_alg(4, [-2, -1, 0, 1, 2, 3], True)
    suite["QM31"] = [
        _make_schedule_from_q("QM31_Karatsuba9", spec_qm31, "Karatsuba-Baseline", U_qm9, V_qm9, W_qm9, "Baseline stwo double-Karatsuba (3x3 = 9 M31 muls)"),
        _make_simple_poly_schedule("QM31_CRT8", spec_qm31, "Cyclotomic-CRT", U_qm8, V_qm8, Wp_qm8, "8-mul CRT over M31[u]/(u^4-4u^2+5) via {-1,0,1,2,inf} + (u^2+1)"),
        _make_simple_poly_schedule("QM31_Rank7", spec_qm31, "Vandermonde", U_qm7, V_qm7, Wp_qm7, "Alder-Strassen optimal 7-mul interpolation over M31[u]/(u^4-4u^2+5) on {-2,-1,0,1,2,3,inf}"),
    ]

    # 3. Quartic Binomials: BabyBear4, KoalaBear4, Goldilocks4
    Uk4, Vk4, Wpk4 = build_karatsuba_poly_alg(4)
    for tname in ("BabyBear4", "KoalaBear4", "Goldilocks4"):
        sp = EXTENSION_SPECS[tname]
        suite[tname] = [
            _make_simple_poly_schedule(f"{tname}_Karatsuba9", sp, "Karatsuba-Baseline", Uk4, Vk4, Wpk4, "Baseline 2-level Karatsuba (9 muls)"),
            _make_simple_poly_schedule(f"{tname}_CRT8", sp, "Cyclotomic-CRT", U_qm8, V_qm8, Wp_qm8, "8-mul Cyclotomic CRT {-1,0,1,2,inf,X^2+1}"),
            _make_simple_poly_schedule(f"{tname}_Rank7", sp, "Vandermonde", U_qm7, V_qm7, Wp_qm7, "Alder-Strassen optimal 7-mul Toom-4 on {-2,-1,0,1,2,3,inf}"),
        ]

    # 4. Goldilocks2 (d = 2)
    sp_g2 = EXTENSION_SPECS["Goldilocks2"]
    suite["Goldilocks2"] = [
        _make_simple_poly_schedule("Goldilocks2_Schoolbook4", sp_g2, "Schoolbook-Baseline", Us2, Vs2, Ws2, "Schoolbook quadratic (4 muls)"),
        _make_simple_poly_schedule("Goldilocks2_Rank3", sp_g2, "Vandermonde", Uk2, Vk2, Wk2, "Alder-Strassen optimal 3-mul Karatsuba {0,1,inf}"),
    ]

    # 5. Quintic Binomials: BabyBear5, Goldilocks5 (d = 5)
    Uk5, Vk5, Wpk5 = build_karatsuba_poly_alg(5)  # 15 muls
    U5_10, V5_10, Wp5_10 = build_crt_poly_alg(5, [-2, -1, 0, 1, 2, 3], [[1, 0, 1]], True)  # 6+2+1=9 conds -> 6+3+1=10 muls
    U5_9, V5_9, Wp5_9 = build_vandermonde_poly_alg(5, [-4, -3, -2, -1, 0, 1, 2, 3], True)  # 9 muls
    for tname in ("BabyBear5", "Goldilocks5"):
        sp = EXTENSION_SPECS[tname]
        suite[tname] = [
            _make_simple_poly_schedule(f"{tname}_Karatsuba15", sp, "Karatsuba-Baseline", Uk5, Vk5, Wpk5, "Baseline 2+3 block Karatsuba (15 muls)"),
            _make_simple_poly_schedule(f"{tname}_CRT10", sp, "Cyclotomic-CRT", U5_10, V5_10, Wp5_10, "10-mul Cyclotomic CRT {-2..3,inf,X^2+1}"),
            _make_simple_poly_schedule(f"{tname}_Rank9", sp, "Vandermonde", U5_9, V5_9, Wp5_9, "Alder-Strassen optimal 9-mul Toom-5 on {-4,-3,-2,-1,0,1,2,3,inf}"),
        ]

    # 6. Octic Binomial: KoalaBear8 (d = 8)
    sp_k8 = EXTENSION_SPECS["KoalaBear8"]
    Uk8, Vk8, Wpk8 = build_karatsuba_poly_alg(8)  # 27 muls
    U8_17, V8_17, Wp8_17 = build_crt_poly_alg(8, list(range(-5, 5)), [[1, 0, 1], [1, 1, 1]], True)  # 10+4+1=15 conds -> 10+6+1=17 muls
    U8_15, V8_15, Wp8_15 = build_vandermonde_poly_alg(8, list(range(-7, 7)), True)  # 15 muls
    suite["KoalaBear8"] = [
        _make_simple_poly_schedule("KoalaBear8_Karatsuba27", sp_k8, "Karatsuba-Baseline", Uk8, Vk8, Wpk8, "Baseline triple-Karatsuba (3^3 = 27 muls)"),
        _make_simple_poly_schedule("KoalaBear8_CRT17", sp_k8, "Cyclotomic-CRT", U8_17, V8_17, Wp8_17, "17-mul Cyclotomic CRT {-5..4,inf,Phi_4,Phi_3}"),
        _make_simple_poly_schedule("KoalaBear8_Rank15", sp_k8, "Vandermonde", U8_15, V8_15, Wp8_15, "Alder-Strassen optimal 15-mul Toom-8 on {-7..6,inf}"),
    ]

    # 7. Pairing Towers: BN254 & BLS12-381 (Fp2, Fp6, Fp12)
    Uk3, Vk3, Wpk3 = build_karatsuba_poly_alg(3)  # 6 muls
    Ut3, Vt3, Wpt3 = build_vandermonde_poly_alg(3, [-2, -1, 0, 1], True)  # 5 muls
    U6_13, V6_13, Wp6_13 = build_crt_poly_alg(6, [-3, -2, -1, 0, 1, 2], [[1, 0, 1], [1, 1, 1]], True)
    U6_12, V6_12, Wp6_12 = build_crt_poly_alg(6, list(range(-4, 4)), [[1, 0, 1]], True)
    U6_11, V6_11, Wp6_11 = build_vandermonde_poly_alg(6, list(range(-5, 5)), True)

    quads_7 = [[1, 0, 1], [1, 1, 1], [1, -1, 1], [2, 0, 1], [2, 1, 1], [2, -1, 1], [3, 0, 1]]
    U12_30, V12_30, Wp12_30 = build_crt_poly_alg(12, list(range(-4, 4)), quads_7, True)
    quads_4 = [[1, 0, 1], [1, 1, 1], [1, -1, 1], [2, 0, 1]]
    U12_27, V12_27, Wp12_27 = build_crt_poly_alg(12, list(range(-7, 7)), quads_4, True)
    U12_23, V12_23, Wp12_23 = build_vandermonde_poly_alg(12, list(range(-11, 11)), True)

    # Permutation between Fp2[w]/(w^6 - xi) block order [w^0,w^1,w^2,w^3,w^4,w^5]
    # and gnark E12 block order [C0=(w^0,w^2,w^4), C1=(w^1,w^3,w^5)]:
    w6_from_gnark = [[0] * 12 for _ in range(12)]
    for w_exp, (g0, g1) in enumerate([(0, 1), (6, 7), (2, 3), (8, 9), (4, 5), (10, 11)]):
        w6_from_gnark[2 * w_exp][g0] = 1
        w6_from_gnark[2 * w_exp + 1][g1] = 1
    gnark_from_w6 = [[w6_from_gnark[j][i] for j in range(12)] for i in range(12)]

    for curve_key in ("BN254", "BLS12_381"):
        sp2 = EXTENSION_SPECS[f"{curve_key}_Fp2"]
        sp6 = EXTENSION_SPECS[f"{curve_key}_Fp6"]
        sp12 = EXTENSION_SPECS[f"{curve_key}_Fp12"]
        xi0 = sp6.xi0
        assert xi0 is not None

        suite[sp2.name] = [
            _make_simple_poly_schedule(f"{curve_key}_Fp2_Schoolbook4", sp2, "Schoolbook-Baseline", Us2, Vs2, Ws2, "Schoolbook Fp2 (4 Fp muls)"),
            _make_simple_poly_schedule(f"{curve_key}_Fp2_Rank3", sp2, "Vandermonde", Uk2, Vk2, Wk2, "Optimal 3-mul Karatsuba Fp2"),
        ]

        W2_mod = _reduce_poly_W_mod_f(Wk2, [1, 0, 1])
        L_xi = [[xi0, -1], [1, xi0]]
        U6_18, V6_18, W6_18 = compose_binomial_tower(Uk3, Vk3, Wpk3, Uk2, Vk2, W2_mod, L_xi)
        U6_15, V6_15, W6_15 = compose_binomial_tower(Ut3, Vt3, Wpt3, Uk2, Vk2, W2_mod, L_xi)

        suite[sp6.name] = [
            _make_schedule_from_q(f"{curve_key}_Fp6_Tower18", sp6, "Karatsuba-Baseline", U6_18, V6_18, W6_18, "Standard Karatsuba-3 x Karatsuba-2 tower (18 Fp muls)"),
            _make_schedule_from_q(f"{curve_key}_Fp6_Toom15", sp6, "Tower-Hybrid", U6_15, V6_15, W6_15, "Toom-3 over Fp2 x Karatsuba-2 (15 Fp muls)"),
            _make_simple_poly_schedule(f"{curve_key}_Fp6_CRT13", sp6, "Cyclotomic-CRT", U6_13, V6_13, Wp6_13, "13-mul Cyclotomic CRT {-3..2,inf,Phi_4,Phi_3}"),
            _make_simple_poly_schedule(f"{curve_key}_Fp6_CRT12", sp6, "Cyclotomic-CRT", U6_12, V6_12, Wp6_12, "12-mul Cyclotomic CRT {-4..3,inf,Phi_4}"),
            _make_simple_poly_schedule(f"{curve_key}_Fp6_Rank11", sp6, "Vandermonde", U6_11, V6_11, Wp6_11, "Alder-Strassen optimal 11-mul Fp6 on {-5..4,inf}"),
        ]

        # L_v on Fp6: v*(B0 + B1*v + B2*v^2) = xi*B2 + B0*v + B1*v^2
        L_v = [
            [0, 0, 0, 0, xi0, -1],
            [0, 0, 0, 0, 1, xi0],
            [1, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [0, 0, 1, 0, 0, 0],
            [0, 0, 0, 1, 0, 0],
        ]
        U12_54, V12_54, W12_54 = compose_binomial_tower(Uk2, Vk2, Wk2, U6_18, V6_18, W6_18, L_v)
        U12_45, V12_45, W12_45 = compose_binomial_tower(Uk2, Vk2, Wk2, U6_15, V6_15, W6_15, L_v)

        # 33-mul Toom-6 over Fp2 x Karatsuba-2 mapped to gnark E12 [C0, C1] layout:
        U12_33_w6, V12_33_w6, W12_33_w6 = compose_binomial_tower(U6_11, V6_11, Wp6_11, Uk2, Vk2, W2_mod, L_xi)
        U12_33, V12_33, W12_33 = _apply_basis_transform(
            U12_33_w6, V12_33_w6, W12_33_w6, w6_from_gnark, gnark_from_w6
        )

        suite[sp12.name] = [
            _make_schedule_from_q(f"{curve_key}_Fp12_Tower54", sp12, "Karatsuba-Baseline", U12_54, V12_54, W12_54, "Standard 3x6x3 Karatsuba tower (54 Fp muls)"),
            _make_schedule_from_q(f"{curve_key}_Fp12_Toom45", sp12, "Tower-Hybrid", U12_45, V12_45, W12_45, "Karatsuba-2 x Toom-3 x Karatsuba-2 tower (45 Fp muls)"),
            _make_schedule_from_q(f"{curve_key}_Fp12_Tower33", sp12, "Tower-Hybrid", U12_33, V12_33, W12_33, "Toom-6 over Fp2 x Karatsuba-2 hybrid (33 Fp muls, 18.5b D)"),
            _make_simple_poly_schedule(f"{curve_key}_Fp12_CRT30", sp12, "Cyclotomic-CRT", U12_30, V12_30, Wp12_30, "30-mul Cyclotomic/Quadratic CRT (9 linear + 7 quadratic, 0 pre-reductions)"),
            _make_simple_poly_schedule(f"{curve_key}_Fp12_CRT27", sp12, "Cyclotomic-CRT", U12_27, V12_27, Wp12_27, "27-mul Cyclotomic CRT (15 linear + 4 quadratic)"),
            _make_simple_poly_schedule(f"{curve_key}_Fp12_Rank23", sp12, "Vandermonde", U12_23, V12_23, Wp12_23, "Alder-Strassen optimal 23-mul Vandermonde {-11..10,inf} (native R1CS optimal; limb-carry heavy)"),
        ]

    # 8. Native 2-Chain Pairing Tower: BLS12-377 (u^2 = -5, v^3 = u, w^2 = v; pure coordinate permutations)
    sp377_2 = EXTENSION_SPECS["BLS12_377_Fp2"]
    sp377_6 = EXTENSION_SPECS["BLS12_377_Fp6"]
    sp377_12 = EXTENSION_SPECS["BLS12_377_Fp12"]

    suite[sp377_2.name] = [
        _make_simple_poly_schedule("BLS12_377_Fp2_Schoolbook4", sp377_2, "Schoolbook-Baseline", Us2, Vs2, Ws2, "Schoolbook Fp2 over u^2 + 5 = 0 (4 Fp muls)"),
        _make_simple_poly_schedule("BLS12_377_Fp2_Rank3", sp377_2, "Vandermonde", Uk2, Vk2, Wk2, "Alder-Strassen optimal 3-mul Karatsuba Fp2 over u^2 + 5 = 0"),
    ]

    W2_377_mod = _reduce_poly_W_mod_f(Wk2, [5, 0, 1])
    L_u_377 = [[0, -5], [1, 0]]  # u * (a0 + a1*u) = -5*a1 + a0*u
    U6_377_18, V6_377_18, W6_377_18 = compose_binomial_tower(Uk3, Vk3, Wpk3, Uk2, Vk2, W2_377_mod, L_u_377)
    U6_377_15, V6_377_15, W6_377_15 = compose_binomial_tower(Ut3, Vt3, Wpt3, Uk2, Vk2, W2_377_mod, L_u_377)

    suite[sp377_6.name] = [
        _make_schedule_from_q("BLS12_377_Fp6_Tower18", sp377_6, "Karatsuba-Baseline", U6_377_18, V6_377_18, W6_377_18, "Standard Karatsuba-3 x Karatsuba-2 tower (18 Fp muls)"),
        _make_schedule_from_q("BLS12_377_Fp6_Toom15", sp377_6, "Tower-Hybrid", U6_377_15, V6_377_15, W6_377_15, "gnark R1CS baseline Toom-3 over Fp2 x Karatsuba-2 (15 Fp muls)"),
        _make_simple_poly_schedule("BLS12_377_Fp6_CRT13", sp377_6, "Cyclotomic-CRT", U6_13, V6_13, Wp6_13, "13-mul Cyclotomic CRT on Y^6 + 5 = 0 mapped to tower coordinates"),
        _make_simple_poly_schedule("BLS12_377_Fp6_CRT12", sp377_6, "Cyclotomic-CRT", U6_12, V6_12, Wp6_12, "12-mul Cyclotomic CRT on Y^6 + 5 = 0 mapped to tower coordinates"),
        _make_simple_poly_schedule("BLS12_377_Fp6_Rank11", sp377_6, "Vandermonde", U6_11, V6_11, Wp6_11, "Winograd / Alder-Strassen optimal 11-mul Fp6 on Y^6 + 5 at {-5..4, inf} via pure tower permutation"),
    ]

    L_v_377 = [
        [0, 0, 0, 0, 0, -5],
        [0, 0, 0, 0, 1, 0],
        [1, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0],
    ]
    U12_377_54, V12_377_54, W12_377_54 = compose_binomial_tower(Uk2, Vk2, Wk2, U6_377_18, V6_377_18, W6_377_18, L_v_377)
    U12_377_45, V12_377_45, W12_377_45 = compose_binomial_tower(Uk2, Vk2, Wk2, U6_377_15, V6_377_15, W6_377_15, L_v_377)

    U12_377_33_w6, V12_377_33_w6, W12_377_33_w6 = compose_binomial_tower(U6_11, V6_11, Wp6_11, Uk2, Vk2, W2_377_mod, L_u_377)
    U12_377_33, V12_377_33, W12_377_33 = _apply_basis_transform(
        U12_377_33_w6, V12_377_33_w6, W12_377_33_w6, w6_from_gnark, gnark_from_w6
    )

    suite[sp377_12.name] = [
        _make_schedule_from_q("BLS12_377_Fp12_Tower54", sp377_12, "Karatsuba-Baseline", U12_377_54, V12_377_54, W12_377_54, "Standard 3x6x3 Karatsuba tower (54 Fp muls)"),
        _make_schedule_from_q("BLS12_377_Fp12_Toom45", sp377_12, "Tower-Hybrid", U12_377_45, V12_377_45, W12_377_45, "gnark R1CS baseline Karatsuba-2 x Toom-3 x Karatsuba-2 tower (45 Fp muls)"),
        _make_schedule_from_q("BLS12_377_Fp12_Tower33", sp377_12, "Tower-Hybrid", U12_377_33, V12_377_33, W12_377_33, "Toom-6 over Fp2 x Karatsuba-2 hybrid (33 Fp muls, 18.5b D)"),
        _make_simple_poly_schedule("BLS12_377_Fp12_CRT30", sp377_12, "Cyclotomic-CRT", U12_30, V12_30, Wp12_30, "30-mul Cyclotomic/Quadratic CRT on W^12 + 5 = 0 (9 linear + 7 quadratic, 0 pre-reductions)"),
        _make_simple_poly_schedule("BLS12_377_Fp12_CRT27", sp377_12, "Cyclotomic-CRT", U12_27, V12_27, Wp12_27, "27-mul Cyclotomic CRT on W^12 + 5 = 0 (15 linear + 4 quadratic)"),
        _make_simple_poly_schedule("BLS12_377_Fp12_Rank23", sp377_12, "Vandermonde", U12_23, V12_23, Wp12_23, "Winograd / Alder-Strassen optimal 23-mul Vandermonde on W^12 + 5 at {-11..10, inf} via pure tower permutation"),
    ]

    return suite


SCHEDULE_SUITE: Dict[str, List[BilinearSchedule]] = build_all_schedules()

BLS12_377_Fp2_Rank3: BilinearSchedule = SCHEDULE_SUITE["BLS12_377_Fp2"][-1]
BLS12_377_Fp6_Rank11: BilinearSchedule = SCHEDULE_SUITE["BLS12_377_Fp6"][-1]
BLS12_377_Fp12_Rank23: BilinearSchedule = SCHEDULE_SUITE["BLS12_377_Fp12"][-1]


def get_schedules_for_target(target_name: str) -> List[BilinearSchedule]:
    if target_name not in SCHEDULE_SUITE:
        raise KeyError(f"Unknown target '{target_name}'. Available: {sorted(SCHEDULE_SUITE)}")
    return list(SCHEDULE_SUITE[target_name])


def get_optimal_native_schedule(target_name: str) -> BilinearSchedule:
    schedules = get_schedules_for_target(target_name)
    return min(schedules, key=lambda s: (s.rank, s.max_uv_l1_product))


def compute_pareto_frontier(
    target_name: str,
) -> List[Tuple[BilinearSchedule, FullScheduleCost, bool]]:
    """Return all candidate schedules annotated with whether each is Pareto-efficient
    on (base_muls, max_uv_slack_bits, groth16_or_plonk_total).
    """
    candidates = get_schedules_for_target(target_name)
    evaluated = [(s, evaluate_full_cost(s)) for s in candidates]
    results: List[Tuple[BilinearSchedule, FullScheduleCost, bool]] = []

    for i, (si, ci) in enumerate(evaluated):
        vec_i = (
            ci.rank,
            ci.max_uv_slack_bits,
            ci.emulated.groth16_r1cs_total if ci.emulated is not None else ci.native.plonk_width4_total_gates,
        )
        dominated = False
        for j, (_, cj) in enumerate(evaluated):
            if i == j:
                continue
            vec_j = (
                cj.rank,
                cj.max_uv_slack_bits,
                cj.emulated.groth16_r1cs_total if cj.emulated is not None else cj.native.plonk_width4_total_gates,
            )
            if all(vj <= vi for vj, vi in zip(vec_j, vec_i)) and any(
                vj < vi for vj, vi in zip(vec_j, vec_i)
            ):
                dominated = True
                break
        results.append((si, ci, not dominated))
    return results
