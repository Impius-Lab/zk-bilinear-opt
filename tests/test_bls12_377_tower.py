"""Dedicated zero-shared-code tower & Z-certification tests for BLS12-377 (gnark fields_bls12377)."""

from __future__ import annotations

from pathlib import Path
import random
import re
from typing import List, Sequence, Tuple
import unittest

from zk_bilinear.cli import audit_all_suite
from zk_bilinear.fields import (
    BLS12_377_FP2,
    BLS12_377_FP6,
    BLS12_377_FP12,
    FIELD_CATALOG,
    P_BLS12_377,
    det_int_exact,
    is_irreducible_rabin,
    is_prime,
)
from zk_bilinear.pareto_search import (
    BLS12_377_Fp2_Rank3,
    BLS12_377_Fp6_Rank11,
    BLS12_377_Fp12_Rank23,
    SCHEDULE_SUITE,
    build_vandermonde_poly_alg,
)
from zk_bilinear.tensor_cert import (
    certify_over_Z,
    evaluate_schedule_fp,
    verify_schedule_certificate,
)


# ---------------------------------------------------------------------------
# Independent Step-by-Step Tower Arithmetic (Zero Shared Code with zk_bilinear)
# Fp -> Fp2 (u^2 = -5) -> Fp6 (v^3 = u) -> Fp12 (w^2 = v)
# ---------------------------------------------------------------------------

def _indep_e2_mul_z(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
    # (a0 + a1*u)*(b0 + b1*u) with u^2 = -5
    return (a[0] * b[0] - 5 * a[1] * b[1], a[0] * b[1] + a[1] * b[0])


def _indep_e2_mul_u_z(x: Tuple[int, int]) -> Tuple[int, int]:
    # u * (x0 + x1*u) = -5*x1 + x0*u
    return (-5 * x[1], x[0])


def _indep_e6_mul_z(a: Sequence[int], b: Sequence[int]) -> List[int]:
    # E6 = B0 + B1*v + B2*v^2 with B_i in E2 and v^3 = u
    b_a = [(a[0], a[1]), (a[2], a[3]), (a[4], a[5])]
    b_b = [(b[0], b[1]), (b[2], b[3]), (b[4], b[5])]
    acc = [[0, 0] for _ in range(5)]
    for i in range(3):
        for j in range(3):
            p0, p1 = _indep_e2_mul_z(b_a[i], b_b[j])
            acc[i + j][0] += p0
            acc[i + j][1] += p1
    # Reduce v^3 -> u and v^4 -> u*v
    s3 = _indep_e2_mul_u_z((acc[3][0], acc[3][1]))
    s4 = _indep_e2_mul_u_z((acc[4][0], acc[4][1]))
    acc[0][0] += s3[0]
    acc[0][1] += s3[1]
    acc[1][0] += s4[0]
    acc[1][1] += s4[1]
    return [acc[0][0], acc[0][1], acc[1][0], acc[1][1], acc[2][0], acc[2][1]]


def _indep_e6_mul_v_z(x: Sequence[int]) -> List[int]:
    # v * (B0 + B1*v + B2*v^2) = u*B2 + B0*v + B1*v^2
    ub2 = _indep_e2_mul_u_z((x[4], x[5]))
    return [ub2[0], ub2[1], x[0], x[1], x[2], x[3]]


def _indep_e12_mul_z(a: Sequence[int], b: Sequence[int]) -> List[int]:
    # E12 = C0 + C1*w with C_i in E6 and w^2 = v
    c0, c1 = a[:6], a[6:]
    d0, d1 = b[:6], b[6:]
    c0d0 = _indep_e6_mul_z(c0, d0)
    c1d1 = _indep_e6_mul_z(c1, d1)
    vc1d1 = _indep_e6_mul_v_z(c1d1)
    c0d1 = _indep_e6_mul_z(c0, d1)
    c1d0 = _indep_e6_mul_z(c1, d0)
    return [c0d0[i] + vc1d1[i] for i in range(6)] + [c0d1[i] + c1d0[i] for i in range(6)]


class TestBLS12377NativeTower(unittest.TestCase):
    def test_01_bls12_377_prime_seed_and_gnark_frobenius_pins(self) -> None:
        p_hex = 0x01AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000001
        self.assertEqual(P_BLS12_377, p_hex)
        self.assertEqual(P_BLS12_377.bit_length(), 377)
        self.assertTrue(is_prime(P_BLS12_377))

        # Verify BLS12 prime polynomial at seed x0 = 0x8508c00000000001
        x0 = 0x8508C00000000001
        self.assertEqual(((x0 - 1) ** 2 * (x0 ** 4 - x0 ** 2 + 1)) // 3 + x0, P_BLS12_377)

        # Cross-check Frobenius constants against gnark std/algebra/native/fields_bls12377/e12.go
        frobv = pow(P_BLS12_377 - 5, (P_BLS12_377 - 1) // 6, P_BLS12_377)
        frobw = pow(P_BLS12_377 - 5, (P_BLS12_377 - 1) // 12, P_BLS12_377)
        self.assertEqual(
            frobv,
            80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946,
        )
        self.assertEqual(
            frobw,
            92949345220277864758624960506473182677953048909283248980960104381795901929519566951595905490535835115111760994353,
        )

        # Catalog & irreducibility checks
        self.assertIs(FIELD_CATALOG["BLS12_377_Fp2"], BLS12_377_FP2)
        self.assertIs(FIELD_CATALOG["BLS12_377_Fp6"], BLS12_377_FP6)
        self.assertIs(FIELD_CATALOG["BLS12_377_Fp12"], BLS12_377_FP12)
        self.assertEqual(BLS12_377_FP2.emulated_limbs, (6, 64))
        self.assertEqual(BLS12_377_FP6.emulated_limbs, (6, 64))
        self.assertEqual(BLS12_377_FP12.emulated_limbs, (6, 64))
        self.assertTrue(is_irreducible_rabin((5, 0, 1), P_BLS12_377))
        self.assertTrue(is_irreducible_rabin((5, 0, 0, 0, 0, 0, 1), P_BLS12_377))
        self.assertTrue(is_irreducible_rabin((5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), P_BLS12_377))

    def test_02_pure_permutation_unimodular_basis_zero_additions(self) -> None:
        # Fp6: towerToMonomial6 = [t[0], t[2], t[4], t[1], t[3], t[5]], det = -1
        perm6 = [0, 2, 4, 1, 3, 5]
        t6 = list(range(6))
        mapped6 = [sum(BLS12_377_FP6.to_simple_basis[i][j] * t6[j] for j in range(6)) for i in range(6)]
        self.assertEqual(mapped6, perm6)
        self.assertEqual(det_int_exact(BLS12_377_FP6.to_simple_basis), -1)
        self.assertEqual(det_int_exact(BLS12_377_FP6.from_simple_basis), -1)
        for row in BLS12_377_FP6.to_simple_basis:
            self.assertEqual(sorted(row), [0, 0, 0, 0, 0, 1])

        # Fp12: towerToMonomial12 = [t[0], t[6], t[2], t[8], t[4], t[10], t[1], t[7], t[3], t[9], t[5], t[11]], det = -1
        perm12 = [0, 6, 2, 8, 4, 10, 1, 7, 3, 9, 5, 11]
        t12 = list(range(12))
        mapped12 = [sum(BLS12_377_FP12.to_simple_basis[i][j] * t12[j] for j in range(12)) for i in range(12)]
        self.assertEqual(mapped12, perm12)
        self.assertEqual(det_int_exact(BLS12_377_FP12.to_simple_basis), -1)
        self.assertEqual(det_int_exact(BLS12_377_FP12.from_simple_basis), -1)
        for row in BLS12_377_FP12.to_simple_basis:
            self.assertEqual(sorted(row), [0] * 11 + [1])

        # Pure permutation preserves exact U/V sparsity and L1 norm vs monomial Vandermonde!
        U6_mono, _, _ = build_vandermonde_poly_alg(6, list(range(-5, 5)), True)
        U12_mono, _, _ = build_vandermonde_poly_alg(12, list(range(-11, 11)), True)
        self.assertEqual(
            [sum(abs(x) for x in r) for r in BLS12_377_Fp6_Rank11.U],
            [sum(abs(x) for x in r) for r in U6_mono],
        )
        self.assertEqual(
            [sum(abs(x) for x in r) for r in BLS12_377_Fp12_Rank23.U],
            [sum(abs(x) for x in r) for r in U12_mono],
        )

    def test_03_certify_over_Z_all_4_36_144_basis_pairs(self) -> None:
        for sched, expected_rank, expected_pairs, indep_z_fn in [
            (BLS12_377_Fp2_Rank3, 3, 4, lambda a, b: list(_indep_e2_mul_z((a[0], a[1]), (b[0], b[1])))),
            (BLS12_377_Fp6_Rank11, 11, 36, _indep_e6_mul_z),
            (BLS12_377_Fp12_Rank23, 23, 144, _indep_e12_mul_z),
        ]:
            self.assertEqual(sched.rank, expected_rank)
            z_rep = certify_over_Z(sched)
            self.assertTrue(z_rep.passed, f"{sched.name} failed over Z: {z_rep.errors}")
            self.assertEqual(z_rep.basis_pairs_checked, expected_pairs)
            fp_rep = verify_schedule_certificate(sched)
            self.assertTrue(fp_rep.passed)
            self.assertTrue(fp_rep.is_alder_strassen_optimal)

            # Zero-shared-code exact Z identity check against independent tower multiplication:
            d = sched.degree
            r = sched.rank
            for i in range(d):
                ei = [1 if k == i else 0 for k in range(d)]
                for j in range(d):
                    ej = [1 if k == j else 0 for k in range(d)]
                    want_z = indep_z_fn(ei, ej)
                    got_scaled = [
                        sum(sched.W_z[k][l] * sched.U[l][i] * sched.V[l][j] for l in range(r))
                        for k in range(d)
                    ]
                    self.assertEqual(got_scaled, [sched.D * c for c in want_z])

        # Also certify every auxiliary schedule in BLS12_377_Fp2/6/12 over Z
        for tname in ("BLS12_377_Fp2", "BLS12_377_Fp6", "BLS12_377_Fp12"):
            for s in SCHEDULE_SUITE[tname]:
                self.assertTrue(certify_over_Z(s).passed)

    def test_04_step_by_step_tower_equivalence_and_random_fp_fuzz(self) -> None:
        rng = random.Random(20261122)
        p = P_BLS12_377

        for sched, indep_z_fn, trials in [
            (BLS12_377_Fp2_Rank3, lambda a, b: list(_indep_e2_mul_z((a[0], a[1]), (b[0], b[1]))), 1_000),
            (BLS12_377_Fp6_Rank11, _indep_e6_mul_z, 1_000),
            (BLS12_377_Fp12_Rank23, _indep_e12_mul_z, 1_000),
        ]:
            d = sched.degree
            # Adversarial vectors: zero, all-(p-1), alternating
            edge_pairs = [
                ([0] * d, [p - 1] * d),
                ([p - 1] * d, [p - 1] * d),
                ([p - 1 if i % 2 == 0 else 0 for i in range(d)], [0 if i % 2 == 0 else p - 1 for i in range(d)]),
            ]
            for a, b in edge_pairs:
                got = evaluate_schedule_fp(sched, a, b, p)
                want = [c % p for c in indep_z_fn(a, b)]
                self.assertEqual(got, want)

            for _ in range(trials):
                a = [rng.randrange(p) for _ in range(d)]
                b = [rng.randrange(p) for _ in range(d)]
                got = evaluate_schedule_fp(sched, a, b, p)
                want = [c % p for c in indep_z_fn(a, b)]
                self.assertEqual(got, want)

    def test_05_go_u64_bilinear_mul_counts_and_cli_audit(self) -> None:
        root = Path(__file__).resolve().parent.parent
        u64_src = (root / "go_gadgets" / "bls12377_u64_generated.go").read_text(encoding="utf-8")
        for fn_name, expected_muls in [
            ("MulBLS12377Fp2Rank3U64", 3),
            ("MulBLS12377Fp6Rank11U64", 11),
            ("MulBLS12377Fp12Rank23U64", 23),
        ]:
            pattern = rf"func {fn_name}\(.*?\n\}}"
            m = re.search(pattern, u64_src, flags=re.DOTALL)
            self.assertIsNotNone(m, f"Missing {fn_name} in bls12377_u64_generated.go")
            assert m is not None
            body = m.group(0)
            self.assertEqual(body.count("fp377Mul("), expected_muls)

        self.assertEqual(audit_all_suite(), 0)


if __name__ == "__main__":
    unittest.main()
