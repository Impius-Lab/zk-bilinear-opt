"""Adversarial Mutation Self-Test Suite: asserts every class of corruption turns RED."""

from __future__ import annotations

from dataclasses import replace
import unittest

from zk_bilinear.cost_models import (
    compute_emulated_limb_cost,
    verify_emulated_witness_bounds,
)
from zk_bilinear.fields import EXTENSION_SPECS, textbook_poly_mul_fixed
from zk_bilinear.pareto_search import get_optimal_native_schedule
from zk_bilinear.tensor_cert import verify_schedule_certificate


class TestAdversarialMutations(unittest.TestCase):
    def test_01_mutate_single_sign_in_U_and_V_caught_red(self) -> None:
        """Corrupt 1 sign in evaluation matrix U (and V) -> verifier MUST reject RED."""
        base = get_optimal_native_schedule("QM31")
        self.assertTrue(verify_schedule_certificate(base).passed)

        # Flip sign of first nonzero entry in U[0]
        u_list = [list(row) for row in base.U]
        for j, val in enumerate(u_list[0]):
            if val != 0:
                u_list[0][j] = -val
                break
        mut_u = replace(base, U=tuple(tuple(r) for r in u_list))
        rep_u = verify_schedule_certificate(mut_u)
        self.assertFalse(rep_u.passed)
        self.assertFalse(rep_u.basis_identity_ok)

        # Flip sign of first nonzero entry in V[1]
        v_list = [list(row) for row in base.V]
        for j, val in enumerate(v_list[1]):
            if val != 0:
                v_list[1][j] = -val
                break
        mut_v = replace(base, V=tuple(tuple(r) for r in v_list))
        rep_v = verify_schedule_certificate(mut_v)
        self.assertFalse(rep_v.passed)
        self.assertFalse(rep_v.basis_identity_ok)

    def test_02_mutate_single_interpolation_coefficient_caught_red(self) -> None:
        """Corrupt 1 interpolation coefficient in W_z -> verifier MUST reject RED."""
        for tname in ("QM31", "BabyBear5", "KoalaBear8", "BN254_Fp6", "BLS12_381_Fp12"):
            base = get_optimal_native_schedule(tname)
            wz_list = [list(row) for row in base.W_z]
            wz_list[0][0] += 1
            mut_w = replace(base, W_z=tuple(tuple(r) for r in wz_list))
            rep = verify_schedule_certificate(mut_w)
            self.assertFalse(rep.passed, f"Mutation in W_z for {tname} was not caught!")
            self.assertFalse(rep.basis_identity_ok)

    def test_03_mutate_reduction_modulus_caught_red(self) -> None:
        """Corrupt 1 reduction modulus coefficient -> caught RED by irreducibility or basis check."""
        # Case A: Reducible polynomial X^4 - 1 over BabyBear
        spec_bb4 = EXTENSION_SPECS["BabyBear4"]
        sched_bb4 = get_optimal_native_schedule("BabyBear4")
        reducible_poly = (-1, 0, 0, 0, 1)
        mut_spec_red = replace(
            spec_bb4,
            simple_poly=reducible_poly,
            reference_mul=lambda a, b: textbook_poly_mul_fixed(a, b, reducible_poly, spec_bb4.prime),
        )
        rep_red = verify_schedule_certificate(sched_bb4, mut_spec_red)
        self.assertFalse(rep_red.passed)
        self.assertFalse(rep_red.irreducibility_ok)

        # Case B: Perturb QM31 simple polynomial u^4 - 4u^2 + 5 -> u^4 - 4u^2 + 6
        spec_qm = EXTENSION_SPECS["QM31"]
        sched_qm = get_optimal_native_schedule("QM31")
        mut_spec_qm = replace(spec_qm, simple_poly=(6, 0, -4, 0, 1))
        rep_qm = verify_schedule_certificate(sched_qm, mut_spec_qm)
        self.assertFalse(rep_qm.passed)

    def test_04_mutate_limb_slack_and_accumulator_bounds_caught_red(self) -> None:
        """Corrupt declared limb-slack bound, native u64 accumulator bound, and emulated
        quotient/carry bit-width -> verifier MUST catch EVERY bound violation RED!
        """
        # A. Corrupt declared_max_limb_slack_bits by -1 bit
        sched_bn6 = get_optimal_native_schedule("BN254_Fp6")
        mut_slack = replace(
            sched_bn6, declared_max_limb_slack_bits=sched_bn6.actual_limb_slack_bits - 1
        )
        rep_slack = verify_schedule_certificate(mut_slack)
        self.assertFalse(rep_slack.passed)
        self.assertFalse(rep_slack.limb_slack_bound_ok)

        # B. Corrupt native u64 accumulator bit bound below actual 62-bit peak
        sched_qm = get_optimal_native_schedule("QM31")
        mut_acc = replace(sched_qm, declared_acc_bound_bits=60)
        rep_acc = verify_schedule_certificate(mut_acc)
        self.assertFalse(rep_acc.passed)
        self.assertFalse(rep_acc.accumulator_bound_ok)

        # C. Corrupt emulated non-native quotient & carry range-check bit-widths below realized values
        spec_bn6 = EXTENSION_SPECS["BN254_Fp6"]
        p = spec_bn6.prime
        true_cost = compute_emulated_limb_cost(sched_bn6, 4, 64, p)
        adv_a = [p - 1 if sched_bn6.U[0][i] > 0 else (p // 3 + i + 1) for i in range(6)]
        adv_b = [p - 1 if sched_bn6.V[0][j] > 0 else (p // 5 + j + 1) for j in range(6)]
        obs = verify_emulated_witness_bounds(sched_bn6, adv_a, adv_b, true_cost, p)
        self.assertGreater(obs["obs_max_mul_q_bits"], 250)
        self.assertGreater(obs["obs_max_out_c_bits"], 10)

        # Under-allocate max_mul_quotient_bits below observed quotient bits -> MUST raise OverflowError!
        corrupted_q_cost = replace(true_cost, max_mul_quotient_bits=obs["obs_max_mul_q_bits"] - 1)
        with self.assertRaises(OverflowError):
            verify_emulated_witness_bounds(sched_bn6, adv_a, adv_b, corrupted_q_cost, p)

        # Under-allocate max_out_carry_bits below observed output carry bits -> MUST raise OverflowError!
        corrupted_c_cost = replace(true_cost, max_out_carry_bits=obs["obs_max_out_carry_bits" if "obs_max_out_carry_bits" in obs else "obs_max_out_c_bits"] - 1)
        with self.assertRaises(OverflowError):
            verify_emulated_witness_bounds(sched_bn6, adv_a, adv_b, corrupted_c_cost, p)

        # D. Signed i128 overflow (>= 2^127 while < 2^128) on 128-bit Goldilocks target -> MUST reject RED!
        sched_g2 = get_optimal_native_schedule("Goldilocks2")
        huge_u = ((1 << 63, -(1 << 63)), sched_g2.U[1], sched_g2.U[2])
        mut_i128 = replace(
            sched_g2,
            U=huge_u,
            declared_max_limb_slack_bits=128,
        )
        rep_i128 = verify_schedule_certificate(mut_i128)
        self.assertFalse(rep_i128.passed)
        self.assertFalse(rep_i128.accumulator_bound_ok)


if __name__ == "__main__":
    unittest.main()
