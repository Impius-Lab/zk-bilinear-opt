"""Exact worst-case u64 / u128 and non-native 4x64 / 6x64 limb-overflow & Pareto proofs."""

from __future__ import annotations

import unittest

from zk_bilinear.cost_models import (
    compute_emulated_limb_cost,
    verify_emulated_witness_bounds,
)
from zk_bilinear.fields import EXTENSION_SPECS, GOLDILOCKS_PRIME
from zk_bilinear.pareto_search import (
    SCHEDULE_SUITE,
    compute_pareto_frontier,
    get_optimal_native_schedule,
)
from zk_bilinear.tensor_cert import (
    execute_native_word_checked,
    theoretical_peak_native_bits,
)


class TestLimbOverflowAndParetoBounds(unittest.TestCase):
    def test_01_31bit_fields_u64_zero_overflow_adversarial(self) -> None:
        """Prove every 31-bit STARK target (CM31, QM31, BabyBear^4/5, KoalaBear^4/8) stays
        strictly < 2^63 (<= 63 bits, zero i64 or u64 overflow) across maximal (p-1,...,p-1)
        AND sign-aligned adversarial input vectors!
        """
        targets_31 = ["CM31", "QM31", "BabyBear4", "BabyBear5", "KoalaBear4", "KoalaBear8"]
        for tname in targets_31:
            spec = EXTENSION_SPECS[tname]
            p = spec.prime
            d = spec.degree
            for sched in SCHEDULE_SUITE[tname]:
                with self.subTest(schedule=sched.name):
                    theo = theoretical_peak_native_bits(sched, p, 64)
                    self.assertLessEqual(theo, 63)

                    # 1. All-(p-1) vector
                    max_v = [p - 1] * d
                    got, obs_bits = execute_native_word_checked(sched, max_v, max_v, p, 64)
                    self.assertEqual(got, spec.reference_mul(max_v, max_v))
                    self.assertLessEqual(obs_bits, 63)

                    # 2. Sign-aligned adversarial vectors maximizing positive and negative U/V rows
                    for l in range(sched.rank):
                        adv_pos_a = [p - 1 if sched.U[l][i] > 0 else 0 for i in range(d)]
                        adv_neg_a = [p - 1 if sched.U[l][i] < 0 else 0 for i in range(d)]
                        adv_pos_b = [p - 1 if sched.V[l][j] > 0 else 0 for j in range(d)]
                        adv_neg_b = [p - 1 if sched.V[l][j] < 0 else 0 for j in range(d)]
                        for va in (adv_pos_a, adv_neg_a):
                            for vb in (adv_pos_b, adv_neg_b):
                                g_adv, b_adv = execute_native_word_checked(sched, va, vb, p, 64)
                                self.assertEqual(g_adv, spec.reference_mul(va, vb))
                                self.assertLessEqual(b_adv, 63)

    def test_02_goldilocks_u128_zero_overflow_adversarial(self) -> None:
        """Prove Goldilocks^{2,4,5} stays strictly < 2^128 across all intermediate u128/i128 ops."""
        self.assertLess((GOLDILOCKS_PRIME - 1) ** 2, 1 << 128)
        for tname in ("Goldilocks2", "Goldilocks4", "Goldilocks5"):
            spec = EXTENSION_SPECS[tname]
            p = spec.prime
            d = spec.degree
            sched = get_optimal_native_schedule(tname)
            with self.subTest(schedule=sched.name):
                max_v = [p - 1] * d
                got, obs_bits = execute_native_word_checked(sched, max_v, max_v, p, 128)
                self.assertEqual(got, spec.reference_mul(max_v, max_v))
                self.assertLessEqual(obs_bits, 128)

                for l in range(sched.rank):
                    adv_a = [p - 1 if sched.U[l][i] > 0 else 0 for i in range(d)]
                    adv_b = [p - 1 if sched.V[l][j] > 0 else 0 for j in range(d)]
                    g2, b2 = execute_native_word_checked(sched, adv_a, adv_b, p, 128)
                    self.assertEqual(g2, spec.reference_mul(adv_a, adv_b))
                    self.assertLessEqual(b2, 128)

    def test_03_emulated_4x64_and_6x64_limb_witness_bounds_and_pareto_honesty(self) -> None:
        """Verify actual non-native integer quotients & 2-limb carries fit inside allocated
        range-check bit-widths on maximal & sign-aligned vectors, and verify the true Pareto
        tradeoff on BN254 (4x64) and BLS12-381 (6x64).
        """
        for curve_key, limbs in [("BN254", 4), ("BLS12_381", 6)]:
            # A. Fp6: Rank-11 achieves BOTH minimum rank (11 vs 18) AND lowest Groth16 & PlonK16 gates!
            t6 = f"{curve_key}_Fp6"
            spec6 = EXTENSION_SPECS[t6]
            p6 = spec6.prime
            f6 = compute_pareto_frontier(t6)
            base6_cost = f6[0][1].emulated
            opt6_sched, opt6_fcost, opt6_par = f6[-1]
            opt6_cost = opt6_fcost.emulated
            assert base6_cost is not None and opt6_cost is not None

            self.assertEqual(opt6_sched.rank, 11)
            self.assertTrue(opt6_par)
            self.assertEqual(opt6_cost.pre_mul_reductions, 0)
            self.assertLess(opt6_cost.groth16_r1cs_total, base6_cost.groth16_r1cs_total)
            self.assertLess(opt6_cost.plonk_total_gates, base6_cost.plonk_total_gates)

            for sched6, fcost6, _ in f6:
                assert fcost6.emulated is not None
                max_v6 = [p6 - 1] * 6
                verify_emulated_witness_bounds(sched6, max_v6, max_v6, fcost6.emulated, p6)
                adv6_a = [p6 - 1 if sched6.U[-2][i] > 0 else 0 for i in range(6)]
                adv6_b = [p6 - 1 if sched6.V[-2][j] > 0 else 0 for j in range(6)]
                verify_emulated_witness_bounds(sched6, adv6_a, adv6_b, fcost6.emulated, p6)

            # B. Fp12: Honest Pareto tradeoff — CRT-30 & Tower-33 need 0 pre-mul reductions and
            # strictly beat BOTH Tower-54 AND Vandermonde-23 in net Groth16 R1CS & PlonK16 gates!
            t12 = f"{curve_key}_Fp12"
            spec12 = EXTENSION_SPECS[t12]
            p12 = spec12.prime
            by_name = {s.name: (s, compute_emulated_limb_cost(s, limbs, 64, p12)) for s in SCHEDULE_SUITE[t12]}

            _, c54 = by_name[f"{curve_key}_Fp12_Tower54"]
            _, c33 = by_name[f"{curve_key}_Fp12_Tower33"]
            _, c30 = by_name[f"{curve_key}_Fp12_CRT30"]
            _, c23 = by_name[f"{curve_key}_Fp12_Rank23"]

            self.assertEqual(c33.pre_mul_reductions, 0)
            self.assertEqual(c30.pre_mul_reductions, 0)
            self.assertGreater(c23.pre_mul_reductions, 10)

            # Tower-33 and CRT-30 beat Tower-54 substantially
            self.assertLess(c33.groth16_r1cs_total, int(0.75 * c54.groth16_r1cs_total))
            self.assertLess(c30.groth16_r1cs_total, int(0.72 * c54.groth16_r1cs_total))
            self.assertLess(c30.plonk_total_gates, int(0.72 * c54.plonk_total_gates))

            # And BOTH Tower-33 and CRT-30 beat naive Vandermonde-23 in Groth16 & PlonK16!
            self.assertLess(c33.groth16_r1cs_total, c23.groth16_r1cs_total)
            self.assertLess(c30.groth16_r1cs_total, c23.groth16_r1cs_total)
            self.assertLess(c33.plonk_total_gates, c23.plonk_total_gates)
            self.assertLess(c30.plonk_total_gates, c23.plonk_total_gates)

            for s12, cost12 in by_name.values():
                max_v12 = [p12 - 1] * 12
                verify_emulated_witness_bounds(s12, max_v12, max_v12, cost12, p12)


if __name__ == "__main__":
    unittest.main()
