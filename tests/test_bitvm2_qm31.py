"""Comprehensive Verification & Adversarial Mutation Suite for BitVM2 `QM31` Tapscript."""

from __future__ import annotations

from dataclasses import replace
import random
import unittest

from zk_bilinear.bitvm2_qm31 import (
    ALLOWED_SMALL_SCALES,
    CSCRIPTNUM_MAX,
    I64_MAX,
    M31_P,
    P_LIMBS_BASE256,
    TapscriptM31Machine,
    TapscriptVerificationError,
    U64_MAX,
    build_honest_m31_mul_witness,
    compute_exact_qm31_u64_bounds,
    qm31_mul_exact_z,
    simulate_qm31_karatsuba9,
    simulate_qm31_rank7,
    simulate_qm31_schoolbook16,
    summarize_bitvm2_schedule_comparison,
    tapscript_u8_mul_shift_add,
    verify_qm31_unimodular_isomorphism_over_z,
    verify_schedule_matrix_tapscript,
)
from zk_bilinear.fields import qm31_tower_mul_ref
from zk_bilinear.pareto_search import SCHEDULE_SUITE, get_optimal_native_schedule
from zk_bilinear.tensor_cert import certify_over_Z


class TestBitVM2QM31Tapscript(unittest.TestCase):
    def test_01_all_16_basis_pairs_over_Z_and_F_m31(self) -> None:
        """Verify all 16 canonical basis pairs `(e_a, e_b)` over `Z` and `F_{2^31-1}`."""
        self.assertTrue(verify_qm31_unimodular_isomorphism_over_z())

        sched_rank7 = get_optimal_native_schedule("QM31")
        sched_k9 = [s for s in SCHEDULE_SUITE["QM31"] if s.rank == 9][0]
        self.assertTrue(certify_over_Z(sched_rank7).passed)
        self.assertTrue(certify_over_Z(sched_k9).passed)

        basis = [[1 if k == idx else 0 for k in range(4)] for idx in range(4)]
        checked_pairs = 0

        for a_idx, ea in enumerate(basis):
            for b_idx, eb in enumerate(basis):
                with self.subTest(a_idx=a_idx, b_idx=b_idx):
                    # 1. Exact integer ring identity over Z (no mod P):
                    want_z = qm31_mul_exact_z(ea, eb)
                    for sched in (sched_rank7, sched_k9):
                        m_z = [
                            sum(sched.U[l][i] * ea[i] for i in range(4))
                            * sum(sched.V[l][j] * eb[j] for j in range(4))
                            for l in range(sched.rank)
                        ]
                        got_d_z = [
                            sum(sched.W_z[k][l] * m_z[l] for l in range(sched.rank))
                            for k in range(4)
                        ]
                        self.assertEqual(got_d_z, [sched.D * c for c in want_z])

                    # 2. Full BitVM2 Tapscript execution over F_{2^31 - 1}:
                    want_fp = tuple(qm31_tower_mul_ref(ea, eb))
                    t_sb = simulate_qm31_schoolbook16(ea, eb, record_witnesses=True)
                    t_k9 = simulate_qm31_karatsuba9(ea, eb, record_witnesses=True)
                    t_r7 = simulate_qm31_rank7(ea, eb, record_witnesses=True)
                    t_mat = verify_schedule_matrix_tapscript(sched_rank7, ea, eb, want_fp)

                    self.assertEqual(t_sb.output, want_fp)
                    self.assertEqual(t_k9.output, want_fp)
                    self.assertEqual(t_r7.output, want_fp)
                    self.assertEqual(t_mat.output, want_fp)
                    self.assertEqual(t_r7.bilinear_products, t_mat.bilinear_products)

                    self.assertEqual(t_sb.op_m31_mul_count, 16)
                    self.assertEqual(t_k9.op_m31_mul_count, 9)
                    self.assertEqual(t_r7.op_m31_mul_count, 7)
                    self.assertEqual(t_k9.op_m31_scale_small_count, 0)
                    self.assertEqual(
                        tuple(sorted(t_r7.scale_small_breakdown.keys())),
                        ALLOWED_SMALL_SCALES,
                    )
                    checked_pairs += 1

        self.assertEqual(checked_pairs, 16)

    def test_02_headline_op_and_witness_counts_pinned(self) -> None:
        """Pin exact `OP_M31_MUL` reductions (`-22.22%` vs Karatsuba-9, `-56.25%` vs Schoolbook-16)
        and verify `Rank-7` reduces both Bitcoin Script opcodes and witness stack elements.
        """
        # Exhaustive check of 8-bit shift-and-conditional-add Tapscript byte product (65,536 pairs):
        for a_b in range(256):
            for b_b in range(256):
                if tapscript_u8_mul_shift_add(a_b, b_b) != a_b * b_b:
                    self.fail(f"u8 shift-add mismatch at ({a_b}, {b_b})")

        summary = summarize_bitvm2_schedule_comparison()

        self.assertEqual(summary["Schoolbook-16"]["op_m31_mul"], 16)
        self.assertEqual(summary["Karatsuba-9"]["op_m31_mul"], 9)
        self.assertEqual(summary["Rank-7"]["op_m31_mul"], 7)

        self.assertEqual(summary["Karatsuba-9"]["op_m31_scale_small"], 0)
        self.assertEqual(summary["Rank-7"]["mul_reduction_vs_karatsuba9_pct"], 22.22)
        self.assertEqual(summary["Rank-7"]["mul_reduction_vs_schoolbook_pct"], 56.25)

        self.assertEqual(summary["Schoolbook-16"]["witness_elements"], 352)
        self.assertEqual(summary["Karatsuba-9"]["witness_elements"], 198)
        self.assertEqual(summary["Rank-7"]["witness_elements"], 158)
        self.assertEqual(summary["Schoolbook-16"]["bitcoin_script_opcodes"], 17880)
        self.assertEqual(summary["Karatsuba-9"]["bitcoin_script_opcodes"], 10224)
        self.assertEqual(summary["Rank-7"]["bitcoin_script_opcodes"], 9447)
        self.assertLess(
            summary["Rank-7"]["witness_elements"],
            summary["Karatsuba-9"]["witness_elements"],
        )
        self.assertLess(
            summary["Rank-7"]["bitcoin_script_opcodes"],
            summary["Karatsuba-9"]["bitcoin_script_opcodes"],
        )
        self.assertLess(
            summary["Karatsuba-9"]["bitcoin_script_opcodes"],
            summary["Schoolbook-16"]["bitcoin_script_opcodes"],
        )

    def test_03_exact_u64_i64_and_cscriptnum_non_overflow_bounds(self) -> None:
        """Verify exact hardware `u64`/`i64` accumulator bounds and 4-byte `CScriptNum` limits."""
        bounds = compute_exact_qm31_u64_bounds()
        p_m1 = M31_P - 1

        self.assertEqual(bounds.max_u_l1_norm, 32)
        self.assertEqual(bounds.max_v_l1_norm, 32)
        self.assertEqual(bounds.max_wz_l1_norm, 1210)
        self.assertEqual(bounds.max_eval_i64_abs, 32 * p_m1)
        self.assertLess(bounds.max_eval_i64_abs, 1 << 36)

        # Exact boundary check on (P - 1)^2 = (2^31 - 2)^2 vs 2^62:
        self.assertEqual(bounds.max_mul_u64, p_m1 * p_m1)
        self.assertEqual(bounds.max_mul_u64, 4_611_686_009_837_453_316)
        self.assertLess(bounds.max_mul_u64, 1 << 62)
        self.assertLess(bounds.max_mul_u64, I64_MAX)
        self.assertLess(bounds.max_inv_d_mul_u64, 1 << 60)
        self.assertEqual(bounds.max_mersenne_fold_sum, 2 * M31_P - 4)
        self.assertTrue(bounds.fits_signed_i64)
        self.assertTrue(bounds.fits_unsigned_u64)
        self.assertTrue(bounds.fits_single_mersenne_fold)

        # Empirical worst-case boundary vectors through all 3 Tapscript machines:
        boundary_vectors = [
            (0, 0, 0, 0),
            (1, 0, 0, 0),
            (p_m1, p_m1, p_m1, p_m1),
            (p_m1, p_m1, 0, 0),
            (0, 0, p_m1, p_m1),
            (p_m1, 0, p_m1, 0),
            (0, p_m1, 0, p_m1),
        ]
        for va in boundary_vectors:
            for vb in boundary_vectors:
                want = tuple(qm31_tower_mul_ref(va, vb))
                for sim in (
                    simulate_qm31_schoolbook16,
                    simulate_qm31_karatsuba9,
                    simulate_qm31_rank7,
                ):
                    tr = sim(va, vb)
                    self.assertEqual(tr.output, want)
                    self.assertLessEqual(tr.peak_stack_item_abs, CSCRIPTNUM_MAX)
                    self.assertLessEqual(tr.peak_u64_accumulator, U64_MAX)

    def test_04_10000_random_qm31_pairs_full_execution_trace_equivalence(self) -> None:
        """Verify 10,000 deterministic random `QM31` pairs across all 3 limb-checked schedules."""
        rng = random.Random(20261122)
        trials = 10_000
        for idx in range(trials):
            a = (
                rng.randrange(M31_P),
                rng.randrange(M31_P),
                rng.randrange(M31_P),
                rng.randrange(M31_P),
            )
            b = (
                rng.randrange(M31_P),
                rng.randrange(M31_P),
                rng.randrange(M31_P),
                rng.randrange(M31_P),
            )
            want = tuple(qm31_tower_mul_ref(a, b))
            t_sb = simulate_qm31_schoolbook16(a, b)
            t_k9 = simulate_qm31_karatsuba9(a, b)
            t_r7 = simulate_qm31_rank7(a, b)

            if not (t_sb.output == t_k9.output == t_r7.output == want):
                self.fail(
                    f"Mismatch at sample {idx}: sb={t_sb.output}, k9={t_k9.output}, "
                    f"r7={t_r7.output}, want={want}"
                )
            self.assertEqual(t_sb.op_m31_mul_count, 16)
            self.assertEqual(t_k9.op_m31_mul_count, 9)
            self.assertEqual(t_r7.op_m31_mul_count, 7)
            self.assertLessEqual(t_r7.peak_stack_item_abs, CSCRIPTNUM_MAX)
            self.assertLessEqual(t_r7.peak_u64_accumulator, U64_MAX)

    def test_05_adversarial_mutation_every_eval_and_interp_weight_caught_red(self) -> None:
        """Corrupt EVERY nonzero weight in `U`, `V`, and `W_z` -> Tapscript verifier MUST fail RED."""
        base = get_optimal_native_schedule("QM31")
        probe_a = (314159265, 271828182, 161803398, 141421356)
        probe_b = (2147483600, 123456789, 987654321, 2147483645)

        # Baseline passes cleanly:
        verify_schedule_matrix_tapscript(base, probe_a, probe_b)

        u_mutations = 0
        for r_idx in range(base.rank):
            for c_idx in range(4):
                orig = base.U[r_idx][c_idx]
                if orig == 0:
                    continue
                for mutated_val in (orig + 1, -orig):
                    u_mut = [list(row) for row in base.U]
                    u_mut[r_idx][c_idx] = mutated_val
                    sched_mut = replace(base, U=tuple(tuple(r) for r in u_mut))
                    with self.assertRaises(TapscriptVerificationError):
                        verify_schedule_matrix_tapscript(sched_mut, probe_a, probe_b)
                    u_mutations += 1

        v_mutations = 0
        for r_idx in range(base.rank):
            for c_idx in range(4):
                orig = base.V[r_idx][c_idx]
                if orig == 0:
                    continue
                for mutated_val in (orig + 1, -orig):
                    v_mut = [list(row) for row in base.V]
                    v_mut[r_idx][c_idx] = mutated_val
                    sched_mut = replace(base, V=tuple(tuple(r) for r in v_mut))
                    with self.assertRaises(TapscriptVerificationError):
                        verify_schedule_matrix_tapscript(sched_mut, probe_a, probe_b)
                    v_mutations += 1

        w_mutations = 0
        for k_idx in range(4):
            for l_idx in range(base.rank):
                orig = base.W_z[k_idx][l_idx]
                if orig == 0:
                    continue
                for mutated_val in (orig + 1, -orig):
                    w_mut = [list(row) for row in base.W_z]
                    w_mut[k_idx][l_idx] = mutated_val
                    sched_mut = replace(base, W_z=tuple(tuple(r) for r in w_mut))
                    with self.assertRaises(TapscriptVerificationError):
                        verify_schedule_matrix_tapscript(sched_mut, probe_a, probe_b)
                    w_mutations += 1

        self.assertEqual(u_mutations, 46)
        self.assertEqual(v_mutations, 46)
        self.assertEqual(w_mutations, 48)

    def test_06_adversarial_mutation_limb_carries_witnesses_and_p_aliasing_caught_red(self) -> None:
        """Corrupt EVERY limb carry, quotient limb, product limb, and test non-canonical `P`
        aliasing -> BitVM2 Tapscript verifier MUST reject RED on every single corruption!
        """
        probe_a = (1987654321, 2147483645, 1073741825, 999999999)
        probe_b = (2012345678, 1777777777, 2147483640, 1234567890)
        honest = simulate_qm31_rank7(probe_a, probe_b, record_witnesses=True)
        self.assertEqual(len(honest.mul_witnesses), 7)
        self.assertEqual(len(honest.div_witnesses), 4)

        # 1. Corrupt EVERY limb carry (+1 and -1) across all 7 OP_M31_MUL gadgets (84 mutations):
        carry_mutations = 0
        for mul_idx, wit in enumerate(honest.mul_witnesses):
            for carry_idx in range(6):
                for delta in (+1, -1):
                    c_list = list(wit.carries)
                    c_list[carry_idx] += delta
                    bad_wit = replace(
                        wit,
                        carries=(c_list[0], c_list[1], c_list[2], c_list[3], c_list[4], c_list[5]),
                    )
                    with self.assertRaises(TapscriptVerificationError):
                        simulate_qm31_rank7(
                            probe_a, probe_b, mul_witness_overrides={mul_idx: bad_wit}
                        )
                    carry_mutations += 1
        self.assertEqual(carry_mutations, 84)

        # 2. Corrupt EVERY quotient limb q_limbs[0..3] and product limb c_limbs[0..3]:
        for mul_idx, wit in enumerate(honest.mul_witnesses):
            for limb_idx in range(4):
                cap = 256 if limb_idx < 3 else 128
                q_list = list(wit.q_limbs)
                q_list[limb_idx] = (q_list[limb_idx] + 1) % cap
                bad_q = replace(wit, q_limbs=(q_list[0], q_list[1], q_list[2], q_list[3]))
                with self.assertRaises(TapscriptVerificationError):
                    simulate_qm31_rank7(probe_a, probe_b, mul_witness_overrides={mul_idx: bad_q})

                c_list = list(wit.c_limbs)
                c_list[limb_idx] = (c_list[limb_idx] + 1) % cap
                bad_c = replace(wit, c_limbs=(c_list[0], c_list[1], c_list[2], c_list[3]))
                with self.assertRaises(TapscriptVerificationError):
                    simulate_qm31_rank7(probe_a, probe_b, mul_witness_overrides={mul_idx: bad_c})

                a_list = list(wit.a_limbs)
                a_list[limb_idx] = (a_list[limb_idx] + 1) % cap
                bad_a = replace(wit, a_limbs=(a_list[0], a_list[1], a_list[2], a_list[3]))
                with self.assertRaises(TapscriptVerificationError):
                    simulate_qm31_rank7(probe_a, probe_b, mul_witness_overrides={mul_idx: bad_a})

        # 3. Corrupt EVERY constant-division witness q0_div..q3_div:
        for div_idx, dw in enumerate(honest.div_witnesses):
            bad_qdiv = (dw.quotient + 1) % M31_P
            with self.assertRaises(TapscriptVerificationError):
                simulate_qm31_rank7(probe_a, probe_b, div_witness_overrides={div_idx: bad_qdiv})

        # 4. Non-canonical c = P = 2^31 - 1 aliasing attacks (120 * P === 0 mod P!):
        with self.assertRaises(TapscriptVerificationError):
            simulate_qm31_rank7((0, 0, 0, 0), (0, 0, 0, 0), div_witness_overrides={0: M31_P})

        zero_wit = build_honest_m31_mul_witness(0, 12345)
        forged_p_wit = replace(zero_wit, c_limbs=P_LIMBS_BASE256)
        vm = TapscriptM31Machine()
        with self.assertRaises(TapscriptVerificationError):
            vm.op_m31_mul(0, 12345, witness_override=forged_p_wit)

        # 5. Reject unsupported small constants and 5-byte CScriptNum overflow:
        with self.assertRaises(ValueError):
            vm.op_m31_scale_small(1, 5)
        with self.assertRaises(TapscriptVerificationError):
            vm.op_m31_add(M31_P, 1)
        with self.assertRaises(TapscriptVerificationError):
            vm._check_cscriptnum(1 << 31)


if __name__ == "__main__":
    unittest.main()
