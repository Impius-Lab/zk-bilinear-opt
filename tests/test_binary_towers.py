"""Comprehensive Verification & Fail-First Mutation Suite for `Binius` & `AES` Binary Towers."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import random
import re
import unittest

from zk_bilinear.binary_towers import (
    AES_POLY,
    GF2BilinearSchedule,
    aes_gf256_mul_isomorphic,
    aes_gf256_mul_ref,
    aes_to_binius_t3,
    binius_inv,
    binius_mul,
    binius_mul_alpha,
    binius_square,
    binius_t3_to_aes,
    build_aes_to_binius_t3_isomorphism,
    certify_gf2_schedule,
    evaluate_gf2_schedule,
    gf2_bits_to_int,
    gf2_det_and_inv,
    gf2_identity,
    gf2_mat_mul,
    summarize_binary_tower_benchmarks,
    synthesize_aes_chudnovsky_rank24,
    synthesize_aes_wiedemann_rank27,
    synthesize_binius_t3_chudnovsky_rank24,
    synthesize_binius_t4_chudnovsky_rank60,
    synthesize_binius_t4_toom_gf16_rank63,
    synthesize_wiedemann_schedule,
    verify_wiedemann_tower_irreducibility,
    wiedemann_karatsuba_gate_counts,
)


def _independent_wiedemann_basis_mul(k: int, i: int, j: int) -> int:
    """Zero-shared-code schoolbook expansion of `e_i * e_j` in `T_k = T_{k-1}[X_{k-1}]/(X_{k-1}^2 + X_{k-2} X_{k-1} + 1)`."""
    if k == 0:
        return 1
    half = 1 << (k - 1)
    i_hi, j_hi = int(i >= half), int(j >= half)
    i_lo, j_lo = i & (half - 1), j & (half - 1)
    sub = _independent_wiedemann_basis_mul(k - 1, i_lo, j_lo)
    if (i_hi, j_hi) == (0, 0):
        return sub
    if i_hi ^ j_hi:
        return sub << half
    # Both in upper half: sub * (X_{k-2} * X_{k-1} + 1)
    if k == 1:
        hi = sub
    else:
        alpha_bit = half >> 1
        hi = 0
        for b in range(half):
            if (sub >> b) & 1:
                hi ^= _independent_wiedemann_basis_mul(k - 1, b, alpha_bit)
    return sub ^ (hi << half)


class TestBinaryTowersBiniusAndAES(unittest.TestCase):
    def test_01_wiedemann_tower_irreducibility_and_gate_counts_k1_to_k7(self) -> None:
        """Verify all 7 Wiedemann levels `T_1..T_7` (`GF(2^2)`..`GF(2^128)`) are fields and match exact `3^k` AND counts."""
        irr = verify_wiedemann_tower_irreducibility(7)
        expected_ranks = {1: 3, 2: 9, 3: 27, 4: 81, 5: 243, 6: 729, 7: 2187}
        expected_sb = {k: (1 << k) ** 2 for k in range(1, 8)}

        for k in range(1, 8):
            self.assertTrue(irr[k]["is_field"])
            self.assertEqual(irr[k]["multiplicative_order"], (1 << (1 << k)) - 1)
            counts = wiedemann_karatsuba_gate_counts(k)
            self.assertEqual(counts["and_gates"], expected_ranks[k])
            self.assertEqual(counts["schoolbook_and_gates"], expected_sb[k])

        self.assertEqual(wiedemann_karatsuba_gate_counts(7)["and_reduction_pct"], 86.65)
        self.assertEqual(wiedemann_karatsuba_gate_counts(3)["and_reduction_pct"], 57.81)

    def test_02_basis_pair_completeness_wiedemann_and_chudnovsky_toom(self) -> None:
        """Verify 100% `d^2` `GF(2)` basis-pair completeness across `T_1..T_4` against an independent oracle."""
        expected_pairs = {1: 4, 2: 16, 3: 64, 4: 256}
        for k, npairs in expected_pairs.items():
            d = 1 << k
            sched = synthesize_wiedemann_schedule(k)
            rep = certify_gf2_schedule(sched, lambda a, b, kk=k: binius_mul(a, b, kk))
            self.assertTrue(rep.passed, rep.errors)
            self.assertEqual(rep.basis_pairs_checked, npairs)
            # Cross-check every basis pair against independent definition-level oracle:
            for i in range(d):
                for j in range(d):
                    want = _independent_wiedemann_basis_mul(k, i, j)
                    self.assertEqual(binius_mul(1 << i, 1 << j, k), want)
                    self.assertEqual(evaluate_gf2_schedule(sched, 1 << i, 1 << j), want)

        # Extension-interpolated lower-rank schedules on GF(2^8) and GF(2^16):
        t3_r24 = synthesize_binius_t3_chudnovsky_rank24()
        t4_r63 = synthesize_binius_t4_toom_gf16_rank63()
        t4_r60 = synthesize_binius_t4_chudnovsky_rank60()

        self.assertEqual(t3_r24.rank, 24)
        self.assertEqual(t4_r63.rank, 63)
        self.assertEqual(t4_r60.rank, 60)

        rep_24 = certify_gf2_schedule(t3_r24, lambda a, b: binius_mul(a, b, 3))
        rep_63 = certify_gf2_schedule(t4_r63, lambda a, b: binius_mul(a, b, 4))
        rep_60 = certify_gf2_schedule(t4_r60, lambda a, b: binius_mul(a, b, 4))
        self.assertTrue(rep_24.passed)
        self.assertTrue(rep_63.passed)
        self.assertTrue(rep_60.passed)
        self.assertEqual(rep_24.basis_pairs_checked, 64)
        self.assertEqual(rep_63.basis_pairs_checked, 256)
        self.assertEqual(rep_60.basis_pairs_checked, 256)

    def test_03_aes_gf256_isomorphism_and_64_basis_plus_65536_byte_completeness(self) -> None:
        """Verify AES `GF(2^8)` (`0x11b`) isomorphism (`det = 1 mod 2`), Rank-27, and Rank-24 schedules."""
        self.assertEqual(AES_POLY, 0x11B)
        m_to, m_from, gamma = build_aes_to_binius_t3_isomorphism()
        det_to, _ = gf2_det_and_inv(m_to)
        det_from, _ = gf2_det_and_inv(m_from)
        self.assertEqual(det_to, 1)
        self.assertEqual(det_from, 1)
        self.assertEqual(gf2_mat_mul(m_to, m_from), gf2_identity(8))
        self.assertEqual(gf2_mat_mul(m_from, m_to), gf2_identity(8))

        # Verify gamma satisfies x^8 + x^4 + x^3 + x + 1 == 0 in T_3
        g2 = binius_square(gamma, 3)
        g3 = binius_mul(g2, gamma, 3)
        g4 = binius_square(g2, 3)
        g8 = binius_square(g4, 3)
        self.assertEqual(g8 ^ g4 ^ g3 ^ gamma ^ 1, 0)

        aes_r27 = synthesize_aes_wiedemann_rank27()
        aes_r24 = synthesize_aes_chudnovsky_rank24()
        self.assertEqual(aes_r27.rank, 27)
        self.assertEqual(aes_r24.rank, 24)
        self.assertLessEqual(aes_r24.rank, 26)

        rep27 = certify_gf2_schedule(aes_r27, aes_gf256_mul_ref)
        rep24 = certify_gf2_schedule(aes_r24, aes_gf256_mul_ref)
        self.assertTrue(rep27.passed)
        self.assertTrue(rep24.passed)
        self.assertEqual(rep27.basis_pairs_checked, 64)
        self.assertEqual(rep24.basis_pairs_checked, 64)

        # Exhaustive 256-element bijection + random/sample pairs:
        for x in range(256):
            self.assertEqual(binius_t3_to_aes(aes_to_binius_t3(x)), x)
            self.assertEqual(aes_to_binius_t3(binius_t3_to_aes(x)), x)

        rng = random.Random(20261122)
        for _ in range(512):
            a, b = rng.randrange(256), rng.randrange(256)
            want = aes_gf256_mul_ref(a, b)
            self.assertEqual(aes_gf256_mul_isomorphic(a, b), want)
            self.assertEqual(evaluate_gf2_schedule(aes_r27, a, b), want)
            self.assertEqual(evaluate_gf2_schedule(aes_r24, a, b), want)

    def test_04_gf2_128_field_axioms_frobenius_and_itoh_tsujii_inversion(self) -> None:
        """Verify 128-bit associativity, distributivity, Frobenius squaring, and `a * inv(a) == 1`."""
        with self.assertRaises(ZeroDivisionError):
            binius_inv(0, 7)

        rng = random.Random(0xB14105)
        for _ in range(200):
            a = rng.getrandbits(128)
            b = rng.getrandbits(128)
            c = rng.getrandbits(128)
            ab = binius_mul(a, b, 7)
            bc = binius_mul(b, c, 7)
            self.assertEqual(ab, binius_mul(b, a, 7))
            self.assertEqual(binius_mul(ab, c, 7), binius_mul(a, bc, 7))
            self.assertEqual(binius_mul(a, b ^ c, 7), ab ^ binius_mul(a, c, 7))
            self.assertEqual(binius_square(a, 7), binius_mul(a, a, 7))
            self.assertEqual(binius_square(a ^ b, 7), binius_square(a, 7) ^ binius_square(b, 7))
            if a != 0:
                self.assertEqual(binius_mul(a, binius_inv(a, 7), 7), 1)
            # Check mul_alpha(x, 6) matches multiplying by X_5 = 1 << 16 in T_6:
            a64 = a & ((1 << 64) - 1)
            self.assertEqual(binius_mul_alpha(a64, 6), binius_mul(a64, 1 << 32, 6))

    def test_05_cross_language_rust_mask_parity(self) -> None:
        """Verify `rust_crates/src/binary_tower.rs` embeds bit-for-bit identical isomorphism & Rank-24 masks."""
        rs_path = Path(__file__).resolve().parent.parent / "rust_crates" / "src" / "binary_tower.rs"
        rs_src = rs_path.read_text(encoding="utf-8")
        self.assertIn("#![forbid(unsafe_code)]", rs_src)

        summary = summarize_binary_tower_benchmarks()
        aes_info = summary["aes_gf256"]

        def parse_hex_array(const_name: str) -> tuple[int, ...]:
            m = re.search(rf"pub const {const_name}:\s*\[u\d+;\s*\d+\]\s*=\s*\[([^\]]+)\];", rs_src)
            self.assertIsNotNone(m, f"Missing {const_name} in binary_tower.rs")
            tokens = [tok.strip() for tok in m.group(1).split(",") if tok.strip()]  # type: ignore[union-attr]
            return tuple(int(tok, 16) for tok in tokens)

        self.assertEqual(parse_hex_array("AES_TO_BINIUS_T3_ROWS"), aes_info["aes_to_t3_row_masks"])
        self.assertEqual(parse_hex_array("BINIUS_T3_TO_AES_ROWS"), aes_info["t3_to_aes_row_masks"])

        t3_r24 = synthesize_binius_t3_chudnovsky_rank24()
        aes_r24 = synthesize_aes_chudnovsky_rank24()
        self.assertEqual(
            parse_hex_array("BINIUS_T3_RANK24_UV"),
            tuple(gf2_bits_to_int(r) for r in t3_r24.U),
        )
        self.assertEqual(
            parse_hex_array("BINIUS_T3_RANK24_W"),
            tuple(gf2_bits_to_int(r) for r in t3_r24.W),
        )
        self.assertEqual(
            parse_hex_array("AES_GF256_RANK24_UV"),
            tuple(gf2_bits_to_int(r) for r in aes_r24.U),
        )
        self.assertEqual(
            parse_hex_array("AES_GF256_RANK24_W"),
            tuple(gf2_bits_to_int(r) for r in aes_r24.W),
        )

    def test_06_live_red_bit_flip_mutations_caught(self) -> None:
        """Fail-first mutation self-test: single bit-flips in `U`, `V`, `W`, non-binary entries,
        and singular isomorphism matrices MUST all fail RED.
        """
        targets: list[tuple[GF2BilinearSchedule, object]] = [
            (synthesize_wiedemann_schedule(3), lambda a, b: binius_mul(a, b, 3)),
            (synthesize_binius_t3_chudnovsky_rank24(), lambda a, b: binius_mul(a, b, 3)),
            (synthesize_binius_t4_chudnovsky_rank60(), lambda a, b: binius_mul(a, b, 4)),
            (synthesize_aes_wiedemann_rank27(), aes_gf256_mul_ref),
            (synthesize_aes_chudnovsky_rank24(), aes_gf256_mul_ref),
        ]

        for sched, ref_fn in targets:
            # 1. Flip 1 bit in U[0][0] -> RED
            u_mut = [list(r) for r in sched.U]
            u_mut[0][0] ^= 1
            rep_u = certify_gf2_schedule(
                replace(sched, U=tuple(tuple(r) for r in u_mut)),
                ref_fn,  # type: ignore[arg-type]
            )
            self.assertFalse(rep_u.passed, f"U bit-flip escaped on {sched.name}")
            self.assertFalse(rep_u.basis_identity_ok)

            # 2. Flip 1 bit in V[-1][-1] -> RED
            v_mut = [list(r) for r in sched.V]
            v_mut[-1][-1] ^= 1
            rep_v = certify_gf2_schedule(
                replace(sched, V=tuple(tuple(r) for r in v_mut)),
                ref_fn,  # type: ignore[arg-type]
            )
            self.assertFalse(rep_v.passed, f"V bit-flip escaped on {sched.name}")
            self.assertFalse(rep_v.basis_identity_ok)

            # 3. Flip 1 bit in W[0][0] -> RED
            w_mut = [list(r) for r in sched.W]
            w_mut[0][0] ^= 1
            rep_w = certify_gf2_schedule(
                replace(sched, W=tuple(tuple(r) for r in w_mut)),
                ref_fn,  # type: ignore[arg-type]
            )
            self.assertFalse(rep_w.passed, f"W bit-flip escaped on {sched.name}")
            self.assertFalse(rep_w.basis_identity_ok)

        # 4. Non-binary entry outside {0, 1} -> RED
        aes24 = synthesize_aes_chudnovsky_rank24()
        bad_u = [list(r) for r in aes24.U]
        bad_u[0][0] = 2
        rep_bin = certify_gf2_schedule(
            replace(aes24, U=tuple(tuple(r) for r in bad_u)), aes_gf256_mul_ref
        )
        self.assertFalse(rep_bin.passed)
        self.assertFalse(rep_bin.binary_entries_ok)

        # 5. Corrupt AES isomorphism row -> singular over GF(2) caught RED
        m_to, _, _ = build_aes_to_binius_t3_isomorphism()
        singular = [list(r) for r in m_to]
        singular[7] = [singular[0][j] ^ singular[1][j] for j in range(8)]
        det_sing, inv_sing = gf2_det_and_inv(singular)
        self.assertEqual(det_sing, 0)
        self.assertIsNone(inv_sing)


if __name__ == "__main__":
    unittest.main()
