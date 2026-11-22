"""Basis-complete d^2 algebraic identity proofs + 100,000-sample differential fuzzing."""

from __future__ import annotations

from pathlib import Path
import random
import unittest

from zk_bilinear.cli import render_benchmarks_markdown
from zk_bilinear.codegen import emit_go_bls12377_u64_module, emit_r1cs_json
from zk_bilinear.fields import EXTENSION_SPECS, PRIMES, is_prime
from zk_bilinear.pareto_search import SCHEDULE_SUITE, get_optimal_native_schedule
from zk_bilinear.tensor_cert import (
    certify_over_Z,
    compute_w_fp,
    verify_schedule_certificate,
)


class TestAllCertificatesAndFuzz(unittest.TestCase):
    def test_01_all_primes_and_extension_isomorphisms(self) -> None:
        for pname, pval in PRIMES.items():
            with self.subTest(prime=pname):
                self.assertTrue(is_prime(pval), f"{pname} failed primality check")

        self.assertGreaterEqual(len(EXTENSION_SPECS), 18)
        for tname, spec in EXTENSION_SPECS.items():
            with self.subTest(target=tname):
                self.assertTrue(spec.verify_isomorphism(), f"{tname} isomorphism failed")
                self.assertEqual(spec.optimal_rank, 2 * spec.degree - 1)

    def test_02_all_64_schedules_basis_complete_and_alder_strassen(self) -> None:
        total_schedules = 0
        total_basis_pairs = 0

        for tname, scheds in SCHEDULE_SUITE.items():
            spec = EXTENSION_SPECS[tname]
            found_optimal = False
            for sched in scheds:
                with self.subTest(schedule=sched.name):
                    z_rep = certify_over_Z(sched, spec)
                    self.assertTrue(z_rep.passed, f"{sched.name} Z-cert failed: {z_rep.errors}")
                    rep = verify_schedule_certificate(sched, spec)
                    self.assertTrue(rep.passed, f"{sched.name} failed: {rep.errors}")
                    self.assertEqual(rep.basis_pairs_checked, spec.degree * spec.degree)
                    self.assertGreaterEqual(rep.rank, 2 * spec.degree - 1)
                    if rep.rank == 2 * spec.degree - 1:
                        self.assertTrue(rep.is_alder_strassen_optimal)
                        found_optimal = True
                    total_schedules += 1
                    total_basis_pairs += rep.basis_pairs_checked
            self.assertTrue(found_optimal, f"No Alder-Strassen 2d-1 optimal schedule for {tname}")

        self.assertEqual(total_schedules, 64)
        self.assertEqual(total_basis_pairs, 3706)

    def test_03_headline_rank_reductions_pinned(self) -> None:
        expected_ranks = {
            "CM31": (4, 3),
            "QM31": (9, 7),
            "BabyBear4": (9, 7),
            "BabyBear5": (15, 9),
            "KoalaBear4": (9, 7),
            "KoalaBear8": (27, 15),
            "Goldilocks2": (3, 3),
            "Goldilocks4": (9, 7),
            "Goldilocks5": (15, 9),
            "BN254_Fp6": (18, 11),
            "BN254_Fp12": (54, 23),
            "BLS12_381_Fp6": (18, 11),
            "BLS12_381_Fp12": (54, 23),
            "BLS12_377_Fp2": (3, 3),
            "BLS12_377_Fp6": (18, 11),
            "BLS12_377_Fp12": (54, 23),
        }
        for tname, (base_r, opt_r) in expected_ranks.items():
            spec = EXTENSION_SPECS[tname]
            opt = get_optimal_native_schedule(tname)
            self.assertEqual(spec.baseline_muls, base_r)
            self.assertEqual(opt.rank, opt_r)

    def test_04_100k_randomized_differential_fuzz(self) -> None:
        """Run >100,000 deterministic randomized differential fuzz samples across all targets
        against independent textbook / tower reference multiplication.
        """
        rng = random.Random(20261121)
        # Distribute >= 100,000 samples across all required extensions:
        fuzz_plan = [
            (get_optimal_native_schedule("CM31"), 6_000),
            (get_optimal_native_schedule("QM31"), 14_000),
            (get_optimal_native_schedule("BabyBear4"), 12_000),
            (get_optimal_native_schedule("BabyBear5"), 12_000),
            (get_optimal_native_schedule("KoalaBear4"), 12_000),
            (get_optimal_native_schedule("KoalaBear8"), 10_000),
            (get_optimal_native_schedule("Goldilocks2"), 6_000),
            (get_optimal_native_schedule("Goldilocks4"), 8_000),
            (get_optimal_native_schedule("Goldilocks5"), 8_000),
            (get_optimal_native_schedule("BN254_Fp6"), 3_000),
            (SCHEDULE_SUITE["BN254_Fp12"][2], 1_500),  # Tower33
            (SCHEDULE_SUITE["BN254_Fp12"][3], 1_500),  # CRT30
            (get_optimal_native_schedule("BN254_Fp12"), 1_000),  # Rank23
            (get_optimal_native_schedule("BLS12_381_Fp6"), 3_000),
            (SCHEDULE_SUITE["BLS12_381_Fp12"][2], 1_500),  # Tower33
            (SCHEDULE_SUITE["BLS12_381_Fp12"][3], 1_500),  # CRT30
            (get_optimal_native_schedule("BLS12_381_Fp12"), 1_000),  # Rank23
            (get_optimal_native_schedule("BLS12_377_Fp2"), 1_000),  # Rank3
            (get_optimal_native_schedule("BLS12_377_Fp6"), 3_000),  # Rank11
            (SCHEDULE_SUITE["BLS12_377_Fp12"][2], 1_000),  # Tower33
            (SCHEDULE_SUITE["BLS12_377_Fp12"][3], 1_000),  # CRT30
            (get_optimal_native_schedule("BLS12_377_Fp12"), 1_000),  # Rank23
        ]

        total_samples = 0
        for sched, count in fuzz_plan:
            spec = EXTENSION_SPECS[sched.target_name]
            p = spec.prime
            d = sched.degree
            r = sched.rank
            w_fp = compute_w_fp(sched, p)
            u_mat = sched.U
            v_mat = sched.V
            ref_fn = spec.reference_mul

            with self.subTest(schedule=sched.name, samples=count):
                for _ in range(count):
                    a = [rng.randrange(p) for _ in range(d)]
                    b = [rng.randrange(p) for _ in range(d)]
                    m = [
                        (
                            sum(u_mat[l][i] * a[i] for i in range(d))
                            * sum(v_mat[l][j] * b[j] for j in range(d))
                        )
                        % p
                        for l in range(r)
                    ]
                    got = [sum(w_fp[k][l] * m[l] for l in range(r)) % p for k in range(d)]
                    want = ref_fn(a, b)
                    if got != want:
                        self.fail(f"Fuzz mismatch on {sched.name}: got={got}, want={want}")
                    total_samples += 1

        self.assertGreaterEqual(total_samples, 100_000)
        self.assertEqual(total_samples, 109_000)

    def test_05_committed_artifacts_match_deterministic_codegen(self) -> None:
        root = Path(__file__).resolve().parent.parent
        qm_cert_path = root / "targets" / "qm31_stwo" / "qm31_rank7_cert.json"
        self.assertTrue(qm_cert_path.exists())
        self.assertEqual(
            qm_cert_path.read_text(encoding="utf-8"),
            emit_r1cs_json(get_optimal_native_schedule("QM31")),
        )
        for tname, slug in [
            ("BLS12_377_Fp2", "bls12_377_fp2_rank3_cert.json"),
            ("BLS12_377_Fp6", "bls12_377_fp6_rank11_cert.json"),
            ("BLS12_377_Fp12", "bls12_377_fp12_rank23_cert.json"),
        ]:
            cpath = root / "targets" / "pairing_towers" / slug
            self.assertTrue(cpath.exists())
            self.assertEqual(
                cpath.read_text(encoding="utf-8"),
                emit_r1cs_json(get_optimal_native_schedule(tname)),
            )

        u64_go_path = root / "go_gadgets" / "bls12377_u64_generated.go"
        self.assertTrue(u64_go_path.exists())
        self.assertEqual(
            u64_go_path.read_text(encoding="utf-8"),
            emit_go_bls12377_u64_module(
                [
                    (get_optimal_native_schedule("BLS12_377_Fp2"), "MulBLS12377Fp2Rank3U64"),
                    (get_optimal_native_schedule("BLS12_377_Fp6"), "MulBLS12377Fp6Rank11U64"),
                    (get_optimal_native_schedule("BLS12_377_Fp12"), "MulBLS12377Fp12Rank23U64"),
                ]
            ),
        )
        bench_path = root / "monetization" / "benchmarks_report.md"
        self.assertTrue(bench_path.exists())
        self.assertEqual(
            bench_path.read_text(encoding="utf-8"),
            render_benchmarks_markdown(),
        )


if __name__ == "__main__":
    unittest.main()
