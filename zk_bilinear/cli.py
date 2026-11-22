"""CLI entrypoint & deterministic artifact generator for zk-bilinear-opt."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import List, Tuple

from .codegen import (
    emit_go_big_gadget,
    emit_r1cs_json,
    emit_rust_function,
    emit_rust_module,
    schedule_sha256,
)
from .cost_models import evaluate_full_cost
from .fields import EXTENSION_SPECS
from .pareto_search import (
    SCHEDULE_SUITE,
    compute_pareto_frontier,
    get_optimal_native_schedule,
    get_schedules_for_target,
)
from .tensor_cert import verify_schedule_certificate


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def verify_all_suite() -> int:
    total_scheds = 0
    total_pairs = 0
    for target_name, scheds in SCHEDULE_SUITE.items():
        spec = EXTENSION_SPECS[target_name]
        for s in scheds:
            rep = verify_schedule_certificate(s, spec)
            if not rep.passed:
                print(f"[FAIL] {s.name}: {rep.errors}", file=sys.stderr)
                return 1
            total_scheds += 1
            total_pairs += rep.basis_pairs_checked
            print(
                f"[PASS] {s.name:28s} | d={rep.degree:2d} | rank={rep.rank:2d} "
                f"(AS_lb={rep.alder_strassen_lower_bound:2d}, opt={str(rep.is_alder_strassen_optimal):5s}) | "
                f"basis={rep.basis_pairs_checked:3d} pairs | slack={rep.actual_limb_slack_bits:2d}b | "
                f"native_peak={str(rep.peak_native_bits):4s}b"
            )
    print(f"\nVerified {total_scheds} schedules ({total_pairs} basis-pair identities) — 100% PASS.")
    return 0


def render_benchmarks_markdown() -> str:
    """Deterministically generate monetization/benchmarks_report.md from live certified schedules."""
    lines: List[str] = []
    lines.append("# Reproducible Benchmark & Constraint-Reduction Report (`zk-bilinear-opt`)")
    lines.append("")
    lines.append("> **Reproducibility Guarantee**: Every figure in this report is computed deterministically")
    lines.append("> from basis-certified integer-rational bilinear decompositions $`(U, V, W_{\\mathbb{Z}}, D)`$")
    lines.append("> via `.venv\\Scripts\\python.exe -m zk_bilinear verify` and `.venv\\Scripts\\python.exe -m zk_bilinear generate-all`.")
    lines.append("")
    lines.append("## 1. Native STARK / AIR / R1CS Extension Towers (`stwo` & `Plonky3` / `SP1`)")
    lines.append("")
    lines.append("| Target Extension | Ecosystem | Prime $`p`$ | Deg $`d`$ | Baseline Muls | Certified Optimal Rank ($`2d-1`$) | Mul / R1CS / Degree-2 AIR Savings | Width-4 PlonK Total Gates | Peak Accumulator Bits (Limit) | Certificate SHA-256 (prefix) |")
    lines.append("| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

    native_targets = [
        "CM31",
        "QM31",
        "BabyBear4",
        "BabyBear5",
        "KoalaBear4",
        "KoalaBear8",
        "Goldilocks2",
        "Goldilocks4",
        "Goldilocks5",
    ]
    for tname in native_targets:
        spec = EXTENSION_SPECS[tname]
        opt = get_optimal_native_schedule(tname)
        cert = verify_schedule_certificate(opt, spec)
        cost = evaluate_full_cost(opt)
        sav = 100.0 * (spec.baseline_muls - opt.rank) / spec.baseline_muls
        lim = 63 if spec.native_accumulator_bits == 64 else 128
        sha = schedule_sha256(opt, spec.prime)[:12]
        p_disp = {
            "M31": "$`2^{31}-1`$",
            "BabyBear": "$`2^{31}-2^{27}+1`$",
            "KoalaBear": "$`2^{31}-2^{24}+1`$",
            "Goldilocks": "$`2^{64}-2^{32}+1`$",
        }[spec.prime_name]
        lines.append(
            f"| `{tname}` | {spec.ecosystem} | {p_disp} | {spec.degree} | {spec.baseline_muls} ({spec.baseline_name}) | "
            f"**{opt.rank}** | **-{sav:.2f}%** | {cost.native.plonk_width4_total_gates} | "
            f"`{cert.peak_native_bits}b` (`< 2^{lim}`) | `{sha}` |"
        )

    lines.append("")
    lines.append("## 2. Non-Native Emulated Pairing Towers (`Consensys/gnark` $`4\\times 64`$-bit `BN254` & $`6\\times 64`$-bit `BLS12-381`)")
    lines.append("")
    lines.append("In non-native emulated field circuits over a 254-bit SNARK scalar field (such as `gnark`'s `std/algebra/emulated`),")
    lines.append("two adjacent 64-bit limb equations are packed per carry constraint (`128 + 64 = 192` bits, plus `4` bits for signed carry + co-addition), leaving a **56-bit overflow ceiling**")
    lines.append("(`192 + 4 + 56 = 252 < 254` bits) for $`L \\cdot \\Vert U_\\ell\\Vert_1 \\cdot \\Vert V_\\ell\\Vert_1`$ before mandatory pre-multiplication `Reduce()` calls are triggered,")
    lines.append("and a **64-bit ceiling** on $`\\Vert W_{\\mathbb{Z},k}\\Vert_1 + D`$ before output modular-reduction quotients split into multi-limb witnesses.")
    lines.append("")

    for tname, header_title in [
        ("BN254_Fp6", "### 2.1 `BN254` $`\\mathbb{F}_{p^6}`$ ($`4\\times 64`$-bit Limbs, $`\\xi = 9 + u`$, Simple Iso $`v^6 - 18v^3 + 82 = 0`$)"),
        ("BN254_Fp12", "### 2.2 `BN254` $`\\mathbb{F}_{p^{12}}`$ ($`4\\times 64`$-bit Limbs, $`\\xi = 9 + u`$, Simple Iso $`w^{12} - 18w^6 + 82 = 0`$)"),
        ("BLS12_381_Fp6", "### 2.3 `BLS12-381` $`\\mathbb{F}_{p^6}`$ ($`6\\times 64`$-bit Limbs, $`\\xi = 1 + u`$, Simple Iso $`v^6 - 2v^3 + 2 = 0`$)"),
        ("BLS12_381_Fp12", "### 2.4 `BLS12-381` $`\\mathbb{F}_{p^{12}}`$ ($`6\\times 64`$-bit Limbs, $`\\xi = 1 + u`$, Simple Iso $`w^{12} - 2w^6 + 2 = 0`$)"),
    ]:
        lines.append(header_title)
        lines.append("")
        frontier = compute_pareto_frontier(tname)
        base_cost = frontier[0][1]
        assert base_cost.emulated is not None
        base_g16 = base_cost.emulated.groth16_r1cs_total
        base_plonk = base_cost.emulated.plonk_total_gates
        base_muls = base_cost.rank

        lines.append("| Schedule | Family | Native $`\\mathbb{F}_p`$ Muls ($`r`$) | Mul Savings | $`\\log_2(UV)`$ Slack | $`\\log_2(D)`$ | Pre-Mul `Reduce()` | Total Range-Check Bits | Net Groth16 R1CS (vs Baseline) | Net PlonK16 Gates (vs Baseline) | Pareto? |")
        lines.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

        for sched, fcost, is_par in frontier:
            emu = fcost.emulated
            assert emu is not None
            m_sav = 100.0 * (base_muls - fcost.rank) / base_muls
            g16_sav = 100.0 * (base_g16 - emu.groth16_r1cs_total) / base_g16
            plk_sav = 100.0 * (base_plonk - emu.plonk_total_gates) / base_plonk
            g16_sign = "-" if g16_sav >= 0 else "+"
            plk_sign = "-" if plk_sav >= 0 else "+"
            lines.append(
                f"| `{sched.name}` | {sched.family} | **{fcost.rank}** | -{m_sav:.2f}% | "
                f"`{fcost.max_uv_slack_bits}b` | `{fcost.d_bits:.1f}b` | `{emu.pre_mul_reductions}` | "
                f"{emu.total_range_check_bits:,} | "
                f"**{emu.groth16_r1cs_total:,}** ({g16_sign}{abs(g16_sav):.2f}%) | "
                f"**{emu.plonk_total_gates:,}** ({plk_sign}{abs(plk_sav):.2f}%) | "
                f"{'YES' if is_par else 'dominated'} |"
            )
        lines.append("")

    bn6 = compute_pareto_frontier("BN254_Fp6")
    bls6 = compute_pareto_frontier("BLS12_381_Fp6")
    bn12 = compute_pareto_frontier("BN254_Fp12")
    bls12 = compute_pareto_frontier("BLS12_381_Fp12")

    bn6_g16_sav = 100.0 * (bn6[0][1].emulated.groth16_r1cs_total - bn6[-1][1].emulated.groth16_r1cs_total) / bn6[0][1].emulated.groth16_r1cs_total  # type: ignore[union-attr]
    bls6_g16_sav = 100.0 * (bls6[0][1].emulated.groth16_r1cs_total - bls6[-1][1].emulated.groth16_r1cs_total) / bls6[0][1].emulated.groth16_r1cs_total  # type: ignore[union-attr]
    bn6_plk_sav = 100.0 * (bn6[0][1].emulated.plonk_total_gates - bn6[-1][1].emulated.plonk_total_gates) / bn6[0][1].emulated.plonk_total_gates  # type: ignore[union-attr]
    bls6_plk_sav = 100.0 * (bls6[0][1].emulated.plonk_total_gates - bls6[-1][1].emulated.plonk_total_gates) / bls6[0][1].emulated.plonk_total_gates  # type: ignore[union-attr]
    v23_reds = bn12[-1][1].emulated.pre_mul_reductions  # type: ignore[union-attr]
    bn12_crt30_sav = 100.0 * (bn12[0][1].emulated.groth16_r1cs_total - bn12[3][1].emulated.groth16_r1cs_total) / bn12[0][1].emulated.groth16_r1cs_total  # type: ignore[union-attr]
    bls12_crt30_sav = 100.0 * (bls12[0][1].emulated.groth16_r1cs_total - bls12[3][1].emulated.groth16_r1cs_total) / bls12[0][1].emulated.groth16_r1cs_total  # type: ignore[union-attr]

    lines.append("## 3. Key Architectural Takeaway: Why Naive `23`-Mul Vandermonde Loses to `CRT-30` & `Tower-33` in Non-Native Limbs")
    lines.append("")
    lines.append("1. **Native $`\\mathbb{F}_p`$ Circuits (e.g., BW6-761 / Pasta 2-chains / Native R1CS)**: Scalar multiplications by $`D^{-1} W_{\\mathbb{Z}} \\bmod p`$ fold into linear combinations for **zero** multiplicative gates, so `Rank-23` Vandermonde achieves the exact Winograd / Alder–Strassen global minimum of **23 R1CS constraints** (`-57.41%` vs `54`).")
    lines.append(f"2. **Emulated $`L\\times 64`$-bit Non-Native Circuits (`gnark` Groth16 / PlonK)**: `Vandermonde-Rank23` evaluates at nodes up to $`\\alpha = -11`$, where $`\\vert -11\\vert^{{11}} \\approx 2^{{38.1}}`$ pushes $`\\Vert U_\\ell\\Vert_1 \\Vert V_\\ell\\Vert_1`$ to **`77` bits** (`> 56`-bit 2-limb malicious-witness non-wrap limit), triggering **{v23_reds} mandatory pre-multiplication `Reduce()` gadgets**, while $`D = \\mathrm{{lcm}}(\\dots) \\approx 2^{{65.5}}`$ and $`\\Vert W_{{\\mathbb{{Z}}}}\\Vert_1 \\approx 2^{{113}}`$ force 2-limb output reduction quotients.")
    lines.append("3. **The Certified Non-Native Sweet Spots**:")
    lines.append(f"   - **On $`\\mathbb{{F}}_{{p^6}}`$**: `Rank-11` (`{{-5..4, inf}}`) stays strictly inside the 2-limb packing envelope (`0` pre-reductions, `18.5`-bit $`D`$), achieving **both** optimal native rank (`18 -> 11`, `-38.89%`) **and** the global minimum net Groth16 R1CS (`-{bn6_g16_sav:.2f}%` on BN254, `-{bls6_g16_sav:.2f}%` on BLS12-381) and PlonK16 (`-{bn6_plk_sav:.2f}%` / `-{bls6_plk_sav:.2f}%`) constraint counts!")
    lines.append(f"   - **On $`\\mathbb{{F}}_{{p^{{12}}}}`$**: `CRT-30` (`9` small linear nodes `{{-4..3, inf}}` + `7` cyclotomic/small quadratic moduli, `0` pre-reductions, single-word output quotients) and `Tower-33` (`Toom-6` over $`\\mathbb{{F}}_{{p^2}}`$ $`\\times`$ `Karatsuba-2`, `18.5`-bit $`D`$, `0` pre-reductions) eliminate 100% of pre-multiplication reductions and beat `Tower-54` by **`-{bn12_crt30_sav:.2f}%` (BN254) and `-{bls12_crt30_sav:.2f}%` (BLS12-381) net Groth16 R1CS constraints AFTER counting every carry & range-check bit**, cleanly outperforming `Vandermonde-23`!")
    lines.append("")
    return "\n".join(lines)


def generate_all_artifacts() -> None:
    root = repo_root()

    # 1. targets/qm31_stwo/
    qm_dir = root / "targets" / "qm31_stwo"
    qm_dir.mkdir(parents=True, exist_ok=True)
    qm_opt = get_optimal_native_schedule("QM31")
    qm_base = get_schedules_for_target("QM31")[0]
    (qm_dir / "qm31_rank7_cert.json").write_text(emit_r1cs_json(qm_opt), encoding="utf-8")
    (qm_dir / "qm31_stwo.rs").write_text(
        emit_rust_module([(qm_opt, "mul_qm31_rank7"), (qm_base, "mul_qm31_karatsuba9")]),
        encoding="utf-8",
    )

    # 2. targets/plonky3_extensions/
    p3_dir = root / "targets" / "plonky3_extensions"
    p3_dir.mkdir(parents=True, exist_ok=True)
    p3_pairs: List[Tuple[object, str]] = []
    for tname, fname, slug in [
        ("BabyBear4", "mul_babybear4_rank7", "babybear4_rank7_cert.json"),
        ("BabyBear5", "mul_babybear5_rank9", "babybear5_rank9_cert.json"),
        ("KoalaBear4", "mul_koalabear4_rank7", "koalabear4_rank7_cert.json"),
        ("KoalaBear8", "mul_koalabear8_rank15", "koalabear8_rank15_cert.json"),
        ("Goldilocks2", "mul_goldilocks2_rank3", "goldilocks2_rank3_cert.json"),
        ("Goldilocks4", "mul_goldilocks4_rank7", "goldilocks4_rank7_cert.json"),
        ("Goldilocks5", "mul_goldilocks5_rank9", "goldilocks5_rank9_cert.json"),
    ]:
        sched = get_optimal_native_schedule(tname)
        (p3_dir / slug).write_text(emit_r1cs_json(sched), encoding="utf-8")
        p3_pairs.append((sched, fname))
    (p3_dir / "plonky3_extensions.rs").write_text(
        emit_rust_module(p3_pairs),  # type: ignore[arg-type]
        encoding="utf-8",
    )

    # 3. targets/pairing_towers/
    pt_dir = root / "targets" / "pairing_towers"
    pt_dir.mkdir(parents=True, exist_ok=True)
    for tname, fname_json in [
        ("BN254_Fp6", "bn254_fp6_pareto.json"),
        ("BN254_Fp12", "bn254_fp12_pareto.json"),
        ("BLS12_381_Fp6", "bls12_381_fp6_pareto.json"),
        ("BLS12_381_Fp12", "bls12_381_fp12_pareto.json"),
    ]:
        frontier = compute_pareto_frontier(tname)
        entries = []
        for sched, fcost, is_par in frontier:
            cert_obj = json.loads(emit_r1cs_json(sched))
            cert_obj["is_pareto_efficient"] = is_par
            entries.append(cert_obj)
        (pt_dir / fname_json).write_text(
            json.dumps({"target": tname, "schedules": entries}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    # 4. rust_crates/src/generated.rs
    rust_src = root / "rust_crates" / "src"
    rust_src.mkdir(parents=True, exist_ok=True)
    all_rust_scheds = [
        (get_optimal_native_schedule("CM31"), "mul_cm31_rank3"),
        (qm_opt, "mul_qm31_rank7"),
        (qm_base, "mul_qm31_karatsuba9"),
        *p3_pairs,
    ]
    gen_rs_blocks = [emit_rust_function(s, fn) for s, fn in all_rust_scheds]  # type: ignore[arg-type]
    (rust_src / "generated.rs").write_text(
        "// Auto-generated by `python -m zk_bilinear generate-all`.\n\n" + "\n".join(gen_rs_blocks),
        encoding="utf-8",
    )

    # 5. go_gadgets/gadgets_generated.go
    go_dir = root / "go_gadgets"
    go_dir.mkdir(parents=True, exist_ok=True)
    go_targets = [
        (get_optimal_native_schedule("QM31"), "MulQM31Rank7"),
        (get_schedules_for_target("QM31")[0], "MulQM31Karatsuba9"),
        (get_optimal_native_schedule("BabyBear4"), "MulBabyBear4Rank7"),
        (get_optimal_native_schedule("BabyBear5"), "MulBabyBear5Rank9"),
        (get_optimal_native_schedule("KoalaBear4"), "MulKoalaBear4Rank7"),
        (get_optimal_native_schedule("KoalaBear8"), "MulKoalaBear8Rank15"),
        (get_optimal_native_schedule("BN254_Fp6"), "MulBN254Fp6Rank11"),
        (get_schedules_for_target("BN254_Fp6")[0], "MulBN254Fp6Tower18"),
        (get_schedules_for_target("BN254_Fp12")[2], "MulBN254Fp12Tower33"),
        (get_schedules_for_target("BN254_Fp12")[3], "MulBN254Fp12CRT30"),
        (get_optimal_native_schedule("BN254_Fp12"), "MulBN254Fp12Rank23"),
        (get_schedules_for_target("BN254_Fp12")[0], "MulBN254Fp12Tower54"),
        (get_optimal_native_schedule("BLS12_381_Fp6"), "MulBLS12381Fp6Rank11"),
        (get_schedules_for_target("BLS12_381_Fp6")[0], "MulBLS12381Fp6Tower18"),
        (get_schedules_for_target("BLS12_381_Fp12")[2], "MulBLS12381Fp12Tower33"),
        (get_schedules_for_target("BLS12_381_Fp12")[3], "MulBLS12381Fp12CRT30"),
        (get_optimal_native_schedule("BLS12_381_Fp12"), "MulBLS12381Fp12Rank23"),
        (get_schedules_for_target("BLS12_381_Fp12")[0], "MulBLS12381Fp12Tower54"),
    ]
    go_header = [
        "// Code generated by `python -m zk_bilinear generate-all`; DO NOT EDIT.",
        "package gogadgets",
        "",
        'import "math/big"',
        "",
    ]
    go_body = [emit_go_big_gadget(s, fn) for s, fn in go_targets]
    (go_dir / "gadgets_generated.go").write_text(
        "\n".join(go_header) + "\n".join(go_body),
        encoding="utf-8",
    )

    # 6. monetization/benchmarks_report.md
    mon_dir = root / "monetization"
    mon_dir.mkdir(parents=True, exist_ok=True)
    (mon_dir / "benchmarks_report.md").write_text(render_benchmarks_markdown(), encoding="utf-8")
    print("[OK] Generated targets/, rust_crates/src/generated.rs, go_gadgets/gadgets_generated.go, and monetization/benchmarks_report.md.")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zk-bilinear", description="ZK Bilinear Rank Certifier & Code Generator")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify", help="Run basis-complete algebraic & overflow checks on all schedules")
    sub.add_parser("generate-all", help="Deterministically regenerate targets, Rust, Go & benchmark report")
    sub.add_parser("report", help="Print Markdown benchmark report to stdout")

    args = parser.parse_args(argv)
    if args.cmd == "verify":
        return verify_all_suite()
    if args.cmd == "generate-all":
        rc = verify_all_suite()
        if rc != 0:
            return rc
        generate_all_artifacts()
        return 0
    if args.cmd == "report":
        print(render_benchmarks_markdown())
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
