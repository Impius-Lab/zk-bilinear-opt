"""Deterministic Code & Certificate Emitters: no_std Rust, Go Gadgets & R1CS JSON."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Sequence

from .cost_models import evaluate_full_cost
from .fields import BLS12_377_PRIME, EXTENSION_SPECS
from .tensor_cert import (
    BilinearSchedule,
    certify_over_Z,
    compute_w_fp,
    verify_schedule_certificate,
)


def schedule_sha256(schedule: BilinearSchedule, prime: int) -> str:
    payload = json.dumps(
        {
            "target": schedule.target_name,
            "prime": str(prime),
            "degree": schedule.degree,
            "rank": schedule.rank,
            "D": schedule.D,
            "U": schedule.U,
            "V": schedule.V,
            "W_z": schedule.W_z,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def emit_r1cs_json(schedule: BilinearSchedule) -> str:
    """Emit deterministic R1CS + algebraic certificate JSON for a schedule."""
    spec = EXTENSION_SPECS[schedule.target_name]
    cert = verify_schedule_certificate(schedule, spec)
    if not cert.passed:
        raise ValueError(f"Refusing to emit JSON for unverified schedule {schedule.name}: {cert.errors}")
    cost = evaluate_full_cost(schedule)
    p = spec.prime
    inv_d = pow(schedule.D, p - 2, p)

    # Wire layout:
    #   0           : constant 1
    #   1 .. d      : input a[0..d-1]
    #   d+1 .. 2d   : input b[0..d-1]
    #   2d+1 .. 2d+r: intermediate products m[0..r-1]
    d = schedule.degree
    r = schedule.rank
    r1cs_bilinear = []
    for l in range(r):
        a_terms = {str(1 + i): int(schedule.U[l][i]) for i in range(d) if schedule.U[l][i] != 0}
        b_terms = {str(1 + d + j): int(schedule.V[l][j]) for j in range(d) if schedule.V[l][j] != 0}
        c_terms = {str(1 + 2 * d + l): 1}
        r1cs_bilinear.append({"A": a_terms, "B": b_terms, "C": c_terms})

    output_forms = []
    for k in range(d):
        terms = {
            str(1 + 2 * d + l): int(schedule.W_z[k][l])
            for l in range(r)
            if schedule.W_z[k][l] != 0
        }
        output_forms.append({"D_denominator": schedule.D, "W_z_terms": terms})

    doc: Dict[str, Any] = {
        "schema": "zk-bilinear-opt/certificate/v1",
        "sha256": schedule_sha256(schedule, p),
        "schedule_name": schedule.name,
        "family": schedule.family,
        "description": schedule.description,
        "target": {
            "name": spec.name,
            "ecosystem": spec.ecosystem,
            "prime_name": spec.prime_name,
            "prime_dec": str(p),
            "prime_bits": p.bit_length(),
            "degree": d,
            "basis_labels": list(spec.basis_labels),
            "simple_poly_coeffs": list(spec.simple_poly),
            "baseline_muls": spec.baseline_muls,
            "baseline_name": spec.baseline_name,
        },
        "certificate": {
            "passed": cert.passed,
            "rank": r,
            "mul_reduction_vs_baseline_pct": round(
                100.0 * (spec.baseline_muls - r) / spec.baseline_muls, 2
            ),
            "alder_strassen_lower_bound": cert.alder_strassen_lower_bound,
            "is_alder_strassen_optimal": cert.is_alder_strassen_optimal,
            "basis_pairs_checked": cert.basis_pairs_checked,
            "irreducibility_verified": cert.irreducibility_ok,
            "isomorphism_verified": cert.isomorphism_ok,
            "peak_native_bits": cert.peak_native_bits,
            "actual_limb_slack_bits": cert.actual_limb_slack_bits,
        },
        "costs": {
            "native_r1cs_constraints": cost.native.r1cs_constraints,
            "native_air_degree2_muls": cost.native.air_degree2_muls,
            "native_plonk_mul_gates": cost.native.plonk_mul_gates,
            "native_plonk_width4_total_gates": cost.native.plonk_width4_total_gates,
            "emulated_limbs": (
                None
                if cost.emulated is None
                else {
                    "limbs": f"{cost.emulated.num_limbs}x{cost.emulated.limb_bits}",
                    "pre_mul_reductions": cost.emulated.pre_mul_reductions,
                    "limb_muls_toom": cost.emulated.limb_muls_toom,
                    "limb_muls_schoolbook": cost.emulated.limb_muls_schoolbook,
                    "total_range_check_bits": cost.emulated.total_range_check_bits,
                    "groth16_r1cs_total": cost.emulated.groth16_r1cs_total,
                    "groth16_r1cs_schoolbook_total": cost.emulated.groth16_r1cs_schoolbook_total,
                    "plonk_lookup16_gates": cost.emulated.plonk_lookup16_gates,
                    "plonk_total_gates": cost.emulated.plonk_total_gates,
                }
            ),
        },
        "matrices": {
            "D": schedule.D,
            "inv_D_mod_p": str(inv_d),
            "U": [list(row) for row in schedule.U],
            "V": [list(row) for row in schedule.V],
            "W_z": [list(row) for row in schedule.W_z],
        },
        "r1cs": {
            "bilinear_gates": r1cs_bilinear,
            "output_linear_forms": output_forms,
        },
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def _format_signed_dot_expr(row: Sequence[int], var_name: str, cast_ty: str) -> str:
    nz = [(idx, coef) for idx, coef in enumerate(row) if coef != 0]
    if not nz:
        return "0"
    if len(nz) == 1 and nz[0][1] == 1:
        return f"{var_name}[{nz[0][0]}] as {cast_ty}"
    terms: List[str] = []
    for idx, coef in nz:
        v = f"({var_name}[{idx}] as {cast_ty})"
        if coef == 1:
            terms.append(f"+ {v}" if terms else v)
        elif coef == -1:
            terms.append(f"- {v}" if terms else f"-{v}")
        elif coef > 0:
            part = f"{coef} * {v}"
            terms.append(f"+ {part}" if terms else part)
        else:
            part = f"{abs(coef)} * {v}"
            terms.append(f"- {part}" if terms else f"-{part}")
    return " ".join(terms)


def emit_rust_function(schedule: BilinearSchedule, fn_name: str) -> str:
    """Emit a zero-overflow no_std Rust multiplication function for a 31-bit or 64-bit target."""
    spec = EXTENSION_SPECS[schedule.target_name]
    cert = verify_schedule_certificate(schedule, spec)
    if not cert.passed:
        raise ValueError(f"Unverified schedule {schedule.name}: {cert.errors}")
    if spec.native_accumulator_bits is None:
        raise ValueError(f"Target {spec.name} is a large pairing field; use Go/emulated emitter")

    p = spec.prime
    d = schedule.degree
    r = schedule.rank
    inv_d = pow(schedule.D, p - 2, p)
    is_64 = spec.native_accumulator_bits == 64

    elem_ty = "u32" if is_64 else "u64"
    signed_ty = "i64" if is_64 else "i128"
    unsigned_ty = "u64" if is_64 else "u128"
    signed_limit = (1 << 63) if is_64 else (1 << 127)
    use_direct_wz = schedule.max_wz_l1 * (p - 1) < (signed_limit >> 1)

    lines: List[str] = []
    lines.append(f"/// Certified {schedule.name} ({spec.ecosystem})")
    lines.append(
        f"/// Prime p = {p}, degree = {d}, rank = {r} (baseline = {spec.baseline_muls}), "
        f"peak intermediate = {cert.peak_native_bits} bits."
    )
    lines.append("#[inline]")
    lines.append(f"pub fn {fn_name}(a: &[{elem_ty}; {d}], b: &[{elem_ty}; {d}]) -> [{elem_ty}; {d}] {{")
    lines.append(f"    const P_S: {signed_ty} = {p};")
    lines.append(f"    const P_U: {unsigned_ty} = {p};")
    lines.append(f"    let mut m = [0{elem_ty}; {r}];")

    for l in range(r):
        u_expr = _format_signed_dot_expr(schedule.U[l], "a", signed_ty)
        v_expr = _format_signed_dot_expr(schedule.V[l], "b", signed_ty)
        lines.append("    {")
        lines.append(f"        let u_acc: {signed_ty} = {u_expr};")
        lines.append(f"        let v_acc: {signed_ty} = {v_expr};")
        lines.append(f"        let u_mod: {unsigned_ty} = u_acc.rem_euclid(P_S) as {unsigned_ty};")
        lines.append(f"        let v_mod: {unsigned_ty} = v_acc.rem_euclid(P_S) as {unsigned_ty};")
        lines.append(f"        m[{l}] = ((u_mod * v_mod) % P_U) as {elem_ty};")
        lines.append("    }")

    lines.append(f"    let mut out = [0{elem_ty}; {d}];")
    if use_direct_wz:
        lines.append(f"    const INV_D: {unsigned_ty} = {inv_d};")
        for k in range(d):
            w_expr = _format_signed_dot_expr(schedule.W_z[k], "m", signed_ty)
            lines.append("    {")
            lines.append(f"        let w_acc: {signed_ty} = {w_expr};")
            lines.append(f"        let w_rem: {unsigned_ty} = w_acc.rem_euclid(P_S) as {unsigned_ty};")
            lines.append(f"        out[{k}] = ((w_rem * INV_D) % P_U) as {elem_ty};")
            lines.append("    }")
    else:
        w_fp = compute_w_fp(schedule, p)
        for k in range(d):
            lines.append("    {")
            lines.append(f"        let mut rem: {unsigned_ty} = 0;")
            l = 0
            while l < r:
                if l + 1 < r:
                    c0 = w_fp[k][l]
                    c1 = w_fp[k][l + 1]
                    lines.append(
                        f"        rem = (rem + {c0}{unsigned_ty} * (m[{l}] as {unsigned_ty}) "
                        f"+ {c1}{unsigned_ty} * (m[{l + 1}] as {unsigned_ty})) % P_U;"
                    )
                    l += 2
                else:
                    c0 = w_fp[k][l]
                    lines.append(
                        f"        rem = (rem + {c0}{unsigned_ty} * (m[{l}] as {unsigned_ty})) % P_U;"
                    )
                    l += 1
            lines.append(f"        out[{k}] = rem as {elem_ty};")
            lines.append("    }")

    lines.append("    out")
    lines.append("}")
    return "\n".join(lines) + "\n"


def emit_rust_module(schedules_with_names: Sequence[tuple[BilinearSchedule, str]]) -> str:
    """Emit a complete #![no_std] Rust module for a list of (schedule, fn_name) pairs."""
    header = [
        "// Auto-generated by zk_bilinear.codegen — DO NOT EDIT MANUALLY.",
        "// Dual-licensed under MIT OR Apache-2.0.",
        "#![no_std]",
        "",
    ]
    blocks = [emit_rust_function(sched, fname) for sched, fname in schedules_with_names]
    return "\n".join(header) + "\n".join(blocks)


def emit_go_big_gadget(schedule: BilinearSchedule, fn_name: str) -> str:
    """Emit a deterministic Go function using math/big for exact arbitrary-prime verification."""
    spec = EXTENSION_SPECS[schedule.target_name]
    cert = verify_schedule_certificate(schedule, spec)
    if not cert.passed:
        raise ValueError(f"Unverified schedule {schedule.name}: {cert.errors}")
    p = spec.prime
    d = schedule.degree
    r = schedule.rank
    inv_d = pow(schedule.D, p - 2, p)

    def fmt_go_2d(mat: Sequence[Sequence[int]]) -> str:
        rows = [", ".join(str(x) for x in row) for row in mat]
        return "{\n\t\t{" + "},\n\t\t{".join(rows) + "},\n\t}"

    lines = [
        f"// {fn_name} implements certified {schedule.name} ({r} base-field multiplications vs {spec.baseline_muls} baseline).",
        f"func {fn_name}(a, b []*{ 'big.Int' }) []*{ 'big.Int' } {{",
        f'\tp := mustBigInt("{p}")',
        f'\tinvD := mustBigInt("{inv_d}")',
        f"\tuMat := [][]int64{fmt_go_2d(schedule.U)}",
        f"\tvMat := [][]int64{fmt_go_2d(schedule.V)}",
    ]
    # Check if W_z entries fit in int64; for deg-12 Vandermonde-23, W_z reaches ~113 bits!
    max_wz_abs = max(abs(x) for row in schedule.W_z for x in row)
    if max_wz_abs < (1 << 62):
        lines.append(f"\twzMat := [][]int64{fmt_go_2d(schedule.W_z)}")
        lines.append(f"\treturn evalBilinearInt64(a, b, p, invD, {d}, {r}, uMat, vMat, wzMat)")
    else:
        str_rows = [
            ", ".join(f'"{x}"' for x in row)
            for row in schedule.W_z
        ]
        wz_str = "{\n\t\t{" + "},\n\t\t{".join(str_rows) + "},\n\t}"
        lines.append(f"\twzStr := [][]string{wz_str}")
        lines.append(f"\treturn evalBilinearBigWz(a, b, p, invD, {d}, {r}, uMat, vMat, wzStr)")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _fp377_mont_literal(val: int, p: int = BLS12_377_PRIME) -> str:
    mont = ((val % p) << 384) % p
    limbs = [(mont >> (64 * i)) & ((1 << 64) - 1) for i in range(6)]
    return "Fp377{" + ", ".join(f"0x{x:016x}" for x in limbs) + "}"


def _emit_fp377_signed_row_lines(
    row: Sequence[int], src_var: str, dst_var: str, p: int = BLS12_377_PRIME
) -> List[str]:
    nz = [(idx, int(c)) for idx, c in enumerate(row) if c != 0]
    if not nz:
        return [f"\t\tvar {dst_var} Fp377"]
    out: List[str] = []
    for k_pos, (idx, coef) in enumerate(nz):
        elem = f"{src_var}[{idx}]"
        if k_pos == 0:
            if coef == 1:
                out.append(f"\t\t{dst_var} := {elem}")
            elif coef == -1:
                out.append(f"\t\t{dst_var} := fp377Neg({elem})")
            elif coef == 2:
                out.append(f"\t\t{dst_var} := fp377Add({elem}, {elem})")
            elif coef == -2:
                out.append(f"\t\t{dst_var} := fp377Neg(fp377Add({elem}, {elem}))")
            elif coef == -5:
                out.append(f"\t\t{dst_var} := fp377MulByNeg5({elem})")
            elif coef > 0:
                out.append(
                    f"\t\t{dst_var} := fp377ScaleConst({elem}, {_fp377_mont_literal(coef, p)})"
                )
            else:
                out.append(
                    f"\t\t{dst_var} := fp377Neg(fp377ScaleConst({elem}, {_fp377_mont_literal(-coef, p)}))"
                )
        else:
            if coef == 1:
                out.append(f"\t\t{dst_var} = fp377Add({dst_var}, {elem})")
            elif coef == -1:
                out.append(f"\t\t{dst_var} = fp377Sub({dst_var}, {elem})")
            elif coef == 2:
                out.append(f"\t\t{dst_var} = fp377Add({dst_var}, fp377Add({elem}, {elem}))")
            elif coef == -2:
                out.append(f"\t\t{dst_var} = fp377Sub({dst_var}, fp377Add({elem}, {elem}))")
            elif coef == -5:
                out.append(f"\t\t{dst_var} = fp377Add({dst_var}, fp377MulByNeg5({elem}))")
            elif coef > 0:
                out.append(
                    f"\t\t{dst_var} = fp377Add({dst_var}, fp377ScaleConst({elem}, {_fp377_mont_literal(coef, p)}))"
                )
            else:
                out.append(
                    f"\t\t{dst_var} = fp377Sub({dst_var}, fp377ScaleConst({elem}, {_fp377_mont_literal(-coef, p)}))"
                )
    return out


def _emit_fp377_mod_row_lines(
    row_fp: Sequence[int], src_var: str, dst_var: str, p: int = BLS12_377_PRIME
) -> List[str]:
    nz = [(idx, int(c) % p) for idx, c in enumerate(row_fp) if (int(c) % p) != 0]
    if not nz:
        return [f"\t\tvar {dst_var} Fp377"]
    out: List[str] = []
    for k_pos, (idx, c_mod) in enumerate(nz):
        elem = f"{src_var}[{idx}]"
        if k_pos == 0:
            if c_mod == 1:
                out.append(f"\t\t{dst_var} := {elem}")
            elif c_mod == p - 1:
                out.append(f"\t\t{dst_var} := fp377Neg({elem})")
            elif c_mod == p - 5:
                out.append(f"\t\t{dst_var} := fp377MulByNeg5({elem})")
            else:
                out.append(
                    f"\t\t{dst_var} := fp377ScaleConst({elem}, {_fp377_mont_literal(c_mod, p)})"
                )
        else:
            if c_mod == 1:
                out.append(f"\t\t{dst_var} = fp377Add({dst_var}, {elem})")
            elif c_mod == p - 1:
                out.append(f"\t\t{dst_var} = fp377Sub({dst_var}, {elem})")
            elif c_mod == p - 5:
                out.append(f"\t\t{dst_var} = fp377Add({dst_var}, fp377MulByNeg5({elem}))")
            else:
                out.append(
                    f"\t\t{dst_var} = fp377Add({dst_var}, fp377ScaleConst({elem}, {_fp377_mont_literal(c_mod, p)}))"
                )
    return out


def emit_go_bls12377_u64_gadget(schedule: BilinearSchedule, fn_name: str) -> str:
    """Emit a deterministic zero-allocation [6]uint64 (Fp377) Go tower gadget for BLS12-377."""
    spec = EXTENSION_SPECS[schedule.target_name]
    if spec.prime != BLS12_377_PRIME:
        raise ValueError(f"Expected BLS12-377 schedule, got prime {spec.prime}")
    cert = verify_schedule_certificate(schedule, spec)
    z_cert = certify_over_Z(schedule, spec)
    if not cert.passed or not z_cert.passed:
        raise ValueError(f"Unverified BLS12-377 schedule {schedule.name}: {cert.errors or z_cert.errors}")

    p = spec.prime
    d = schedule.degree
    r = schedule.rank
    w_fp = compute_w_fp(schedule, p)

    lines: List[str] = [
        f"// {fn_name} implements Z-certified {schedule.name} in canonical gnark BLS12-377 tower coordinates",
        f"// using zero-allocation [6]uint64 Montgomery arithmetic ({r} bilinear fp377Mul calls vs {spec.baseline_muls} baseline).",
        f"func {fn_name}(a, b [{d}]Fp377) [{d}]Fp377 {{",
        f"\tvar m [{r}]Fp377",
    ]
    for l in range(r):
        lines.append("\t{")
        lines.extend(_emit_fp377_signed_row_lines(schedule.U[l], "a", "uAcc", p))
        lines.extend(_emit_fp377_signed_row_lines(schedule.V[l], "b", "vAcc", p))
        lines.append(f"\t\tm[{l}] = fp377Mul(uAcc, vAcc)")
        lines.append("\t}")

    lines.append(f"\tvar out [{d}]Fp377")
    for k in range(d):
        lines.append("\t{")
        lines.extend(_emit_fp377_mod_row_lines(w_fp[k], "m", "wAcc", p))
        lines.append(f"\t\tout[{k}] = wAcc")
        lines.append("\t}")
    lines.append("\treturn out")
    lines.append("}")
    return "\n".join(lines) + "\n"


def emit_go_bls12377_u64_module(
    schedules_with_names: Sequence[tuple[BilinearSchedule, str]],
) -> str:
    """Emit go_gadgets/bls12377_u64_generated.go for [6]uint64 BLS12-377 tower gadgets."""
    header = [
        "// Code generated by `python -m zk_bilinear.cli generate-all`; DO NOT EDIT.",
        "package gogadgets",
        "",
    ]
    blocks = [emit_go_bls12377_u64_gadget(sched, fn) for sched, fn in schedules_with_names]
    return "\n".join(header) + "\n".join(blocks)
