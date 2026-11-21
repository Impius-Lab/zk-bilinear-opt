"""Exact ZK Circuit Cost Models: Native R1CS, PlonK, Degree-2 AIR & Emulated Limbs.

Models every cost component honestly from the integer-rational bilinear representation
(U, V, W_z, D):
  1. Native R1CS: exact bilinear rank r (linear combinations folded into A, B, C).
  2. Native PlonK: bilinear mul gates (r) + deduplicated width-4 linear addition gates.
  3. Degree-2 STARK AIR (stwo / Plonky3): degree-2 bilinear column budget + exact
     hardware accumulator bit-width (u64 for 31-bit primes, u128 for Goldilocks).
  4. Non-Native Emulated Limbs (gnark std/algebra/emulated style over a 254-bit SNARK
     scalar field, e.g. 4x64-bit for BN254 and 6x64-bit for BLS12-381):
     - Enforces gnark's 2-limb carry-packing overflow budget:
         128 (limb*limb) + 64 (2-limb pack) + ceil(log2(L * ||U_l||_1 * ||V_l||_1)) <= 252
       (=> <= 60 bits of product overflow before mandatory pre-multiplication Reduce()!).
     - Counts Toom-limb (2L - 1) and schoolbook (L^2) bilinear limb multiplications,
       quotient witness range-check bits, 2-limb-packed carry range-check bits, and
       output modular reduction W_z * m - D * c = q_W * p range-check bits for BOTH
       Groth16 R1CS (1 constraint/bit) and PlonK with 16-bit range-check lookups.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Dict, List, Optional, Sequence, Tuple

from .fields import EXTENSION_SPECS, ExtensionSpec
from .tensor_cert import BilinearSchedule, theoretical_peak_native_bits


@dataclass(frozen=True)
class NativeCircuitCost:
    r1cs_constraints: int
    air_degree2_muls: int
    plonk_mul_gates: int
    plonk_width4_linear_gates: int
    plonk_width4_total_gates: int
    peak_native_word_bits: Optional[int]


@dataclass(frozen=True)
class EmulatedLimbCost:
    num_limbs: int
    limb_bits: int
    prime_bits: int
    base_muls: int
    pre_mul_reductions: int
    limb_muls_toom: int
    limb_muls_schoolbook: int
    quotient_and_witness_bits: int
    carry_range_bits: int
    output_reduction_bits: int
    total_range_check_bits: int
    carry_linear_constraints: int
    groth16_r1cs_total: int
    groth16_r1cs_schoolbook_total: int
    plonk_lookup16_gates: int
    plonk_arith_gates: int
    plonk_total_gates: int
    max_mul_quotient_bits: int
    max_mul_carry_bits: int
    max_out_quotient_bits: int
    max_out_carry_bits: int


@dataclass(frozen=True)
class FullScheduleCost:
    schedule_name: str
    target_name: str
    rank: int
    d_bits: float
    max_uv_slack_bits: int
    native: NativeCircuitCost
    emulated: Optional[EmulatedLimbCost]


def _count_dedup_width4_gates(matrix: Sequence[Sequence[int]]) -> int:
    """Count width-4 PlonK linear gates needed to form unique non-trivial rows."""
    seen = set()
    gates = 0
    for row in matrix:
        nz = tuple((idx, val) for idx, val in enumerate(row) if val != 0)
        if len(nz) <= 1:
            continue
        # Canonicalize up to sign
        first_sign = 1 if nz[0][1] > 0 else -1
        canon = tuple((idx, val * first_sign) for idx, val in nz)
        if canon in seen:
            continue
        seen.add(canon)
        # Width-4 gate combines 3 wires -> 1 output wire (reduces wire count by 2 per gate)
        gates += math.ceil((len(nz) - 1) / 2)
    return gates


def compute_native_cost(
    schedule: BilinearSchedule, spec: Optional[ExtensionSpec] = None
) -> NativeCircuitCost:
    if spec is None:
        spec = EXTENSION_SPECS[schedule.target_name]
    r = schedule.rank
    u_gates = _count_dedup_width4_gates(schedule.U)
    v_gates = _count_dedup_width4_gates(schedule.V)
    w_gates = _count_dedup_width4_gates(schedule.W_z)
    lin_gates = u_gates + v_gates + w_gates
    peak_bits: Optional[int] = None
    if spec.native_accumulator_bits is not None:
        peak_bits = theoretical_peak_native_bits(schedule, spec.prime, spec.native_accumulator_bits)
    return NativeCircuitCost(
        r1cs_constraints=r,
        air_degree2_muls=r,
        plonk_mul_gates=r,
        plonk_width4_linear_gates=lin_gates,
        plonk_width4_total_gates=r + lin_gates,
        peak_native_word_bits=peak_bits,
    )


def compute_emulated_limb_cost(
    schedule: BilinearSchedule,
    num_limbs: int,
    limb_bits: int = 64,
    prime: Optional[int] = None,
    snark_scalar_limit_bits: int = 252,
) -> EmulatedLimbCost:
    """Compute exact non-native limb constraint & carry-range-check cost (gnark model)."""
    spec = EXTENSION_SPECS[schedule.target_name]
    p = spec.prime if prime is None else prime
    p_bits = p.bit_length()
    r = schedule.rank
    d = schedule.degree
    D = schedule.D

    # In gnark, 2 adjacent limb equations are packed (128 + 64 = 192 base bits), leaving
    # snark_scalar_limit_bits - 192 (= 60 bits for 252-bit BN254 scalar cap) for L * ||U||_1 * ||V||_1.
    two_limb_pack_cap = snark_scalar_limit_bits - 2 * limb_bits - limb_bits

    pre_mul_reds = 0
    limb_muls_toom = 0
    limb_muls_school = 0
    quot_and_wit_bits = 0
    carry_bits = 0
    out_red_bits = 0
    carry_lin_eqs = 0
    plonk_lookups = 0
    plonk_arith = 0

    max_mul_q_bits = 0
    max_mul_c_bits = 0
    max_out_q_bits = 0
    max_out_c_bits = 0

    for l in range(r):
        u_l1 = max(1, sum(abs(x) for x in schedule.U[l]))
        v_l1 = max(1, sum(abs(y) for y in schedule.V[l]))
        conv_slack = math.ceil(math.log2(max(2, num_limbs * u_l1 * v_l1)))

        eff_u = u_l1
        eff_v = v_l1
        if conv_slack > two_limb_pack_cap:
            # Reduce whichever side(s) exceed half the budget
            half_cap = (two_limb_pack_cap - math.ceil(math.log2(num_limbs))) // 2
            if math.ceil(math.log2(max(1, u_l1))) > half_cap and u_l1 > 1:
                pre_mul_reds += 1
                q_in_b = math.ceil(math.log2(u_l1 + 1))
                c_in_b = q_in_b + 2
                n_in_c = max(1, math.ceil((num_limbs - 1) / 2))
                red_b = num_limbs * limb_bits + q_in_b + n_in_c * c_in_b
                quot_and_wit_bits += num_limbs * limb_bits + q_in_b
                carry_bits += n_in_c * c_in_b
                carry_lin_eqs += n_in_c + 1
                plonk_lookups += (
                    num_limbs * (limb_bits // 16)
                    + math.ceil(q_in_b / 16)
                    + n_in_c * math.ceil(c_in_b / 16)
                )
                plonk_arith += num_limbs + sum(1 for x in schedule.U[l] if x != 0)
                eff_u = 1
            if math.ceil(math.log2(max(1, v_l1))) > half_cap and v_l1 > 1:
                pre_mul_reds += 1
                q_in_b = math.ceil(math.log2(v_l1 + 1))
                c_in_b = q_in_b + 2
                n_in_c = max(1, math.ceil((num_limbs - 1) / 2))
                quot_and_wit_bits += num_limbs * limb_bits + q_in_b
                carry_bits += n_in_c * c_in_b
                carry_lin_eqs += n_in_c + 1
                plonk_lookups += (
                    num_limbs * (limb_bits // 16)
                    + math.ceil(q_in_b / 16)
                    + n_in_c * math.ceil(c_in_b / 16)
                )
                plonk_arith += num_limbs + sum(1 for y in schedule.V[l] if y != 0)
                eff_v = 1

        eff_uv = eff_u * eff_v
        uv_slack = 0 if eff_uv == 1 else math.ceil(math.log2(eff_uv))

        # Bilinear limb multiplication u_l * v_l - m_l = q_l * p
        limb_muls_toom += 2 * num_limbs - 1
        limb_muls_school += num_limbs * num_limbs

        m_bits = num_limbs * limb_bits
        # Quotient |q_l| <= (eff_uv * (p-1)^2 + (p-1)) // p < eff_uv * p => p_bits + uv_slack bits
        q_bits = p_bits + uv_slack
        q_limbs = math.ceil(q_bits / limb_bits)
        max_mul_q_bits = max(max_mul_q_bits, q_bits)

        # Number of 2-limb packed carry words across (num_limbs + q_limbs) limb positions
        total_positions = max(2 * num_limbs - 1, num_limbs + q_limbs - 1)
        n_packed_carries = math.ceil((total_positions - 1) / 2)
        # Each 2-limb packed carry absorbs sum of <= L products of 2^(2*64) * eff_uv plus q*p
        c_bits = limb_bits + math.ceil(math.log2(num_limbs * eff_uv + q_limbs + 1)) + 2
        max_mul_c_bits = max(max_mul_c_bits, c_bits)

        quot_and_wit_bits += m_bits + q_bits
        carry_bits += n_packed_carries * c_bits
        carry_lin_eqs += n_packed_carries + 1
        plonk_lookups += (
            num_limbs * (limb_bits // 16)
            + math.ceil(q_bits / 16)
            + n_packed_carries * math.ceil(c_bits / 16)
        )
        plonk_arith += (2 * num_limbs - 1) + num_limbs + n_packed_carries

    # Output reconstructions: W_z[k] * m - D * c_k = q_W_k * p (k = 0 .. d-1)
    for k in range(d):
        wz_l1 = sum(abs(x) for x in schedule.W_z[k])
        if D == 1 and wz_l1 == 1 and all(x >= 0 for x in schedule.W_z[k]):
            # Identity pass-through wire: 0 extra constraints!
            continue
        c_out_b = num_limbs * limb_bits
        # |W_z[k]*m - D*c_k| <= (wz_l1 + D)*(p - 1) => |q_W_k| < wz_l1 + D
        qw_bits = max(1, math.ceil(math.log2(wz_l1 + D + 1)))
        qw_limbs = math.ceil(qw_bits / limb_bits)
        max_out_q_bits = max(max_out_q_bits, qw_bits)

        # If qw_limbs == 1 (wz_l1 + D < 2^64), q_W_k is a single <=64b scalar,
        # so q_W_k * p_s has <= 128b and 2-limb carry has max(qw_bits, 64) + 3 bits.
        # If qw_limbs >= 2 (e.g. Vandermonde-23 has 113b!), q_W_k spans multiple limbs AND
        # W_z[k][l] constants > 64b must be split into 64b limb chunks!
        const_chunks = math.ceil(max(1, qw_bits) / limb_bits)
        total_w_pos = num_limbs + qw_limbs - 1
        n_w_carries = max(1, math.ceil((total_w_pos - 1) / 2))
        if qw_limbs == 1:
            cw_bits = qw_bits + 3
        else:
            cw_bits = limb_bits + math.ceil(math.log2(qw_limbs + const_chunks + 2)) + (qw_bits - limb_bits) + 3
        max_out_c_bits = max(max_out_c_bits, cw_bits)

        out_red_bits += c_out_b + qw_bits + n_w_carries * cw_bits
        carry_lin_eqs += n_w_carries + const_chunks
        plonk_lookups += (
            num_limbs * (limb_bits // 16)
            + math.ceil(qw_bits / 16)
            + n_w_carries * math.ceil(cw_bits / 16)
        )
        nz_w = sum(1 for x in schedule.W_z[k] if x != 0)
        plonk_arith += nz_w * const_chunks + num_limbs + n_w_carries

    total_range_bits = quot_and_wit_bits + carry_bits + out_red_bits
    groth16_toom = limb_muls_toom + total_range_bits + carry_lin_eqs
    groth16_school = limb_muls_school + total_range_bits + carry_lin_eqs
    plonk_tot = plonk_lookups + plonk_arith

    return EmulatedLimbCost(
        num_limbs=num_limbs,
        limb_bits=limb_bits,
        prime_bits=p_bits,
        base_muls=r,
        pre_mul_reductions=pre_mul_reds,
        limb_muls_toom=limb_muls_toom,
        limb_muls_schoolbook=limb_muls_school,
        quotient_and_witness_bits=quot_and_wit_bits,
        carry_range_bits=carry_bits,
        output_reduction_bits=out_red_bits,
        total_range_check_bits=total_range_bits,
        carry_linear_constraints=carry_lin_eqs,
        groth16_r1cs_total=groth16_toom,
        groth16_r1cs_schoolbook_total=groth16_school,
        plonk_lookup16_gates=plonk_lookups,
        plonk_arith_gates=plonk_arith,
        plonk_total_gates=plonk_tot,
        max_mul_quotient_bits=max_mul_q_bits,
        max_mul_carry_bits=max_mul_c_bits,
        max_out_quotient_bits=max_out_q_bits,
        max_out_carry_bits=max_out_c_bits,
    )


def verify_emulated_witness_bounds(
    schedule: BilinearSchedule,
    a: Sequence[int],
    b: Sequence[int],
    cost: EmulatedLimbCost,
    p: int,
    snark_scalar_limit_bits: int = 252,
) -> Dict[str, int]:
    """Execute actual non-native integer witness & quotient generation on (a, b) and verify
    that EVERY realized integer quotient and limb carry fits strictly inside `cost` bit bounds!

    Raises OverflowError if any quotient or carry exceeds the allocated range-check bit-width
    (enabling adversarial mutation testing of limb-slack bounds!).
    """
    r = schedule.rank
    d = schedule.degree
    L = cost.num_limbs
    w_bits = cost.limb_bits
    base = 1 << w_bits
    two_limb_pack_cap = snark_scalar_limit_bits - 3 * w_bits
    half_cap = (two_limb_pack_cap - math.ceil(math.log2(L))) // 2

    def to_limbs(val: int, n_l: int) -> List[int]:
        mag = abs(val)
        out = []
        for _ in range(n_l):
            out.append(mag & (base - 1))
            mag >>= w_bits
        if mag != 0:
            raise OverflowError(f"Value {val} exceeds {n_l}x{w_bits} limbs")
        return [x if val >= 0 else -x for x in out]

    p_limbs = to_limbs(p, L)
    obs_max_mul_q_bits = 0
    obs_max_mul_c_bits = 0
    obs_max_out_q_bits = 0
    obs_max_out_c_bits = 0

    m_vals = [0] * r
    for l in range(r):
        u_l1 = max(1, sum(abs(x) for x in schedule.U[l]))
        v_l1 = max(1, sum(abs(y) for y in schedule.V[l]))
        conv_slack = math.ceil(math.log2(max(2, L * u_l1 * v_l1)))

        u_int = sum(schedule.U[l][i] * a[i] for i in range(d))
        v_int = sum(schedule.V[l][j] * b[j] for j in range(d))

        if conv_slack > two_limb_pack_cap:
            if math.ceil(math.log2(max(1, u_l1))) > half_cap and u_l1 > 1:
                u_int = u_int % p
            if math.ceil(math.log2(max(1, v_l1))) > half_cap and v_l1 > 1:
                v_int = v_int % p

        m_l = (u_int * v_int) % p
        m_vals[l] = m_l
        diff = u_int * v_int - m_l
        assert diff % p == 0
        q_l = diff // p
        q_b = 0 if q_l == 0 else abs(q_l).bit_length()
        obs_max_mul_q_bits = max(obs_max_mul_q_bits, q_b)
        if q_b > cost.max_mul_quotient_bits:
            raise OverflowError(
                f"Mul quotient overflow at l={l}: {q_b}b > allocated {cost.max_mul_quotient_bits}b"
            )

        # Check limb-level carries of u_limbs * v_limbs - m_limbs - q_limbs * p_limbs == 0
        u_limbs = [sum(schedule.U[l][i] * ((a[i] >> (s * w_bits)) & (base - 1)) for i in range(d)) for s in range(L)]
        v_limbs = [sum(schedule.V[l][j] * ((b[j] >> (s * w_bits)) & (base - 1)) for j in range(d)) for s in range(L)]
        if conv_slack > two_limb_pack_cap:
            if math.ceil(math.log2(max(1, u_l1))) > half_cap and u_l1 > 1:
                u_limbs = to_limbs(u_int, L)
            if math.ceil(math.log2(max(1, v_l1))) > half_cap and v_l1 > 1:
                v_limbs = to_limbs(v_int, L)
        m_limbs = to_limbs(m_l, L)
        q_limbs_cnt = max(1, math.ceil(max(1, cost.max_mul_quotient_bits) / w_bits))
        q_limbs = to_limbs(q_l, q_limbs_cnt)

        tot_pos = max(2 * L - 1, L + q_limbs_cnt - 1)
        coeffs = [0] * tot_pos
        for i_u in range(L):
            for j_v in range(L):
                coeffs[i_u + j_v] += u_limbs[i_u] * v_limbs[j_v]
        for s in range(L):
            coeffs[s] -= m_limbs[s]
        for iq in range(q_limbs_cnt):
            for ip in range(L):
                coeffs[iq + ip] -= q_limbs[iq] * p_limbs[ip]

        carry = 0
        pos = 0
        while pos < tot_pos:
            val0 = coeffs[pos] + carry
            if pos + 1 < tot_pos:
                combined = val0 + coeffs[pos + 1] * base
                assert combined % (base * base) == 0
                carry = combined // (base * base)
                pos += 2
            else:
                assert val0 % base == 0
                carry = val0 // base
                pos += 1
            cb = 0 if carry == 0 else abs(carry).bit_length()
            obs_max_mul_c_bits = max(obs_max_mul_c_bits, cb)
            if cb > cost.max_mul_carry_bits:
                raise OverflowError(
                    f"Mul 2-limb carry overflow at l={l}: {cb}b > allocated {cost.max_mul_carry_bits}b"
                )
        assert carry == 0

    inv_d = pow(schedule.D, p - 2, p)
    for k in range(d):
        wz_l1 = sum(abs(x) for x in schedule.W_z[k])
        if schedule.D == 1 and wz_l1 == 1 and all(x >= 0 for x in schedule.W_z[k]):
            continue
        lhs_m = sum(schedule.W_z[k][l] * m_vals[l] for l in range(r))
        c_k = ((lhs_m % p) * inv_d) % p
        diff_w = lhs_m - schedule.D * c_k
        assert diff_w % p == 0
        qw = diff_w // p
        qwb = 0 if qw == 0 else abs(qw).bit_length()
        obs_max_out_q_bits = max(obs_max_out_q_bits, qwb)
        if qwb > cost.max_out_quotient_bits:
            raise OverflowError(
                f"Output quotient overflow at k={k}: {qwb}b > allocated {cost.max_out_quotient_bits}b"
            )

        # Verify output limb carries
        c_limbs = to_limbs(c_k, L)
        qw_limbs_cnt = max(1, math.ceil(max(1, cost.max_out_quotient_bits) / w_bits))
        qw_limbs = to_limbs(qw, qw_limbs_cnt)
        tot_w = L + qw_limbs_cnt - 1
        w_coeffs = [0] * tot_w
        for s in range(L):
            m_s_sum = sum(
                schedule.W_z[k][l] * ((m_vals[l] >> (s * w_bits)) & (base - 1))
                for l in range(r)
            )
            w_coeffs[s] += m_s_sum - schedule.D * c_limbs[s]
        for iq in range(qw_limbs_cnt):
            for ip in range(L):
                w_coeffs[iq + ip] -= qw_limbs[iq] * p_limbs[ip]

        carry_w = 0
        pos = 0
        while pos < tot_w:
            v0 = w_coeffs[pos] + carry_w
            if pos + 1 < tot_w:
                comb = v0 + w_coeffs[pos + 1] * base
                assert comb % (base * base) == 0
                carry_w = comb // (base * base)
                pos += 2
            else:
                assert v0 % base == 0
                carry_w = v0 // base
                pos += 1
            cwb = 0 if carry_w == 0 else abs(carry_w).bit_length()
            obs_max_out_c_bits = max(obs_max_out_c_bits, cwb)
            if cwb > cost.max_out_carry_bits:
                raise OverflowError(
                    f"Output carry overflow at k={k}: {cwb}b > allocated {cost.max_out_carry_bits}b"
                )
        assert carry_w == 0

    return {
        "obs_max_mul_q_bits": obs_max_mul_q_bits,
        "obs_max_mul_c_bits": obs_max_mul_c_bits,
        "obs_max_out_q_bits": obs_max_out_q_bits,
        "obs_max_out_c_bits": obs_max_out_c_bits,
    }


def evaluate_full_cost(schedule: BilinearSchedule) -> FullScheduleCost:
    spec = EXTENSION_SPECS[schedule.target_name]
    nat = compute_native_cost(schedule, spec)
    emu: Optional[EmulatedLimbCost] = None
    if spec.emulated_limbs is not None:
        num_l, l_bits = spec.emulated_limbs
        emu = compute_emulated_limb_cost(schedule, num_l, l_bits, spec.prime)
    return FullScheduleCost(
        schedule_name=schedule.name,
        target_name=schedule.target_name,
        rank=schedule.rank,
        d_bits=round(math.log2(schedule.D), 2),
        max_uv_slack_bits=schedule.actual_limb_slack_bits,
        native=nat,
        emulated=emu,
    )
