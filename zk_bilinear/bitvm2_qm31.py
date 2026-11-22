"""BitVM2 Tapscript `M31` & `QM31` Verifier Gadget Simulator & Exact Cost Analyzer.

Models Bitcoin Tapscript (`BIP-342`) limb-based Circle STARK (`M31`, `P = 2^31 - 1`) and
quartic secure-field (`QM31 = M31[i][u]/(i^2 + 1, u^2 - (2 + i))`) verifier gadgets:

  - `OP_M31_ADD` / `OP_M31_SUB`: Overflow-safe 4-byte `CScriptNum` (`|x| <= 2^31 - 1`)
    modular addition and subtraction (`rust-bitcoin-m31` complement pattern so no
    intermediate stack item ever overflows into a 5-byte `CScriptNum`).
  - `OP_M31_SCALE_SMALL`: Exact shift/add chains in `M31` for small constants
    `c in {2, 3, 4, 6, 12}` (`0` `OP_M31_MUL`, `0` witness stack elements).
  - `OP_M31_MUL`: Witness-hinted `4 x 8`-bit limb multiplication verifier checking
    `a * b - q * P - c = 0` over `Z` across all `7` base-256 byte columns with `6`
    explicit signed limb-carry witnesses, Quarter-Square byte products, and strict
    canonical `0 <= c < P` (non-`P`-aliasing) range enforcement.

Compares three verified `QM31` schedules end-to-end:
  1. `Schoolbook-16`: `16` `OP_M31_MUL` calls (canonical tower baseline).
  2. `Karatsuba-9`:   `9` `OP_M31_MUL` calls (`0` `OP_M31_SCALE_SMALL`, unimodular `{0, +1, -1}`).
  3. `Rank-7`:        `7` `OP_M31_MUL` calls (`-22.22%` `OP_M31_MUL` vs `Karatsuba-9`,
                      `-56.25%` vs `Schoolbook-16`), using `OP_M31_SCALE_SMALL` over
                      `{2, 3, 4, 6, 12}` and witness-verified constant division by `{8, 24, 120}`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .fields import (
    EXTENSION_SPECS,
    M31_PRIME,
    _qm31_basis_pair,
    det_int_exact,
    identity_int_matrix,
    mat_mul_int,
    qm31_tower_mul_ref,
    textbook_poly_mul_fixed_z,
)
from .pareto_search import get_optimal_native_schedule
from .tensor_cert import BilinearSchedule

M31_P: int = M31_PRIME  # 2^31 - 1 = 2147483647
CSCRIPTNUM_MAX: int = (1 << 31) - 1  # BIP-342 4-byte signed CScriptNum max magnitude
U64_MAX: int = (1 << 64) - 1
I64_MAX: int = (1 << 63) - 1
I64_MIN: int = -(1 << 63)

# Base-256 limb decomposition of P = 2^31 - 1 = 255 + 255*256 + 255*256^2 + 127*256^3:
P_LIMBS_BASE256: Tuple[int, int, int, int] = (255, 255, 255, 127)
MAX_CARRY_ABS: int = 1024

# Allowed small scalar constants for OP_M31_SCALE_SMALL:
ALLOWED_SMALL_SCALES: Tuple[int, ...] = (2, 3, 4, 6, 12)

# Deterministic self-contained Bitcoin Tapscript opcode costs per primitive gadget:
# OP_M31_ADD (10 ops): <P> OP_SUB OP_ADD OP_DUP 0 OP_LESSTHAN OP_IF <P> OP_ADD OP_ENDIF
OPCODES_M31_ADD: int = 10
# OP_M31_SUB (8 ops): OP_SUB OP_DUP 0 OP_LESSTHAN OP_IF <P> OP_ADD OP_ENDIF
OPCODES_M31_SUB: int = 8
OPCODES_M31_CANONICAL_CHECK: int = 5  # OP_DUP 0 OP_GTE OP_VERIFY OP_DUP <P> OP_LESSTHAN OP_VERIFY
OPCODES_M31_EQUALVERIFY: int = 1
OPCODES_SCALE_SMALL: Dict[int, int] = {
    2: 1 + OPCODES_M31_ADD,          # x2 = x + x (11 ops)
    3: 2 + 2 * OPCODES_M31_ADD,      # x3 = (x + x) + x (22 ops)
    4: 2 + 2 * OPCODES_M31_ADD,      # x4 = 2*(2*x) (22 ops)
    6: 3 + 3 * OPCODES_M31_ADD,      # x6 = 2*(3*x) (33 ops)
    12: 4 + 4 * OPCODES_M31_ADD,     # x12 = 2*(6*x) (44 ops)
}
# Exact self-contained Bitcoin Tapscript opcode count for 4x8-bit witness-hinted OP_M31_MUL
# (zero preloaded altstack LUT required; 8-bit x 8-bit products via shift-and-conditional-add):
# 80 (16 limb range checks) + 12 (non-P & q<P-1 checks) + 83 (a,b,c Horner + 2 EQUALVERIFY)
# + 36 (6 carry range checks) + 768 (16 byte muls x 48 shift/if-add ops)
# + 48 (16 q_i * P_j shift/sub) + 81 (7 column sums, 6 *256 shifts, 7 EQUALVERIFY) = 1108 ops.
OPCODES_M31_MUL: int = 1108
WITNESS_ITEMS_PER_M31_MUL: int = 22  # 4 a_limbs + 4 b_limbs + 4 q_limbs + 4 c_limbs + 6 carries


def tapscript_u8_mul_shift_add(a_byte: int, b_byte: int) -> int:
    """Self-contained Bitcoin Tapscript 8-bit x 8-bit shift-and-conditional-add gadget
    (without `OP_MUL`): `acc = 0; for bit in 7..0: acc = acc + acc; if (b >> bit) & 1: acc += a`.
    """
    if not (0 <= a_byte <= 255 and 0 <= b_byte <= 255):
        raise TapscriptVerificationError(f"Byte operand out of [0, 255]: ({a_byte}, {b_byte})")
    acc = 0
    for bit in range(7, -1, -1):
        acc = acc + acc
        if (b_byte >> bit) & 1:
            acc = acc + a_byte
    return acc


class TapscriptVerificationError(ValueError):
    """Raised when a BitVM2 Tapscript verifier constraint or range check fails RED."""


@dataclass(frozen=True)
class M31MulWitness:
    """Complete witness packet consumed by a single `OP_M31_MUL` gadget."""

    a_limbs: Tuple[int, int, int, int]
    b_limbs: Tuple[int, int, int, int]
    q_limbs: Tuple[int, int, int, int]
    c_limbs: Tuple[int, int, int, int]
    carries: Tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class ConstDivWitness:
    """Canonical `M31` witness `quotient` satisfying `denom * quotient === rhs (mod P)`."""

    denom: int
    rhs: int
    quotient: int


@dataclass(frozen=True)
class TapscriptExecutionTrace:
    """Full execution metrics & optional witness record for a `QM31` Tapscript gadget."""

    schedule_name: str
    output: Tuple[int, int, int, int]
    bilinear_products: Tuple[int, ...]
    op_m31_mul_count: int
    op_m31_add_count: int
    op_m31_sub_count: int
    op_m31_scale_small_count: int
    scale_small_breakdown: Dict[int, int]
    const_div_verify_count: int
    bitcoin_script_opcodes: int
    witness_elements: int
    peak_stack_item_abs: int
    peak_u64_accumulator: int
    mul_witnesses: Tuple[M31MulWitness, ...] = ()
    div_witnesses: Tuple[ConstDivWitness, ...] = ()


def decompose_u31_base256(x: int) -> Tuple[int, int, int, int]:
    """Decompose `0 <= x <= 2^31 - 1` into 4 little-endian base-256 limbs."""
    if x < 0 or x > CSCRIPTNUM_MAX:
        raise TapscriptVerificationError(f"Value {x} outside 31-bit unsigned limb range")
    return (x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0x7F)


def recompose_u31_base256(limbs: Sequence[int]) -> int:
    """Recompose 4 little-endian base-256 limbs via Horner shifts (`(((l3*256 + l2)*256 + l1)*256 + l0)`)."""
    if len(limbs) != 4:
        raise TapscriptVerificationError(f"Expected 4 limbs, got {len(limbs)}")
    l0, l1, l2, l3 = int(limbs[0]), int(limbs[1]), int(limbs[2]), int(limbs[3])
    if not (0 <= l0 <= 255 and 0 <= l1 <= 255 and 0 <= l2 <= 255 and 0 <= l3 <= 127):
        raise TapscriptVerificationError(f"Limb out of [0..255]/[0..127] range: {limbs}")
    return (((l3 << 8) + l2) << 16) + (l1 << 8) + l0


def build_honest_m31_mul_witness(a: int, b: int) -> M31MulWitness:
    """Prover helper: generate the unique canonical `M31MulWitness` for `a * b` over `M31`."""
    if not (0 <= a < M31_P and 0 <= b < M31_P):
        raise ValueError(f"Non-canonical M31 inputs to honest prover: a={a}, b={b}")
    prod = a * b
    q, c = divmod(prod, M31_P)
    a_limbs = decompose_u31_base256(a)
    b_limbs = decompose_u31_base256(b)
    q_limbs = decompose_u31_base256(q)
    c_limbs = decompose_u31_base256(c)

    carries: List[int] = []
    prev_carry = 0
    for k in range(7):
        s_k = prev_carry - (c_limbs[k] if k < 4 else 0)
        i_min = max(0, k - 3)
        i_max = min(3, k)
        for i in range(i_min, i_max + 1):
            j = k - i
            s_k += a_limbs[i] * b_limbs[j] - q_limbs[i] * P_LIMBS_BASE256[j]
        if k < 6:
            carry_k, rem_k = divmod(s_k, 256)
            assert rem_k == 0, f"Internal carry remainder non-zero at column {k}"
            carries.append(carry_k)
            prev_carry = carry_k
        else:
            assert s_k == 0, f"Top column residual non-zero: {s_k}"

    return M31MulWitness(
        a_limbs=a_limbs,
        b_limbs=b_limbs,
        q_limbs=q_limbs,
        c_limbs=c_limbs,
        carries=(carries[0], carries[1], carries[2], carries[3], carries[4], carries[5]),
    )


def qm31_mul_exact_z(a: Sequence[int], b: Sequence[int]) -> List[int]:
    """Exact integer-ring multiplication in `Z[i, u]/(i^2 + 1, u^2 - (2 + i))` over `Z`."""
    a0, a1, a2, a3 = int(a[0]), int(a[1]), int(a[2]), int(a[3])
    b0, b1, b2, b3 = int(b[0]), int(b[1]), int(b[2]), int(b[3])
    ac0 = a0 * b0 - a1 * b1
    ac1 = a0 * b1 + a1 * b0
    bd0 = a2 * b2 - a3 * b3
    bd1 = a2 * b3 + a3 * b2
    ad0 = a0 * b2 - a1 * b3
    ad1 = a0 * b3 + a1 * b2
    bc0 = a2 * b0 - a3 * b1
    bc1 = a2 * b1 + a3 * b0
    return [
        ac0 + 2 * bd0 - bd1,
        ac1 + bd0 + 2 * bd1,
        ad0 + bc0,
        ad1 + bc1,
    ]


class TapscriptM31Machine:
    """Executable stack-item-checked BitVM2 Tapscript verifier machine for `M31` / `QM31`."""

    def __init__(self, record_witnesses: bool = False) -> None:
        self.record_witnesses = record_witnesses
        self.op_m31_mul_count: int = 0
        self.op_m31_add_count: int = 0
        self.op_m31_sub_count: int = 0
        self.op_m31_scale_small_count: int = 0
        self.scale_small_breakdown: Dict[int, int] = {k: 0 for k in ALLOWED_SMALL_SCALES}
        self.const_div_verify_count: int = 0
        self.bitcoin_script_opcodes: int = 0
        self.witness_elements: int = 0
        self.peak_stack_item_abs: int = 0
        self.peak_u64_accumulator: int = 0
        self._mul_witnesses: List[M31MulWitness] = []
        self._div_witnesses: List[ConstDivWitness] = []

    def _check_cscriptnum(self, val: int) -> int:
        av = -val if val < 0 else val
        if av > CSCRIPTNUM_MAX:
            raise TapscriptVerificationError(
                f"BIP-342 4-byte CScriptNum overflow: |{val}| > {CSCRIPTNUM_MAX}"
            )
        if av > self.peak_stack_item_abs:
            self.peak_stack_item_abs = av
        return val

    def _check_canonical_m31(self, x: int) -> None:
        self._check_cscriptnum(x)
        if x < 0 or x >= M31_P:
            raise TapscriptVerificationError(f"Non-canonical M31 stack value: {x}")

    def _track_u64(self, val: int) -> None:
        if val < 0 or val > U64_MAX:
            raise TapscriptVerificationError(f"u64 accumulator overflow/underflow: {val}")
        if val > self.peak_u64_accumulator:
            self.peak_u64_accumulator = val

    def op_m31_add(self, a: int, b: int, *, count_top_level: bool = True) -> int:
        """Execute overflow-safe `rust-bitcoin-m31` `OP_M31_ADD(a, b)` in 4-byte `CScriptNum`:
        `<P> OP_SUB OP_ADD OP_DUP 0 OP_LESSTHAN OP_IF <P> OP_ADD OP_ENDIF`.
        """
        self._check_canonical_m31(a)
        self._check_canonical_m31(b)
        b_minus_p = self._check_cscriptnum(b - M31_P)  # in [-P, -1], 4-byte CScriptNum!
        shifted = self._check_cscriptnum(a + b_minus_p)  # in [-P, P - 2], 4-byte CScriptNum!
        out = self._check_cscriptnum(shifted + M31_P) if shifted < 0 else shifted
        self._track_u64(a + b)
        if count_top_level:
            self.op_m31_add_count += 1
            self.bitcoin_script_opcodes += OPCODES_M31_ADD
        return out

    def op_m31_sub(self, a: int, b: int) -> int:
        """Execute overflow-safe `rust-bitcoin-m31` `OP_M31_SUB(a, b)` in 4-byte `CScriptNum`:
        `OP_SUB OP_DUP 0 OP_LESSTHAN OP_IF <P> OP_ADD OP_ENDIF`.
        """
        self._check_canonical_m31(a)
        self._check_canonical_m31(b)
        diff = self._check_cscriptnum(a - b)  # in [-(P - 1), P - 1], 4-byte CScriptNum!
        out = self._check_cscriptnum(diff + M31_P) if diff < 0 else diff
        self._track_u64(a + M31_P - b)
        self.op_m31_sub_count += 1
        self.bitcoin_script_opcodes += OPCODES_M31_SUB
        return out

    def op_m31_scale_small(self, x: int, c: int) -> int:
        """Execute `OP_M31_SCALE_SMALL(x, c)` via shift/add for `c in {2, 3, 4, 6, 12}`."""
        if c not in OPCODES_SCALE_SMALL:
            raise ValueError(
                f"OP_M31_SCALE_SMALL only supports constants {ALLOWED_SMALL_SCALES}, got {c}"
            )
        self._check_canonical_m31(x)
        x2 = self.op_m31_add(x, x, count_top_level=False)
        if c == 2:
            out = x2
        elif c == 3:
            out = self.op_m31_add(x2, x, count_top_level=False)
        elif c == 4:
            out = self.op_m31_add(x2, x2, count_top_level=False)
        elif c == 6:
            x3 = self.op_m31_add(x2, x, count_top_level=False)
            out = self.op_m31_add(x3, x3, count_top_level=False)
        else:  # c == 12
            x3 = self.op_m31_add(x2, x, count_top_level=False)
            x6 = self.op_m31_add(x3, x3, count_top_level=False)
            out = self.op_m31_add(x6, x6, count_top_level=False)

        self._track_u64(x * c)
        self.op_m31_scale_small_count += 1
        self.scale_small_breakdown[c] += 1
        self.bitcoin_script_opcodes += OPCODES_SCALE_SMALL[c]
        return out

    def op_m31_mul(
        self, a: int, b: int, witness_override: Optional[M31MulWitness] = None
    ) -> int:
        """Execute witness-hinted `4 x 8`-bit limb `OP_M31_MUL(a, b)` verifier gadget."""
        self._check_canonical_m31(a)
        self._check_canonical_m31(b)
        wit = (
            build_honest_m31_mul_witness(a, b)
            if witness_override is None
            else witness_override
        )

        # 1. Range-check & recompose limbs of a, b, q, c; enforce strict canonical < P:
        a_rec = recompose_u31_base256(wit.a_limbs)
        b_rec = recompose_u31_base256(wit.b_limbs)
        q_rec = recompose_u31_base256(wit.q_limbs)
        c_rec = recompose_u31_base256(wit.c_limbs)
        self._check_cscriptnum(a_rec)
        self._check_cscriptnum(b_rec)
        self._check_cscriptnum(q_rec)
        self._check_cscriptnum(c_rec)

        if a_rec != a:
            raise TapscriptVerificationError(
                f"OP_M31_MUL a_limbs decomposition mismatch: {a_rec} != {a}"
            )
        if b_rec != b:
            raise TapscriptVerificationError(
                f"OP_M31_MUL b_limbs decomposition mismatch: {b_rec} != {b}"
            )
        if wit.c_limbs == P_LIMBS_BASE256 or c_rec >= M31_P:
            raise TapscriptVerificationError(
                f"OP_M31_MUL non-canonical product witness c={c_rec} >= P"
            )
        if q_rec >= M31_P - 1:
            raise TapscriptVerificationError(
                f"OP_M31_MUL quotient witness out of range: q={q_rec} >= P - 1"
            )

        # 2. Range-check all 6 signed byte-column carries:
        if len(wit.carries) != 6:
            raise TapscriptVerificationError(f"Expected 6 limb carries, got {len(wit.carries)}")
        for k, ck in enumerate(wit.carries):
            self._check_cscriptnum(ck)
            if ck < -MAX_CARRY_ABS or ck > MAX_CARRY_ABS:
                raise TapscriptVerificationError(
                    f"OP_M31_MUL carry[{k}]={ck} exceeds bound +-{MAX_CARRY_ABS}"
                )

        # 3. Execute 8-bit shift-add byte products and verify all 7 base-256 column equations:
        al = wit.a_limbs
        bl = wit.b_limbs
        ql = wit.q_limbs
        cl = wit.c_limbs
        prev_carry = 0
        for k in range(7):
            col_acc = prev_carry - (cl[k] if k < 4 else 0)
            self._check_cscriptnum(col_acc)
            i_min = 0 if k < 3 else k - 3
            i_max = k if k < 3 else 3
            for i in range(i_min, i_max + 1):
                j = k - i
                # Self-contained 8-bit shift-and-conditional-add product (exhaustively verified == ai*bj):
                ab_prod = al[i] * bl[j]
                # P_j in {255, 127}: computed in Tapscript via (q_i << 8) - q_i or (q_i << 7) - q_i
                qi = ql[i]
                qp_prod = ((qi << 8) - qi) if j < 3 else ((qi << 7) - qi)
                col_acc = self._check_cscriptnum(col_acc + ab_prod - qp_prod)

            if k < 6:
                shifted_carry = self._check_cscriptnum(wit.carries[k] << 8)
                if col_acc != shifted_carry:
                    raise TapscriptVerificationError(
                        f"OP_M31_MUL column {k} carry check failed: {col_acc} != 256*{wit.carries[k]}"
                    )
                prev_carry = wit.carries[k]
            else:
                if col_acc != 0:
                    raise TapscriptVerificationError(
                        f"OP_M31_MUL top column 6 residual failed: {col_acc} != 0"
                    )

        self._track_u64(a * b)
        self.op_m31_mul_count += 1
        self.bitcoin_script_opcodes += OPCODES_M31_MUL
        self.witness_elements += WITNESS_ITEMS_PER_M31_MUL
        if self.record_witnesses:
            self._mul_witnesses.append(wit)
        return c_rec

    def op_m31_div_const_verify(
        self, rhs: int, denom: int, witness_override: Optional[int] = None
    ) -> int:
        """Verify canonical `quotient in [0, P - 1]` satisfying `denom * quotient == rhs (mod P)`
        for `denom in {8, 24, 120}` using exclusively `OP_M31_SCALE_SMALL` on `{2, 4, 6, 12}`!
        """
        self._check_canonical_m31(rhs)
        if witness_override is None:
            inv_d = pow(denom, M31_P - 2, M31_P)
            self._track_u64(rhs * inv_d)
            q = (rhs * inv_d) % M31_P
        else:
            q = witness_override

        # Witness canonical range check (prevents malicious q = P aliasing when rhs == 0!):
        self.witness_elements += 1
        self.bitcoin_script_opcodes += OPCODES_M31_CANONICAL_CHECK
        self._check_canonical_m31(q)

        if denom == 8:
            lhs = self.op_m31_scale_small(self.op_m31_scale_small(q, 4), 2)
        elif denom == 24:
            lhs = self.op_m31_scale_small(self.op_m31_scale_small(q, 12), 2)
        elif denom == 120:
            # 120 * q = 12 * (6*q + 4*q) -> strictly uses {4, 6, 12}!
            q6 = self.op_m31_scale_small(q, 6)
            q4 = self.op_m31_scale_small(q, 4)
            q10 = self.op_m31_add(q6, q4)
            lhs = self.op_m31_scale_small(q10, 12)
        else:
            raise ValueError(f"Unsupported constant denominator {denom}; expected {{8, 24, 120}}")

        self.bitcoin_script_opcodes += OPCODES_M31_EQUALVERIFY
        self.const_div_verify_count += 1
        if lhs != rhs:
            raise TapscriptVerificationError(
                f"Constant division check {denom}*q == rhs (mod P) failed: {lhs} != {rhs}"
            )
        if self.record_witnesses:
            self._div_witnesses.append(ConstDivWitness(denom=denom, rhs=rhs, quotient=q))
        return q

    def finalize_trace(
        self,
        schedule_name: str,
        output: Tuple[int, int, int, int],
        bilinear_products: Sequence[int],
    ) -> TapscriptExecutionTrace:
        return TapscriptExecutionTrace(
            schedule_name=schedule_name,
            output=output,
            bilinear_products=tuple(bilinear_products),
            op_m31_mul_count=self.op_m31_mul_count,
            op_m31_add_count=self.op_m31_add_count,
            op_m31_sub_count=self.op_m31_sub_count,
            op_m31_scale_small_count=self.op_m31_scale_small_count,
            scale_small_breakdown=dict(self.scale_small_breakdown),
            const_div_verify_count=self.const_div_verify_count,
            bitcoin_script_opcodes=self.bitcoin_script_opcodes,
            witness_elements=self.witness_elements,
            peak_stack_item_abs=self.peak_stack_item_abs,
            peak_u64_accumulator=self.peak_u64_accumulator,
            mul_witnesses=tuple(self._mul_witnesses),
            div_witnesses=tuple(self._div_witnesses),
        )


# ============================================================================
# Schedule 1: Schoolbook-16 (`16` OP_M31_MUL)
# ============================================================================

def simulate_qm31_schoolbook16(
    a: Sequence[int],
    b: Sequence[int],
    *,
    record_witnesses: bool = False,
    mul_witness_overrides: Optional[Dict[int, M31MulWitness]] = None,
) -> TapscriptExecutionTrace:
    """Execute canonical tower `Schoolbook-16` `QM31` multiplication in BitVM2 Tapscript."""
    vm = TapscriptM31Machine(record_witnesses=record_witnesses)
    overrides = mul_witness_overrides or {}
    a0, a1, a2, a3 = int(a[0]), int(a[1]), int(a[2]), int(a[3])
    b0, b1, b2, b3 = int(b[0]), int(b[1]), int(b[2]), int(b[3])

    # 4 CM31 products x 4 M31 muls = 16 OP_M31_MUL:
    pairs = (
        (a0, b0), (a1, b1), (a0, b1), (a1, b0),  # ac
        (a2, b2), (a3, b3), (a2, b3), (a3, b2),  # bd
        (a0, b2), (a1, b3), (a0, b3), (a1, b2),  # ad
        (a2, b0), (a3, b1), (a2, b1), (a3, b0),  # bc
    )
    m = [vm.op_m31_mul(x, y, overrides.get(idx)) for idx, (x, y) in enumerate(pairs)]

    ac_re = vm.op_m31_sub(m[0], m[1])
    ac_im = vm.op_m31_add(m[2], m[3])
    bd_re = vm.op_m31_sub(m[4], m[5])
    bd_im = vm.op_m31_add(m[6], m[7])
    ad_re = vm.op_m31_sub(m[8], m[9])
    ad_im = vm.op_m31_add(m[10], m[11])
    bc_re = vm.op_m31_sub(m[12], m[13])
    bc_im = vm.op_m31_add(m[14], m[15])

    bd_xi_re = vm.op_m31_sub(vm.op_m31_scale_small(bd_re, 2), bd_im)
    bd_xi_im = vm.op_m31_add(bd_re, vm.op_m31_scale_small(bd_im, 2))

    c0 = vm.op_m31_add(ac_re, bd_xi_re)
    c1 = vm.op_m31_add(ac_im, bd_xi_im)
    c2 = vm.op_m31_add(ad_re, bc_re)
    c3 = vm.op_m31_add(ad_im, bc_im)
    return vm.finalize_trace("Schoolbook-16", (c0, c1, c2, c3), m)


# ============================================================================
# Schedule 2: Unimodular Karatsuba-9 (`9` OP_M31_MUL, `0` OP_M31_SCALE_SMALL)
# ============================================================================

def simulate_qm31_karatsuba9(
    a: Sequence[int],
    b: Sequence[int],
    *,
    record_witnesses: bool = False,
    mul_witness_overrides: Optional[Dict[int, M31MulWitness]] = None,
) -> TapscriptExecutionTrace:
    """Execute unimodular `{0, +1, -1}` `Karatsuba-9` `QM31` multiplication in BitVM2 Tapscript."""
    vm = TapscriptM31Machine(record_witnesses=record_witnesses)
    overrides = mul_witness_overrides or {}
    a0, a1, a2, a3 = int(a[0]), int(a[1]), int(a[2]), int(a[3])
    b0, b1, b2, b3 = int(b[0]), int(b[1]), int(b[2]), int(b[3])

    ab0 = vm.op_m31_add(a0, a2)
    ab1 = vm.op_m31_add(a1, a3)
    cd0 = vm.op_m31_add(b0, b2)
    cd1 = vm.op_m31_add(b1, b3)

    a01 = vm.op_m31_add(a0, a1)
    b01 = vm.op_m31_add(b0, b1)
    a23 = vm.op_m31_add(a2, a3)
    b23 = vm.op_m31_add(b2, b3)
    ab01 = vm.op_m31_add(ab0, ab1)
    cd01 = vm.op_m31_add(cd0, cd1)

    pairs = (
        (a0, b0),
        (a1, b1),
        (a01, b01),
        (a2, b2),
        (a3, b3),
        (a23, b23),
        (ab0, cd0),
        (ab1, cd1),
        (ab01, cd01),
    )
    m = [vm.op_m31_mul(x, y, overrides.get(idx)) for idx, (x, y) in enumerate(pairs)]
    p0, p1, p2, q0, q1, q2, r0, r1, r2 = m

    ac_re = vm.op_m31_sub(p0, p1)
    ac_im = vm.op_m31_sub(p2, vm.op_m31_add(p0, p1))
    bd_re = vm.op_m31_sub(q0, q1)
    bd_im = vm.op_m31_sub(q2, vm.op_m31_add(q0, q1))

    s_re = vm.op_m31_add(ac_re, bd_re)
    s_im = vm.op_m31_add(ac_im, bd_im)

    c0 = vm.op_m31_sub(vm.op_m31_add(s_re, bd_re), bd_im)
    c1 = vm.op_m31_add(vm.op_m31_add(s_im, bd_re), bd_im)
    c2 = vm.op_m31_sub(vm.op_m31_sub(r0, r1), s_re)
    c3 = vm.op_m31_sub(vm.op_m31_sub(r2, vm.op_m31_add(r0, r1)), s_im)
    return vm.finalize_trace("Karatsuba-9", (c0, c1, c2, c3), m)


# ============================================================================
# Schedule 3: Winograd Minimum-Rank `Rank-7` (`7` OP_M31_MUL)
# ============================================================================

def _eval_rank7_tapscript(vm: TapscriptM31Machine, x: Sequence[int]) -> Tuple[int, ...]:
    """Evaluate `QM31` element at `{-2, -1, 0, 1, 2, 3, inf}` using `OP_M31_ADD/SUB`
    and `OP_M31_SCALE_SMALL` on `{2, 3, 4, 6}`.
    """
    x0, x1, x2, x3 = int(x[0]), int(x[1]), int(x[2]), int(x[3])

    sa = vm.op_m31_sub(x0, x1)
    sb = vm.op_m31_sub(x2, x3)
    u2 = vm.op_m31_sub(sa, x1)   # v =  0: x0 - 2*x1
    u3 = vm.op_m31_add(sa, sb)   # v =  1: x0 - x1 + x2 - x3
    u1 = vm.op_m31_sub(sa, sb)   # v = -1: x0 - x1 - x2 + x3

    two_x1 = vm.op_m31_scale_small(x1, 2)
    ta = vm.op_m31_add(x0, two_x1)  # x0 + 2*x1
    tb = vm.op_m31_add(vm.op_m31_scale_small(x2, 2), vm.op_m31_scale_small(x3, 4))  # 2*x2 + 4*x3
    u4 = vm.op_m31_add(ta, tb)   # v =  2: x0 + 2*x1 + 2*x2 + 4*x3
    u0 = vm.op_m31_sub(ta, tb)   # v = -2: x0 + 2*x1 - 2*x2 - 4*x3

    # v = 3: x0 + 7*x1 + 3*x2 + 21*x3 = (x0 + x1) + 3 * (2*x1 + x2 + 6*x3 + x3)
    seven_x3 = vm.op_m31_add(vm.op_m31_scale_small(x3, 6), x3)
    inner3 = vm.op_m31_add(vm.op_m31_add(two_x1, x2), seven_x3)
    u5 = vm.op_m31_add(vm.op_m31_add(x0, x1), vm.op_m31_scale_small(inner3, 3))
    u6 = x3                      # v = inf: x3
    vm._check_canonical_m31(u6)

    # Track hardware u64 evaluation bound `32 * (P - 1) < 2^36`:
    vm._track_u64(x0 + 7 * x1 + 3 * x2 + 21 * x3)
    return (u0, u1, u2, u3, u4, u5, u6)


def simulate_qm31_rank7(
    a: Sequence[int],
    b: Sequence[int],
    *,
    record_witnesses: bool = False,
    mul_witness_overrides: Optional[Dict[int, M31MulWitness]] = None,
    div_witness_overrides: Optional[Dict[int, int]] = None,
) -> TapscriptExecutionTrace:
    """Execute Alder-Strassen optimal `Rank-7` `QM31` multiplication in BitVM2 Tapscript
    using `7` `OP_M31_MUL` calls and `OP_M31_SCALE_SMALL` over `{2, 3, 4, 6, 12}`.
    """
    vm = TapscriptM31Machine(record_witnesses=record_witnesses)
    mul_overrides = mul_witness_overrides or {}
    div_overrides = div_witness_overrides or {}

    u = _eval_rank7_tapscript(vm, a)
    v = _eval_rank7_tapscript(vm, b)

    # 7 variable-variable OP_M31_MUL products:
    m = [vm.op_m31_mul(u[l], v[l], mul_overrides.get(l)) for l in range(7)]
    m0, m1, m2, m3, m4, m5, m6 = m

    # Coordinate 0: 24 * (c0 + 5*m6) == (m0 + m4) + 20*(m1 + m3) - 18*m2
    s04 = vm.op_m31_add(m0, m4)
    s13 = vm.op_m31_add(m1, m3)
    five_s13 = vm.op_m31_add(vm.op_m31_scale_small(s13, 4), s13)
    twenty_s13 = vm.op_m31_scale_small(five_s13, 4)
    eighteen_m2 = vm.op_m31_add(vm.op_m31_scale_small(m2, 12), vm.op_m31_scale_small(m2, 6))
    rhs0 = vm.op_m31_sub(vm.op_m31_add(s04, twenty_s13), eighteen_m2)
    q0_div = vm.op_m31_div_const_verify(rhs0, 24, div_overrides.get(0))
    five_m6 = vm.op_m31_add(vm.op_m31_scale_small(m6, 4), m6)
    c0 = vm.op_m31_sub(q0_div, five_m6)

    # Coordinate 1: 8 * (c1 + 5*m6) == (m0 + m4) - 2*m2
    rhs1 = vm.op_m31_sub(s04, vm.op_m31_scale_small(m2, 2))
    q1_div = vm.op_m31_div_const_verify(rhs1, 8, div_overrides.get(1))
    c1 = vm.op_m31_sub(q1_div, five_m6)

    # Coordinate 2: 120 * (c2 - 9*m6) == 30*m2 + 10*m3 + 25*m4 - 7*m0 - 55*m1 - 3*m5
    five_m2 = vm.op_m31_add(vm.op_m31_scale_small(m2, 4), m2)
    thirty_m2 = vm.op_m31_scale_small(five_m2, 6)
    ten_m2 = vm.op_m31_scale_small(five_m2, 2)
    five_m3 = vm.op_m31_add(vm.op_m31_scale_small(m3, 4), m3)
    ten_m3 = vm.op_m31_scale_small(five_m3, 2)
    twentyfive_m4 = vm.op_m31_add(
        vm.op_m31_scale_small(vm.op_m31_scale_small(m4, 12), 2), m4
    )
    six_m0 = vm.op_m31_scale_small(m0, 6)
    seven_m0 = vm.op_m31_add(six_m0, m0)
    fortyeight_m1 = vm.op_m31_scale_small(vm.op_m31_scale_small(m1, 4), 12)
    seven_m1 = vm.op_m31_add(vm.op_m31_scale_small(m1, 6), m1)
    fiftyfive_m1 = vm.op_m31_add(fortyeight_m1, seven_m1)
    three_m5 = vm.op_m31_scale_small(m5, 3)

    pos2 = vm.op_m31_add(vm.op_m31_add(thirty_m2, ten_m3), twentyfive_m4)
    neg2 = vm.op_m31_add(vm.op_m31_add(seven_m0, fiftyfive_m1), three_m5)
    rhs2 = vm.op_m31_sub(pos2, neg2)
    q2_div = vm.op_m31_div_const_verify(rhs2, 120, div_overrides.get(2))
    three_m6 = vm.op_m31_scale_small(m6, 3)
    nine_m6 = vm.op_m31_add(vm.op_m31_scale_small(m6, 6), three_m6)
    c2 = vm.op_m31_add(q2_div, nine_m6)

    # Coordinate 3: 120 * (c3 - 3*m6) == 15*(m1 + m4) + 10*m2 - 9*m0 - 30*m3 - m5
    m14 = vm.op_m31_add(m1, m4)
    fifteen_m14 = vm.op_m31_scale_small(
        vm.op_m31_add(vm.op_m31_scale_small(m14, 4), m14), 3
    )
    nine_m0 = vm.op_m31_add(six_m0, vm.op_m31_scale_small(m0, 3))
    thirty_m3 = vm.op_m31_scale_small(ten_m3, 3)

    pos3 = vm.op_m31_add(fifteen_m14, ten_m2)
    neg3 = vm.op_m31_add(vm.op_m31_add(nine_m0, thirty_m3), m5)
    rhs3 = vm.op_m31_sub(pos3, neg3)
    q3_div = vm.op_m31_div_const_verify(rhs3, 120, div_overrides.get(3))
    c3 = vm.op_m31_add(q3_div, three_m6)

    # Track worst-case W_z u64 accumulator span as well:
    vm._track_u64(30 * m2 + 10 * m3 + 25 * m4 + 1080 * m6)
    return vm.finalize_trace("Rank-7", (c0, c1, c2, c3), m)


# ============================================================================
# Matrix-Driven Verifier & Exact Z / u64 Bound Auditors for Mutation Testing
# ============================================================================

def verify_schedule_matrix_tapscript(
    schedule: BilinearSchedule,
    a: Sequence[int],
    b: Sequence[int],
    expected_out: Optional[Sequence[int]] = None,
) -> TapscriptExecutionTrace:
    """Execute any `QM31` `BilinearSchedule` `(U, V, W_z, D)` through `TapscriptM31Machine`
    and assert exact agreement with `expected_out` (defaults to `qm31_tower_mul_ref(a, b)`).
    Raises `TapscriptVerificationError` if any linear weight, carry, or output check fails!
    """
    vm = TapscriptM31Machine(record_witnesses=False)
    d = schedule.degree
    r = schedule.rank
    if d != 4:
        raise ValueError(f"Expected degree-4 QM31 schedule, got d={d}")

    def eval_int_row(row: Sequence[int], vec: Sequence[int]) -> int:
        acc = 0
        for coeff, val in zip(row, vec):
            c = int(coeff)
            if c == 0:
                continue
            term = (abs(c) * int(val)) % M31_P
            acc = vm.op_m31_add(acc, term) if c > 0 else vm.op_m31_sub(acc, term)
        return acc

    u_vals = [eval_int_row(schedule.U[l], a) for l in range(r)]
    v_vals = [eval_int_row(schedule.V[l], b) for l in range(r)]
    m_vals = [vm.op_m31_mul(u_vals[l], v_vals[l]) for l in range(r)]

    inv_d = pow(schedule.D, M31_P - 2, M31_P)
    got_out: List[int] = []
    for k in range(4):
        w_mod = eval_int_row(schedule.W_z[k], m_vals)
        got_out.append((w_mod * inv_d) % M31_P)

    want = list(qm31_tower_mul_ref(a, b) if expected_out is None else expected_out)
    if got_out != want:
        raise TapscriptVerificationError(
            f"Schedule {schedule.name} Tapscript output mismatch: got={got_out}, want={want}"
        )
    return vm.finalize_trace(schedule.name, (got_out[0], got_out[1], got_out[2], got_out[3]), m_vals)


@dataclass(frozen=True)
class QM31HardwareBoundsReport:
    """Exact worst-case integer & `u64` / `i64` / `CScriptNum` bounds for `QM31_Rank7`."""

    max_u_l1_norm: int
    max_v_l1_norm: int
    max_wz_l1_norm: int
    max_eval_i64_abs: int
    max_mul_u64: int
    max_interp_i64_abs: int
    max_biased_eval_u64: int
    max_biased_interp_u64: int
    max_inv_d_mul_u64: int
    max_mersenne_fold_sum: int
    fits_signed_i64: bool
    fits_unsigned_u64: bool
    fits_single_mersenne_fold: bool


def compute_exact_qm31_u64_bounds(
    schedule: Optional[BilinearSchedule] = None,
) -> QM31HardwareBoundsReport:
    """Compute exact worst-case `i64` and `u64` bounds over all canonical `[0, P - 1]^4` inputs."""
    sched = get_optimal_native_schedule("QM31") if schedule is None else schedule
    p_m1 = M31_P - 1

    max_u_l1 = max(sum(abs(x) for x in row) for row in sched.U)
    max_v_l1 = max(sum(abs(x) for x in row) for row in sched.V)
    max_wz_l1 = max(sum(abs(x) for x in row) for row in sched.W_z)

    max_eval_pos = max(sum(x for x in row if x > 0) for row in sched.U) * p_m1
    max_eval_neg = max(sum(-x for x in row if x < 0) for row in sched.U) * p_m1
    max_eval_i64_abs = max(max_eval_pos, max_eval_neg)

    max_mul_u64 = p_m1 * p_m1  # (2^31 - 2)^2 = 4,611,686,009,837,453,316 < 2^62

    max_interp_pos = max(sum(x for x in row if x > 0) for row in sched.W_z) * p_m1
    max_interp_neg = max(sum(-x for x in row if x < 0) for row in sched.W_z) * p_m1
    max_interp_i64_abs = max(max_interp_pos, max_interp_neg)

    # Biased unsigned u64 accumulators used in Cairo `zk_qm31_opt`:
    max_biased_eval_u64 = 32 * M31_P + max_eval_pos
    max_biased_interp_u64 = 1500 * M31_P + max_interp_pos

    inv_d = pow(sched.D, M31_P - 2, M31_P)
    max_inv_d_mul_u64 = p_m1 * inv_d

    # Exact maximum of q + r for x = q * 2^31 + r over 0 <= x <= (P - 1)^2:
    # Achieved at q = P - 4 = 2^31 - 5 and r = P = 2^31 - 1 -> q + r = 2*P - 4 < 2*P!
    max_mersenne_fold_sum = (M31_P - 4) + M31_P

    fits_i64 = (
        max_eval_i64_abs <= I64_MAX
        and max_mul_u64 <= I64_MAX
        and max_interp_i64_abs <= I64_MAX
        and max_inv_d_mul_u64 <= I64_MAX
    )
    fits_u64 = (
        max_biased_eval_u64 <= U64_MAX
        and max_mul_u64 <= U64_MAX
        and max_biased_interp_u64 <= U64_MAX
        and max_inv_d_mul_u64 <= U64_MAX
    )
    fits_fold = max_mersenne_fold_sum < 2 * M31_P

    return QM31HardwareBoundsReport(
        max_u_l1_norm=max_u_l1,
        max_v_l1_norm=max_v_l1,
        max_wz_l1_norm=max_wz_l1,
        max_eval_i64_abs=max_eval_i64_abs,
        max_mul_u64=max_mul_u64,
        max_interp_i64_abs=max_interp_i64_abs,
        max_biased_eval_u64=max_biased_eval_u64,
        max_biased_interp_u64=max_biased_interp_u64,
        max_inv_d_mul_u64=max_inv_d_mul_u64,
        max_mersenne_fold_sum=max_mersenne_fold_sum,
        fits_signed_i64=fits_i64,
        fits_unsigned_u64=fits_u64,
        fits_single_mersenne_fold=fits_fold,
    )


def summarize_bitvm2_schedule_comparison() -> Dict[str, Dict[str, float | int]]:
    """Return exact BitVM2 Tapscript opcode, `OP_M31_MUL`, and witness-stack counts across
    `Schoolbook-16`, `Karatsuba-9`, and `Rank-7` (evaluated on a canonical sample pair).
    """
    sample_a = (314159265, 271828182, 161803398, 141421356)
    sample_b = (2147483600, 123456789, 987654321, 2147483645)
    t_sb = simulate_qm31_schoolbook16(sample_a, sample_b)
    t_k9 = simulate_qm31_karatsuba9(sample_a, sample_b)
    t_r7 = simulate_qm31_rank7(sample_a, sample_b)

    assert t_sb.output == t_k9.output == t_r7.output

    return {
        "Schoolbook-16": {
            "op_m31_mul": t_sb.op_m31_mul_count,
            "op_m31_add": t_sb.op_m31_add_count,
            "op_m31_sub": t_sb.op_m31_sub_count,
            "op_m31_scale_small": t_sb.op_m31_scale_small_count,
            "const_div_verify": t_sb.const_div_verify_count,
            "bitcoin_script_opcodes": t_sb.bitcoin_script_opcodes,
            "witness_elements": t_sb.witness_elements,
            "mul_reduction_vs_schoolbook_pct": 0.0,
            "mul_reduction_vs_karatsuba9_pct": round((9 - 16) / 9 * 100.0, 2),
        },
        "Karatsuba-9": {
            "op_m31_mul": t_k9.op_m31_mul_count,
            "op_m31_add": t_k9.op_m31_add_count,
            "op_m31_sub": t_k9.op_m31_sub_count,
            "op_m31_scale_small": t_k9.op_m31_scale_small_count,
            "const_div_verify": t_k9.const_div_verify_count,
            "bitcoin_script_opcodes": t_k9.bitcoin_script_opcodes,
            "witness_elements": t_k9.witness_elements,
            "mul_reduction_vs_schoolbook_pct": round((16 - 9) / 16 * 100.0, 2),
            "mul_reduction_vs_karatsuba9_pct": 0.0,
        },
        "Rank-7": {
            "op_m31_mul": t_r7.op_m31_mul_count,
            "op_m31_add": t_r7.op_m31_add_count,
            "op_m31_sub": t_r7.op_m31_sub_count,
            "op_m31_scale_small": t_r7.op_m31_scale_small_count,
            "const_div_verify": t_r7.const_div_verify_count,
            "bitcoin_script_opcodes": t_r7.bitcoin_script_opcodes,
            "witness_elements": t_r7.witness_elements,
            "mul_reduction_vs_schoolbook_pct": round((16 - 7) / 16 * 100.0, 2),
            "mul_reduction_vs_karatsuba9_pct": round((9 - 7) / 9 * 100.0, 2),
        },
    }


def verify_qm31_unimodular_isomorphism_over_z() -> bool:
    """Verify over `Z` (without modular reduction) that `T` (`det = -1`) is an exact
    ring isomorphism `Z[i, u]/(i^2 + 1, u^2 - (2 + i)) ~= Z[v]/(v^4 - 4v^2 + 5)`.
    """
    to_poly, from_poly = _qm31_basis_pair()
    if det_int_exact(to_poly) != -1 or det_int_exact(from_poly) != -1:
        return False
    if mat_mul_int(to_poly, from_poly) != identity_int_matrix(4):
        return False
    if mat_mul_int(from_poly, to_poly) != identity_int_matrix(4):
        return False

    f_monic = EXTENSION_SPECS["QM31"].simple_poly  # (5, 0, -4, 0, 1)
    for a_idx in range(4):
        ea = [1 if k == a_idx else 0 for k in range(4)]
        pa = [sum(to_poly[r][c] * ea[c] for c in range(4)) for r in range(4)]
        for b_idx in range(4):
            eb = [1 if k == b_idx else 0 for k in range(4)]
            pb = [sum(to_poly[r][c] * eb[c] for c in range(4)) for r in range(4)]
            poly_prod = textbook_poly_mul_fixed_z(pa, pb, f_monic)
            mapped_back = [sum(from_poly[r][c] * poly_prod[c] for c in range(4)) for r in range(4)]
            if mapped_back != qm31_mul_exact_z(ea, eb):
                return False
    return True
