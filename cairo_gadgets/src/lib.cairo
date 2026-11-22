//! Certified Mersenne-31 (`M31`, `P = 2^31 - 1`) and degree-4 Circle STARK secure extension
//! (`QM31 = CM31[u]/(u^2 - (2 + i))`, `CM31 = M31[i]/(i^2 + 1)`) arithmetic gadgets for Cairo.
//!
//! Implements three verified multiplication & squaring schedules:
//!   1. `qm31_mul_schoolbook` / `qm31_square_schoolbook`: canonical tower baseline (`16` `M31`
//!   muls).
//!   2. `qm31_mul_karatsuba9` / `qm31_square_karatsuba6`: unimodular `{0, +1, -1}` nested Karatsuba
//!      (`9` `M31` muls for multiplication, `6` `M31` muls for squaring, and `0` non-unit
//!      `Const * Var` multiplications, matching `starkware-libs/proving#9` `stwo_cairo_verifier`).
//!   3. `qm31_mul_rank7` / `qm31_square_rank7`: Alder-Strassen / Winograd minimum-rank `7`-mul
//!      interpolation schedule on `{-2, -1, 0, 1, 2, 3, inf}` via the unimodular (`det = -1`)
//!      basis isomorphism `QM31 ~= M31[v]/(v^4 - 4v^2 + 5)` (`v = u`, `i = v^2 - 2`), matching
//!      `targets/qm31_stwo/qm31_rank7_cert.json` (`D = 120`, `120^{-1} mod P = 304226850`).

/// Mersenne-31 prime `P = 2^31 - 1 = 2147483647`.
pub const M31_P: u32 = 0x7fffffff_u32;

/// Mersenne-31 prime as `u64`.
pub const M31_P_U64: u64 = 0x7fffffff_u64;

/// `2^31 = P + 1` power-of-two modulus for single-pass Mersenne folding on `[0, (P - 1)^2]`.
pub const M31_SHIFT_MOD: u64 = 0x80000000_u64;

/// Modular inverse `120^{-1} mod (2^31 - 1) = 304226850` (`120 * 304226850 = 17 * P + 1`).
pub const INV_120_MOD_M31: u64 = 304226850_u64;

/// Canonical Mersenne-31 field element with invariant `0 <= val < 2^31 - 1`.
#[derive(Copy, Drop, Debug, PartialEq)]
pub struct M31 {
    pub val: u32,
}

/// Complex Mersenne-31 element `c0 + c1 * i` in `M31[i]/(i^2 + 1)`.
#[derive(Copy, Drop, Debug, PartialEq)]
pub struct CM31 {
    pub c0: M31,
    pub c1: M31,
}

/// Quartic Circle STARK secure-field element `(c0 + c1 * i) + (c2 + c3 * i) * u`
/// in `CM31[u]/(u^2 - (2 + i))` (canonical `stwo` coordinate order `[a0, a1, b0, b1]`).
#[derive(Copy, Drop, Debug, PartialEq)]
pub struct QM31 {
    pub c0: M31,
    pub c1: M31,
    pub c2: M31,
    pub c3: M31,
}

/// Construct a canonical `M31` element, asserting `val < 2^31 - 1`.
pub fn m31_new(val: u32) -> M31 {
    assert!(val < M31_P, "M31 value must be strictly less than 2^31 - 1");
    M31 { val }
}

/// Zero element of `M31`.
pub fn m31_zero() -> M31 {
    M31 { val: 0 }
}

/// Multiplicative identity of `M31`.
pub fn m31_one() -> M31 {
    M31 { val: 1 }
}

/// Check whether an `M31` element is in canonical `[0, P - 1]`.
pub fn m31_is_canonical(a: M31) -> bool {
    a.val < M31_P
}

/// Reduce an arbitrary `u64` modulo `P = 2^31 - 1` into canonical `[0, P - 1]`.
pub fn m31_reduce_u64(x: u64) -> M31 {
    let rem: u64 = x % M31_P_U64;
    M31 { val: rem.try_into().unwrap() }
}

/// Exact single-fold Mersenne reduction for `0 <= x <= (P - 1)^2 < 2^62`:
/// Writing `x = q * 2^31 + r` (`0 <= r <= P`), for all `x <= (P - 1)^2` we have
/// `0 <= q + r <= 2*P - 4 < 2*P`, so a single conditional subtraction yields canonical `[0, P -
/// 1]`.
pub fn m31_fold_u62(x: u64) -> M31 {
    let q: u64 = x / M31_SHIFT_MOD;
    let r: u64 = x % M31_SHIFT_MOD;
    let s: u64 = q + r;
    let red: u64 = if s >= M31_P_U64 {
        s - M31_P_U64
    } else {
        s
    };
    M31 { val: red.try_into().unwrap() }
}

/// Canonical `M31` addition `(a + b) mod P` backed by `u64` without overflow.
pub fn m31_add(a: M31, b: M31) -> M31 {
    let sum: u64 = a.val.into() + b.val.into();
    let red: u64 = if sum >= M31_P_U64 {
        sum - M31_P_U64
    } else {
        sum
    };
    M31 { val: red.try_into().unwrap() }
}

/// Canonical `M31` subtraction `(a - b) mod P` backed by `u64` without underflow.
pub fn m31_sub(a: M31, b: M31) -> M31 {
    let diff: u64 = if a.val >= b.val {
        (a.val - b.val).into()
    } else {
        a.val.into() + M31_P_U64 - b.val.into()
    };
    M31 { val: diff.try_into().unwrap() }
}

/// Canonical `M31` negation `(-a) mod P`.
pub fn m31_neg(a: M31) -> M31 {
    if a.val == 0 {
        M31 { val: 0 }
    } else {
        M31 { val: M31_P - a.val }
    }
}

/// Canonical variable-variable `M31` multiplication `(a * b) mod P` via `u64` Mersenne folding.
/// Peak `u64` product for canonical inputs is `(P - 1)^2 = 4611686009837453316 < 2^62`.
pub fn m31_mul(a: M31, b: M31) -> M31 {
    let prod: u64 = a.val.into() * b.val.into();
    m31_fold_u62(prod)
}

/// Constant scalar multiplication `(c * a) mod P` for known field constant `0 <= c < P`
/// (degree-1 linear scaling in R1CS / PlonK / native CPU models).
pub fn m31_scale_const(a: M31, c: u64) -> M31 {
    let prod: u64 = a.val.into() * c;
    m31_fold_u62(prod)
}

/// Construct a canonical `QM31` element from four `u32` coordinates in `[0, P - 1]`.
pub fn qm31_new(c0: u32, c1: u32, c2: u32, c3: u32) -> QM31 {
    QM31 { c0: m31_new(c0), c1: m31_new(c1), c2: m31_new(c2), c3: m31_new(c3) }
}

/// Zero element of `QM31`.
pub fn qm31_zero() -> QM31 {
    QM31 { c0: m31_zero(), c1: m31_zero(), c2: m31_zero(), c3: m31_zero() }
}

/// Multiplicative identity `(1, 0, 0, 0)` of `QM31`.
pub fn qm31_one() -> QM31 {
    QM31 { c0: m31_one(), c1: m31_zero(), c2: m31_zero(), c3: m31_zero() }
}

/// Canonical `QM31` coordinatewise addition.
pub fn qm31_add(a: QM31, b: QM31) -> QM31 {
    QM31 {
        c0: m31_add(a.c0, b.c0),
        c1: m31_add(a.c1, b.c1),
        c2: m31_add(a.c2, b.c2),
        c3: m31_add(a.c3, b.c3),
    }
}

/// Canonical `QM31` coordinatewise subtraction.
pub fn qm31_sub(a: QM31, b: QM31) -> QM31 {
    QM31 {
        c0: m31_sub(a.c0, b.c0),
        c1: m31_sub(a.c1, b.c1),
        c2: m31_sub(a.c2, b.c2),
        c3: m31_sub(a.c3, b.c3),
    }
}

// ============================================================================
// Schedule (a): Canonical Tower Schoolbook Baseline (`16` M31 Multiplications)
// ============================================================================

/// Schoolbook `CM31 = M31[i]/(i^2 + 1)` multiplication (`4` `M31` muls).
pub fn cm31_mul_schoolbook(a: CM31, b: CM31) -> CM31 {
    let re = m31_sub(m31_mul(a.c0, b.c0), m31_mul(a.c1, b.c1));
    let im = m31_add(m31_mul(a.c0, b.c1), m31_mul(a.c1, b.c0));
    CM31 { c0: re, c1: im }
}

/// Reference schoolbook multiplication in `QM31 = CM31[u]/(u^2 - (2 + i))` (`16` `M31` muls).
pub fn qm31_mul_schoolbook(a: QM31, b: QM31) -> QM31 {
    let a_lo = CM31 { c0: a.c0, c1: a.c1 };
    let a_hi = CM31 { c0: a.c2, c1: a.c3 };
    let b_lo = CM31 { c0: b.c0, c1: b.c1 };
    let b_hi = CM31 { c0: b.c2, c1: b.c3 };

    let ac = cm31_mul_schoolbook(a_lo, b_lo);
    let bd = cm31_mul_schoolbook(a_hi, b_hi);
    let ad = cm31_mul_schoolbook(a_lo, b_hi);
    let bc = cm31_mul_schoolbook(a_hi, b_lo);

    // (2 + i) * (bd.c0 + bd.c1 * i) = (2 * bd.c0 - bd.c1) + (bd.c0 + 2 * bd.c1) * i
    let bd_xi_re = m31_sub(m31_add(bd.c0, bd.c0), bd.c1);
    let bd_xi_im = m31_add(bd.c0, m31_add(bd.c1, bd.c1));

    QM31 {
        c0: m31_add(ac.c0, bd_xi_re),
        c1: m31_add(ac.c1, bd_xi_im),
        c2: m31_add(ad.c0, bc.c0),
        c3: m31_add(ad.c1, bc.c1),
    }
}

/// Reference schoolbook squaring in `QM31` (`16` `M31` muls).
pub fn qm31_square_schoolbook(a: QM31) -> QM31 {
    qm31_mul_schoolbook(a, a)
}

// ============================================================================
// Schedule (b): Unimodular `{0, +1, -1}` Nested Karatsuba (`9` Mul / `6` Sq, `0` Const*Var)
// ============================================================================

/// Unimodular `{0, +1, -1}` nested Karatsuba `QM31` multiplication:
///   - Exactly `9` `M31` variable-variable multiplications (`m31_mul`).
///   - Strictly `0` non-unit `Const * Var` multiplications (both evaluation and interpolation
///     use exclusively `{0, +1, -1}` additions/subtractions, matching `starkware-libs/proving#9`).
pub fn qm31_mul_karatsuba9(a: QM31, b: QM31) -> QM31 {
    let ab0 = m31_add(a.c0, a.c2);
    let ab1 = m31_add(a.c1, a.c3);
    let cd0 = m31_add(b.c0, b.c2);
    let cd1 = m31_add(b.c1, b.c3);

    let a01 = m31_add(a.c0, a.c1);
    let b01 = m31_add(b.c0, b.c1);
    let a23 = m31_add(a.c2, a.c3);
    let b23 = m31_add(b.c2, b.c3);
    let ab01 = m31_add(ab0, ab1);
    let cd01 = m31_add(cd0, cd1);

    // 9 M31 variable-variable multiplications:
    let p0 = m31_mul(a.c0, b.c0);
    let p1 = m31_mul(a.c1, b.c1);
    let p2 = m31_mul(a01, b01);

    let q0 = m31_mul(a.c2, b.c2);
    let q1 = m31_mul(a.c3, b.c3);
    let q2 = m31_mul(a23, b23);

    let r0 = m31_mul(ab0, cd0);
    let r1 = m31_mul(ab1, cd1);
    let r2 = m31_mul(ab01, cd01);

    // Pure {0, +1, -1} reconstruction (0 Const * Var multiplications):
    let ac_re = m31_sub(p0, p1);
    let ac_im = m31_sub(p2, m31_add(p0, p1));

    let bd_re = m31_sub(q0, q1);
    let bd_im = m31_sub(q2, m31_add(q0, q1));

    let s_re = m31_add(ac_re, bd_re);
    let s_im = m31_add(ac_im, bd_im);

    let c0 = m31_sub(m31_add(s_re, bd_re), bd_im);
    let c1 = m31_add(m31_add(s_im, bd_re), bd_im);
    let c2 = m31_sub(m31_sub(r0, r1), s_re);
    let c3 = m31_sub(m31_sub(r2, m31_add(r0, r1)), s_im);

    QM31 { c0, c1, c2, c3 }
}

/// Unimodular `{0, +1, -1}` nested Karatsuba `QM31` squaring:
///   - Exactly `6` `M31` variable-variable multiplications (`3` complex squarings x `2` muls).
///   - Strictly `0` non-unit `Const * Var` multiplications.
pub fn qm31_square_karatsuba6(a: QM31) -> QM31 {
    let a0_plus_a1 = m31_add(a.c0, a.c1);
    let a0_minus_a1 = m31_sub(a.c0, a.c1);
    let a2_plus_a3 = m31_add(a.c2, a.c3);
    let a2_minus_a3 = m31_sub(a.c2, a.c3);

    let s0 = m31_add(a.c0, a.c2);
    let s1 = m31_add(a.c1, a.c3);
    let s0_plus_s1 = m31_add(s0, s1);
    let s0_minus_s1 = m31_sub(s0, s1);

    // 6 M31 variable-variable multiplications:
    let a0_sq_re = m31_mul(a0_plus_a1, a0_minus_a1);
    let a0_a1 = m31_mul(a.c0, a.c1);

    let a1_sq_re = m31_mul(a2_plus_a3, a2_minus_a3);
    let a2_a3 = m31_mul(a.c2, a.c3);

    let sum_sq_re = m31_mul(s0_plus_s1, s0_minus_s1);
    let s0_s1 = m31_mul(s0, s1);

    // Pure {0, +1, -1} reconstruction (0 Const * Var multiplications):
    let a0_sq_im = m31_add(a0_a1, a0_a1);
    let a1_sq_im = m31_add(a2_a3, a2_a3);
    let sum_sq_im = m31_add(s0_s1, s0_s1);

    let t_re = m31_add(a0_sq_re, a1_sq_re);
    let t_im = m31_add(a0_sq_im, a1_sq_im);

    let c0 = m31_sub(m31_add(t_re, a1_sq_re), a1_sq_im);
    let c1 = m31_add(m31_add(t_im, a1_sq_re), a1_sq_im);
    let c2 = m31_sub(sum_sq_re, t_re);
    let c3 = m31_sub(sum_sq_im, t_im);

    QM31 { c0, c1, c2, c3 }
}

// ============================================================================
// Schedule (c): Winograd / Alder-Strassen Minimum-Rank `7`-Mul Schedule
// ============================================================================

/// Unimodular (`det = -1`) forward basis map `QM31 -> M31[v]/(v^4 - 4v^2 + 5)` (`v = u`):
/// Since `u^2 = 2 + i` implies `i = v^2 - 2`:
///   `(a0 + a1*i) + (a2 + a3*i)*u = (a0 - 2*a1) + (a2 - 2*a3)*v + a1*v^2 + a3*v^3`.
pub fn qm31_to_simple_basis(a: QM31) -> (M31, M31, M31, M31) {
    let p0 = m31_sub(a.c0, m31_add(a.c1, a.c1));
    let p1 = m31_sub(a.c2, m31_add(a.c3, a.c3));
    let p2 = a.c1;
    let p3 = a.c3;
    (p0, p1, p2, p3)
}

/// Unimodular (`det = -1`) inverse basis map `M31[v]/(v^4 - 4v^2 + 5) -> QM31`:
///   `a0 = p0 + 2*p2`, `a1 = p2`, `a2 = p1 + 2*p3`, `a3 = p3`.
pub fn qm31_from_simple_basis(p0: M31, p1: M31, p2: M31, p3: M31) -> QM31 {
    QM31 { c0: m31_add(p0, m31_add(p2, p2)), c1: p2, c2: m31_add(p1, m31_add(p3, p3)), c3: p3 }
}

/// Evaluate `QM31` element at the 7 projective Vandermonde nodes `{-2, -1, 0, 1, 2, 3, inf}`
/// using the exact folded matrix `U` from `targets/qm31_stwo/qm31_rank7_cert.json`:
///   row 0 (v = -2): [ 1,  2, -2, -4]
///   row 1 (v = -1): [ 1, -1, -1,  1]
///   row 2 (v =  0): [ 1, -2,  0,  0]
///   row 3 (v =  1): [ 1, -1,  1, -1]
///   row 4 (v =  2): [ 1,  2,  2,  4]
///   row 5 (v =  3): [ 1,  7,  3, 21]
///   row 6 (v = inf): [0,  0,  0,  1]
pub fn qm31_eval_rank7(a: QM31) -> (M31, M31, M31, M31, M31, M31, M31) {
    // Even/odd shared evaluation butterfly matching `qm31_rank7_cert.json` U rows:
    let sa = m31_sub(a.c0, a.c1);
    let sb = m31_sub(a.c2, a.c3);
    let u2 = m31_sub(sa, a.c1); // v =  0: a0 - 2*a1
    let u3 = m31_add(sa, sb); // v =  1: a0 - a1 + a2 - a3
    let u1 = m31_sub(sa, sb); // v = -1: a0 - a1 - a2 + a3

    let two_a1 = m31_add(a.c1, a.c1);
    let ta = m31_add(a.c0, two_a1); // a0 + 2*a1
    let two_a2 = m31_add(a.c2, a.c2);
    let two_a3 = m31_add(a.c3, a.c3);
    let four_a3 = m31_add(two_a3, two_a3);
    let tb = m31_add(two_a2, four_a3); // 2*a2 + 4*a3
    let u4 = m31_add(ta, tb); // v =  2: a0 + 2*a1 + 2*a2 + 4*a3
    let u0 = m31_sub(ta, tb); // v = -2: a0 + 2*a1 - 2*a2 - 4*a3

    let a0: u64 = a.c0.val.into();
    let a1: u64 = a.c1.val.into();
    let a2: u64 = a.c2.val.into();
    let a3: u64 = a.c3.val.into();
    let u5 = m31_fold_u62(a0 + 7 * a1 + 3 * a2 + 21 * a3); // v = 3: a0 + 7*a1 + 3*a2 + 21*a3
    let u6 = a.c3; // v = inf: a3

    (u0, u1, u2, u3, u4, u5, u6)
}

/// Interpolate the 4 canonical `QM31` coordinates from the 7 pointwise `M31` products
/// `(m0..m6)` using exact `W_z` and `D = 120` (`INV_120_MOD_M31 = 304226850`) from
/// `targets/qm31_stwo/qm31_rank7_cert.json`.
pub fn qm31_interpolate_rank7(
    m0: M31, m1: M31, m2: M31, m3: M31, m4: M31, m5: M31, m6: M31,
) -> QM31 {
    let x0: u64 = m0.val.into();
    let x1: u64 = m1.val.into();
    let x2: u64 = m2.val.into();
    let x3: u64 = m3.val.into();
    let x4: u64 = m4.val.into();
    let x5: u64 = m5.val.into();
    let x6: u64 = m6.val.into();
    let bias: u64 = 1500_u64 * M31_P_U64;

    // W_z[0] = [ 5, 100, -90, 100,  5,  0, -600]
    let w0 = m31_fold_u62(bias + 5 * x0 + 100 * x1 - 90 * x2 + 100 * x3 + 5 * x4 - 600 * x6);
    // W_z[1] = [15,   0, -30,   0, 15,  0, -600]
    let w1 = m31_fold_u62(bias + 15 * x0 - 30 * x2 + 15 * x4 - 600 * x6);
    // W_z[2] = [-7, -55,  30,  10, 25, -3, 1080]
    let w2 = m31_fold_u62(
        bias - 7 * x0 - 55 * x1 + 30 * x2 + 10 * x3 + 25 * x4 - 3 * x5 + 1080 * x6,
    );
    // W_z[3] = [-9,  15,  10, -30, 15, -1,  360]
    let w3 = m31_fold_u62(bias - 9 * x0 + 15 * x1 + 10 * x2 - 30 * x3 + 15 * x4 - x5 + 360 * x6);

    QM31 {
        c0: m31_scale_const(w0, INV_120_MOD_M31),
        c1: m31_scale_const(w1, INV_120_MOD_M31),
        c2: m31_scale_const(w2, INV_120_MOD_M31),
        c3: m31_scale_const(w3, INV_120_MOD_M31),
    }
}

/// Alder-Strassen / Winograd minimum-rank `QM31` multiplication using **exactly `7`**
/// variable-variable `M31` multiplications (`m31_mul`), `-22.22%` vs `Karatsuba-9` and
/// `-56.25%` vs `Schoolbook-16`.
pub fn qm31_mul_rank7(a: QM31, b: QM31) -> QM31 {
    let (u0, u1, u2, u3, u4, u5, u6) = qm31_eval_rank7(a);
    let (v0, v1, v2, v3, v4, v5, v6) = qm31_eval_rank7(b);

    // Exactly 7 M31 variable-variable multiplications:
    let m0 = m31_mul(u0, v0);
    let m1 = m31_mul(u1, v1);
    let m2 = m31_mul(u2, v2);
    let m3 = m31_mul(u3, v3);
    let m4 = m31_mul(u4, v4);
    let m5 = m31_mul(u5, v5);
    let m6 = m31_mul(u6, v6);

    qm31_interpolate_rank7(m0, m1, m2, m3, m4, m5, m6)
}

/// Alder-Strassen / Winograd minimum-rank `QM31` squaring using **exactly `7`**
/// variable-variable `M31` squarings (`m31_mul`) and a single 7-point evaluation pass.
pub fn qm31_square_rank7(a: QM31) -> QM31 {
    let (u0, u1, u2, u3, u4, u5, u6) = qm31_eval_rank7(a);

    // Exactly 7 M31 variable-variable squarings:
    let m0 = m31_mul(u0, u0);
    let m1 = m31_mul(u1, u1);
    let m2 = m31_mul(u2, u2);
    let m3 = m31_mul(u3, u3);
    let m4 = m31_mul(u4, u4);
    let m5 = m31_mul(u5, u5);
    let m6 = m31_mul(u6, u6);

    qm31_interpolate_rank7(m0, m1, m2, m3, m4, m5, m6)
}

#[cfg(test)]
mod tests {
    use super::{
        INV_120_MOD_M31, M31_P, M31_P_U64, QM31, m31_add, m31_fold_u62, m31_is_canonical, m31_mul,
        m31_neg, m31_new, m31_one, m31_reduce_u64, m31_scale_const, m31_sub, m31_zero, qm31_add,
        qm31_eval_rank7, qm31_from_simple_basis, qm31_mul_karatsuba9, qm31_mul_rank7,
        qm31_mul_schoolbook, qm31_new, qm31_one, qm31_square_karatsuba6, qm31_square_rank7,
        qm31_square_schoolbook, qm31_sub, qm31_to_simple_basis, qm31_zero,
    };

    fn basis_element(idx: u32) -> QM31 {
        if idx == 0 {
            qm31_new(1, 0, 0, 0)
        } else if idx == 1 {
            qm31_new(0, 1, 0, 0)
        } else if idx == 2 {
            qm31_new(0, 0, 1, 0)
        } else {
            qm31_new(0, 0, 0, 1)
        }
    }

    fn assert_qm31_canonical(x: QM31) {
        assert!(m31_is_canonical(x.c0), "c0 non-canonical");
        assert!(m31_is_canonical(x.c1), "c1 non-canonical");
        assert!(m31_is_canonical(x.c2), "c2 non-canonical");
        assert!(m31_is_canonical(x.c3), "c3 non-canonical");
    }

    fn next_prng_u64(state: u64) -> u64 {
        // SplitMix64-style deterministic transition modulo 2^64 via wrapping u128 truncation:
        let s128: u128 = state.into() * 6364136223846793005_u128 + 1442695040888963407_u128;
        let mask64: u128 = 0xffffffffffffffff_u128;
        (s128 & mask64).try_into().unwrap()
    }

    fn sample_qm31(seed: u64) -> (QM31, u64) {
        let s0 = next_prng_u64(seed);
        let s1 = next_prng_u64(s0);
        let s2 = next_prng_u64(s1);
        let s3 = next_prng_u64(s2);
        let q = QM31 {
            c0: m31_reduce_u64(s0),
            c1: m31_reduce_u64(s1),
            c2: m31_reduce_u64(s2),
            c3: m31_reduce_u64(s3),
        };
        (q, s3)
    }

    #[test]
    fn test_m31_canonical_bounds_and_inv120() {
        let p_minus_1 = m31_new(M31_P - 1);
        assert_eq!(m31_add(p_minus_1, m31_one()), m31_zero());
        assert_eq!(m31_sub(m31_zero(), m31_one()), p_minus_1);
        assert_eq!(m31_neg(m31_zero()), m31_zero());
        assert_eq!(m31_neg(m31_one()), p_minus_1);

        // (P - 1)^2 == 1 (mod P) via u64 Mersenne folding without overflow:
        assert_eq!(m31_mul(p_minus_1, p_minus_1), m31_one());
        assert_eq!(m31_fold_u62(M31_P_U64), m31_zero());
        let max_sq: u64 = (M31_P_U64 - 1) * (M31_P_U64 - 1);
        assert_eq!(m31_fold_u62(max_sq), m31_reduce_u64(max_sq));

        // Worst-case Mersenne fold sum q + r = 2*P - 4:
        let worst_fold: u64 = (M31_P_U64 - 4) * 0x80000000_u64 + M31_P_U64;
        assert_eq!(m31_fold_u62(worst_fold), m31_reduce_u64(worst_fold));

        // Verify 120 * INV_120_MOD_M31 === 1 (mod P):
        let c120 = m31_new(120);
        assert_eq!(m31_scale_const(c120, INV_120_MOD_M31), m31_one());
    }

    #[test]
    fn test_all_16_canonical_basis_pairs_and_algebraic_relations() {
        // Explicit tower generator checks: i^2 = -1, u^2 = 2 + i, (i*u)^2 = -(2 + i)
        let e1 = basis_element(0);
        let ei = basis_element(1);
        let eu = basis_element(2);
        let eiu = basis_element(3);

        assert_eq!(qm31_mul_schoolbook(ei, ei), qm31_new(M31_P - 1, 0, 0, 0));
        assert_eq!(qm31_mul_schoolbook(eu, eu), qm31_new(2, 1, 0, 0));
        assert_eq!(qm31_mul_schoolbook(ei, eu), eiu);
        assert_eq!(qm31_mul_schoolbook(eiu, eiu), qm31_new(M31_P - 2, M31_P - 1, 0, 0));
        assert_eq!(qm31_mul_schoolbook(e1, eiu), eiu);

        // Exhaustive check of all 16 canonical basis pairs (e_a, e_b):
        let mut a_idx: u32 = 0;
        while a_idx < 4 {
            let ea = basis_element(a_idx);
            // Diagonal squaring consistency on basis elements:
            let sq_sb = qm31_square_schoolbook(ea);
            let sq_k6 = qm31_square_karatsuba6(ea);
            let sq_r7 = qm31_square_rank7(ea);
            assert_qm31_canonical(sq_k6);
            assert_qm31_canonical(sq_r7);
            assert_eq!(sq_k6, sq_sb);
            assert_eq!(sq_r7, sq_sb);

            let mut b_idx: u32 = 0;
            while b_idx < 4 {
                let eb = basis_element(b_idx);
                let prod_sb = qm31_mul_schoolbook(ea, eb);
                let prod_k9 = qm31_mul_karatsuba9(ea, eb);
                let prod_r7 = qm31_mul_rank7(ea, eb);

                assert_qm31_canonical(prod_sb);
                assert_qm31_canonical(prod_k9);
                assert_qm31_canonical(prod_r7);
                assert_eq!(prod_k9, prod_sb);
                assert_eq!(prod_r7, prod_sb);
                b_idx += 1;
            }
            a_idx += 1;
        };
    }

    #[test]
    fn test_unimodular_simple_basis_isomorphism_and_eval_folding() {
        // Verify u satisfies v^4 - 4*v^2 + 5 = 0 in QM31:
        let v = basis_element(2); // v = u
        let v2 = qm31_mul_schoolbook(v, v);
        let v4 = qm31_mul_schoolbook(v2, v2);
        let four_v2 = qm31_add(qm31_add(v2, v2), qm31_add(v2, v2));
        let five = qm31_new(5, 0, 0, 0);
        assert_eq!(qm31_add(qm31_sub(v4, four_v2), five), qm31_zero());

        // Verify unimodular roundtrip and folded evaluation equivalence:
        let sample = qm31_new(123456789, 2147483600, 987654321, 2147483646);
        let (p0, p1, p2, p3) = qm31_to_simple_basis(sample);
        assert_eq!(qm31_from_simple_basis(p0, p1, p2, p3), sample);

        // Evaluate P(t) = p0 + p1*t + p2*t^2 + p3*t^3 directly at t = -2, -1, 0, 1, 2, 3, inf:
        let (u0, u1, u2, u3, u4, u5, u6) = qm31_eval_rank7(sample);
        assert_eq!(u2, p0);
        assert_eq!(u6, p3);
        assert_eq!(u3, m31_add(m31_add(p0, p1), m31_add(p2, p3)));
        assert_eq!(u1, m31_sub(m31_add(p0, p2), m31_add(p1, p3)));

        let two_p1 = m31_scale_const(p1, 2);
        let four_p2 = m31_scale_const(p2, 4);
        let eight_p3 = m31_scale_const(p3, 8);
        assert_eq!(u4, m31_add(m31_add(p0, two_p1), m31_add(four_p2, eight_p3)));
        assert_eq!(u0, m31_sub(m31_add(p0, four_p2), m31_add(two_p1, eight_p3)));
        assert_eq!(
            u5,
            m31_add(
                m31_add(p0, m31_scale_const(p1, 3)),
                m31_add(m31_scale_const(p2, 9), m31_scale_const(p3, 27)),
            ),
        );
    }

    #[test]
    fn test_zero_unit_and_worst_case_boundary_vectors() {
        let z = qm31_zero();
        let one = qm31_one();
        let max_val = M31_P - 1;
        let all_max = qm31_new(max_val, max_val, max_val, max_val);
        let alt_hi_lo = qm31_new(max_val, 0, max_val, 0);
        let alt_lo_hi = qm31_new(0, max_val, 0, max_val);
        let rank7_worst_pos = qm31_new(max_val, max_val, 0, 0);
        let rank7_worst_neg = qm31_new(0, 0, max_val, max_val);

        let vectors: Array<QM31> = array![
            z, one, all_max, alt_hi_lo, alt_lo_hi, rank7_worst_pos, rank7_worst_neg,
        ];

        let n = vectors.len();
        let mut i: usize = 0;
        while i < n {
            let va = *vectors.at(i);

            // Identity & zero laws:
            assert_eq!(qm31_mul_karatsuba9(va, z), z);
            assert_eq!(qm31_mul_rank7(va, z), z);
            assert_eq!(qm31_mul_karatsuba9(va, one), va);
            assert_eq!(qm31_mul_rank7(va, one), va);

            // Squaring schedules match schoolbook & mul(va, va):
            let sq_sb = qm31_square_schoolbook(va);
            let sq_k6 = qm31_square_karatsuba6(va);
            let sq_r7 = qm31_square_rank7(va);
            assert_qm31_canonical(sq_k6);
            assert_qm31_canonical(sq_r7);
            assert_eq!(sq_k6, sq_sb);
            assert_eq!(sq_r7, sq_sb);
            assert_eq!(qm31_mul_rank7(va, va), sq_sb);

            let mut j: usize = 0;
            while j < n {
                let vb = *vectors.at(j);
                let expected = qm31_mul_schoolbook(va, vb);
                let got_k9 = qm31_mul_karatsuba9(va, vb);
                let got_r7 = qm31_mul_rank7(va, vb);
                assert_qm31_canonical(got_k9);
                assert_qm31_canonical(got_r7);
                assert_eq!(got_k9, expected);
                assert_eq!(got_r7, expected);
                j += 1;
            }
            i += 1;
        };
    }

    #[test]
    fn test_200_deterministic_pseudorandom_qm31_pairs_and_algebra_laws() {
        let mut seed: u64 = 0x20261122_c9bb5e19_u64;
        let mut trial: u32 = 0;
        while trial < 200 {
            let (a, s1) = sample_qm31(seed);
            let (b, s2) = sample_qm31(s1);
            seed = s2;

            let expected_ab = qm31_mul_schoolbook(a, b);
            let k9_ab = qm31_mul_karatsuba9(a, b);
            let r7_ab = qm31_mul_rank7(a, b);

            assert_qm31_canonical(k9_ab);
            assert_qm31_canonical(r7_ab);
            assert_eq!(k9_ab, expected_ab);
            assert_eq!(r7_ab, expected_ab);

            // Commutativity check on Rank-7 and Karatsuba-9:
            assert_eq!(qm31_mul_rank7(b, a), expected_ab);
            assert_eq!(qm31_mul_karatsuba9(b, a), expected_ab);

            // Squaring consistency on all 200 pseudo-random elements:
            let sq_a = qm31_mul_schoolbook(a, a);
            assert_eq!(qm31_square_karatsuba6(a), sq_a);
            assert_eq!(qm31_square_rank7(a), sq_a);

            // Distributivity spot-check every 10th sample: a * (b + c) == a*b + a*c
            if trial % 10 == 0 {
                let (c, s3) = sample_qm31(seed);
                seed = s3;
                let lhs = qm31_mul_rank7(a, qm31_add(b, c));
                let rhs = qm31_add(qm31_mul_karatsuba9(a, b), qm31_mul_rank7(a, c));
                assert_eq!(lhs, rhs);
            }

            trial += 1;
        };
    }

    #[test]
    fn test_chain_equivalence_mul_and_square_16_iters() {
        let init = qm31_new(314159265, 271828182, 161803398, 141421356);
        let step = qm31_new(2147483600, 123456789, 987654321, 2147483645);
        let mut a_sb = init;
        let mut a_k9 = init;
        let mut a_r7 = init;
        let mut s_sb = init;
        let mut s_k6 = init;
        let mut s_r7 = init;
        let mut i: u32 = 0;
        while i < 16 {
            a_sb = qm31_mul_schoolbook(a_sb, step);
            a_k9 = qm31_mul_karatsuba9(a_k9, step);
            a_r7 = qm31_mul_rank7(a_r7, step);
            s_sb = qm31_square_schoolbook(s_sb);
            s_k6 = qm31_square_karatsuba6(s_k6);
            s_r7 = qm31_square_rank7(s_r7);
            i += 1;
        }
        assert_eq!(a_k9, a_sb);
        assert_eq!(a_r7, a_sb);
        assert_eq!(s_k6, s_sb);
        assert_eq!(s_r7, s_sb);
    }

    #[test]
    fn test_chain_benchmark_mul_schoolbook_64_iters() {
        let mut acc = qm31_new(314159265, 271828182, 161803398, 141421356);
        let step = qm31_new(2147483600, 123456789, 987654321, 2147483645);
        let mut i: u32 = 0;
        while i < 64 {
            acc = qm31_mul_schoolbook(acc, step);
            i += 1;
        }
        assert_qm31_canonical(acc);
    }

    #[test]
    fn test_chain_benchmark_mul_karatsuba9_64_iters() {
        let mut acc = qm31_new(314159265, 271828182, 161803398, 141421356);
        let step = qm31_new(2147483600, 123456789, 987654321, 2147483645);
        let mut i: u32 = 0;
        while i < 64 {
            acc = qm31_mul_karatsuba9(acc, step);
            i += 1;
        }
        assert_qm31_canonical(acc);
    }

    #[test]
    fn test_chain_benchmark_mul_rank7_64_iters() {
        let mut acc = qm31_new(314159265, 271828182, 161803398, 141421356);
        let step = qm31_new(2147483600, 123456789, 987654321, 2147483645);
        let mut i: u32 = 0;
        while i < 64 {
            acc = qm31_mul_rank7(acc, step);
            i += 1;
        }
        assert_qm31_canonical(acc);
    }

    #[test]
    fn test_chain_benchmark_square_schoolbook_64_iters() {
        let mut acc = qm31_new(314159265, 271828182, 161803398, 141421356);
        let mut i: u32 = 0;
        while i < 64 {
            acc = qm31_square_schoolbook(acc);
            i += 1;
        }
        assert_qm31_canonical(acc);
    }

    #[test]
    fn test_chain_benchmark_square_karatsuba6_64_iters() {
        let mut acc = qm31_new(314159265, 271828182, 161803398, 141421356);
        let mut i: u32 = 0;
        while i < 64 {
            acc = qm31_square_karatsuba6(acc);
            i += 1;
        }
        assert_qm31_canonical(acc);
    }

    #[test]
    fn test_chain_benchmark_square_rank7_64_iters() {
        let mut acc = qm31_new(314159265, 271828182, 161803398, 141421356);
        let mut i: u32 = 0;
        while i < 64 {
            acc = qm31_square_rank7(acc);
            i += 1;
        }
        assert_qm31_canonical(acc);
    }
}
