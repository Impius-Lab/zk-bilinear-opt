//! `#![no_std]` Zero-Dependency Zcash `Halo2` / `BLS12-381` & `Pasta` (`Pallas` / `Vesta`)
//! Bilinear Extension-Tower Kernels and PlonKish Lookup-Cell / CRT Cost Estimators.
//!
//! Covers two tightly integrated layers for the Zcash `orchard` / `bls12_381` / `pasta_curves` stack:
//! 1. **Generic `PrimeFieldOps` Pairing-Tower Kernels (`BLS12-381`)**:
//!    - [`Fp2`]: $`\mathbb{F}_p[u]/(u^2 + 1)`$ — **Rank-3** (`3` muls vs `4` schoolbook).
//!    - [`Fp6`]: $`\mathbb{F}_{p^2}[v]/(v^3 - (u + 1))`$ — **Rank-11** (`11` muls via unimodular
//!      $`u = v^3 - 1 \implies v^6 - 2v^3 + 2 = 0`$) vs `18` (`Fp6::mul_schoolbook18`) and `15`
//!      (`Fp6::mul_karatsuba15` Toom-3).
//!    - [`Fp12`]: $`\mathbb{F}_{p^6}[w]/(w^2 - v)`$ — **Rank-23** (`23` muls via unimodular
//!      $`u = w^6 - 1 \implies w^{12} - 2w^6 + 2 = 0`$, `-57.41%` vs `54` Karatsuba) plus sparse
//!      Miller-loop line multiplications:
//!      * [`Fp12::mul_by_014_rank18`] (`self * (1 + c1*v + y_p*v*w)` normalized untwisted-`G1` line:
//!        **`18`** muls vs `54`, `-66.67%`),
//!      * [`Fp12::mul_by_014_unit_rank19`] (`self * (1 + c1*v + c4*v*w)` matching
//!        `zkcrypto/bls12_381`'s `mul_by_014_unit`: **`19`** muls),
//!      * [`Fp12::mul_by_014_projective_rank21`] (`self * (c0 + c1*v + c4*v*w)` general projective
//!        `014` line: **`21`** muls vs `39` Karatsuba / `54` schoolbook).
//! 2. **Exact PlonKish `Halo2LookupCostModel` & `gnark#1951` `quoBits` CRT Calculator**:
//!    - Exact 1024-bit integer arithmetic (`U1024`) computing `posMax`, `negMax`,
//!      `maxQuo = max(floor(posMax / p), ceil(negMax / p))`, `quoBits = maxQuo.bit_len()`,
//!      `crtLowCarries`, signed carry range bounds, and small-field excess-quotient-bit soundness
//!      diagnostics (`2 * limb_bits >= native_field_bits - 1`).
//!    - Compares Halo2 `FlexGate` + `RangeChip` (`lookup_bits` in `{8, 12, 16}`, `limb_bits` in
//!      `{88, 64}`) cell counts across `Schoolbook-54`, `Karatsuba-36`, `CRT-30`, and `Rank-23`
//!      non-native `BLS12-381` `Fp12` and `Pasta` (`Pallas` / `Vesta`) wrong-field CRT reductions.

use core::fmt::Debug;

// ============================================================================
// 1. Generic PrimeFieldOps Trait & Compile-Time Verified Lagrange Tables
// ============================================================================

/// Minimal `#![no_std]` prime-field operations trait distinguishing degree-0 constant
/// scaling (`scale_const`, folded into Halo2 fixed selector columns for 0 mul gates)
/// from degree-2 variable-variable multiplications (`mul`).
pub trait PrimeFieldOps: Copy + Clone + PartialEq + Eq + Debug {
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u64(v: u64) -> Self;
    fn add(self, rhs: Self) -> Self;
    fn sub(self, rhs: Self) -> Self;
    fn neg(self) -> Self;
    /// Multiply a witness value by a compile-time / setup-time field constant (degree-0 in PlonK/R1CS).
    fn scale_const(self, constant: Self) -> Self;
    /// Multiply two witness values (`a * b`, 1 degree-2 multiplicative gate).
    fn mul(self, rhs: Self) -> Self;
    /// Multiplicative inverse of a non-zero constant (called only during weight-table setup).
    fn inv_const(self) -> Self;

    #[inline]
    fn double(self) -> Self {
        self.add(self)
    }

    /// Convert a signed 128-bit integer literal into `Self` cleanly over any modulus.
    fn from_i128(v: i128) -> Self {
        let mag: u128 = v.unsigned_abs();
        let lo = (mag & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        let hi = (mag >> 64) as u64;
        let abs_fe = if hi == 0 {
            Self::from_u64(lo)
        } else {
            // 2^64 = 2^32 * 2^32 as compile-time constants
            let two32 = Self::from_u64(1u64 << 32);
            let two64 = two32.scale_const(two32);
            Self::from_u64(hi)
                .scale_const(two64)
                .add(Self::from_u64(lo))
        };
        if v < 0 {
            abs_fe.neg()
        } else {
            abs_fe
        }
    }

    /// Evaluate a small integer scalar multiple `coeff * self` via shift-and-add (`0` `mul` gates).
    #[inline]
    fn mul_small_i64(self, coeff: i64) -> Self {
        if coeff == 0 {
            return Self::zero();
        }
        let mut mag = coeff.unsigned_abs();
        let mut base = self;
        let mut acc = Self::zero();
        while mag > 0 {
            if (mag & 1) != 0 {
                acc = acc.add(base);
            }
            mag >>= 1;
            if mag > 0 {
                base = base.double();
            }
        }
        if coeff < 0 {
            acc.neg()
        } else {
            acc
        }
    }
}

/// Compile-time verified Even/Odd Lagrange interpolation polynomial table over $\mathbb{Z}$
/// for degree $\le D_{\max}$ products evaluated at $\{0, \pm 1, \dots, \pm K\}$ (plus $\infty$
/// when `HAS_INF` is `true`, i.e., $D_{\max} = 2K + 1$).
#[derive(Clone, Copy, Debug)]
pub struct EvenOddLagrangeTable<const K: usize, const EVEN_LEN: usize, const ODD_LEN: usize> {
    pub even_num: [[i128; EVEN_LEN]; EVEN_LEN],
    pub even_den: [i128; EVEN_LEN],
    pub odd_num: [[i128; ODD_LEN]; ODD_LEN],
    pub odd_den: [i128; ODD_LEN],
    pub has_inf: bool,
}

impl<const K: usize, const EVEN_LEN: usize, const ODD_LEN: usize>
    EvenOddLagrangeTable<K, EVEN_LEN, ODD_LEN>
{
    pub const fn build(has_inf: bool) -> Self {
        assert!(EVEN_LEN == K + 1);
        if has_inf {
            assert!(ODD_LEN == K + 1);
        } else {
            assert!(ODD_LEN == K);
        }

        let mut ys = [0i128; EVEN_LEN];
        let mut i = 0;
        while i < EVEN_LEN {
            ys[i] = (i as i128) * (i as i128);
            i += 1;
        }

        let mut even_num = [[0i128; EVEN_LEN]; EVEN_LEN];
        let mut even_den = [0i128; EVEN_LEN];

        let mut idx = 0;
        while idx < EVEN_LEN {
            let mut poly = [0i128; EVEN_LEN];
            poly[0] = 1;
            let mut deg = 0usize;
            let mut den = 1i128;

            let mut j = 0;
            while j < EVEN_LEN {
                if j != idx {
                    let mut next = [0i128; EVEN_LEN];
                    let mut d = 0;
                    while d <= deg {
                        next[d] -= poly[d] * ys[j];
                        next[d + 1] += poly[d];
                        d += 1;
                    }
                    poly = next;
                    deg += 1;
                    den *= ys[idx] - ys[j];
                }
                j += 1;
            }
            if idx >= 1 {
                den *= 2; // S_idx = P(idx) + P(-idx) = 2 * C_even(idx^2)
            }
            if den < 0 {
                den = -den;
                let mut d = 0;
                while d < EVEN_LEN {
                    poly[d] = -poly[d];
                    d += 1;
                }
            }
            even_num[idx] = poly;
            even_den[idx] = den;
            idx += 1;
        }

        let mut odd_num = [[0i128; ODD_LEN]; ODD_LEN];
        let mut odd_den = [0i128; ODD_LEN];

        let mut o_idx = 0;
        while o_idx < K {
            let k_val = (o_idx + 1) as i128;
            let y_here = k_val * k_val;
            let mut poly = [0i128; ODD_LEN];
            poly[0] = 1;
            let mut deg = 0usize;
            let mut den = 1i128;

            let mut j = 0;
            while j < K {
                if j != o_idx {
                    let y_other = ((j + 1) as i128) * ((j + 1) as i128);
                    let mut next = [0i128; ODD_LEN];
                    let mut d = 0;
                    while d <= deg {
                        next[d] -= poly[d] * y_other;
                        next[d + 1] += poly[d];
                        d += 1;
                    }
                    poly = next;
                    deg += 1;
                    den *= y_here - y_other;
                }
                j += 1;
            }
            den *= 2 * k_val; // D_k = P(k) - P(-k) = 2 * k * C_odd(k^2)
            if den < 0 {
                den = -den;
                let mut d = 0;
                while d < ODD_LEN {
                    poly[d] = -poly[d];
                    d += 1;
                }
            }
            odd_num[o_idx] = poly;
            odd_den[o_idx] = den;
            o_idx += 1;
        }

        if has_inf {
            // Monic polynomial prod_{k=1}^K (Y - k^2) recovers leading odd coefficient m_inf
            let mut poly = [0i128; ODD_LEN];
            poly[0] = 1;
            let mut deg = 0usize;
            let mut j = 0;
            while j < K {
                let y_other = ((j + 1) as i128) * ((j + 1) as i128);
                let mut next = [0i128; ODD_LEN];
                let mut d = 0;
                while d <= deg {
                    next[d] -= poly[d] * y_other;
                    next[d + 1] += poly[d];
                    d += 1;
                }
                poly = next;
                deg += 1;
                j += 1;
            }
            odd_num[K] = poly;
            odd_den[K] = 1;
        }

        // Compile-time Vandermonde exactness verification across all nodes!
        let mut r = 0;
        while r < EVEN_LEN {
            let mut pt = 0;
            while pt < EVEN_LEN {
                let y = ys[pt];
                let mut y_pow = 1i128;
                let mut acc = 0i128;
                let mut d = 0;
                while d < EVEN_LEN {
                    acc += even_num[r][d] * y_pow;
                    if d + 1 < EVEN_LEN {
                        y_pow *= y;
                    }
                    d += 1;
                }
                let scale = if r == 0 { 1i128 } else { 2i128 };
                let expected = if r == pt { even_den[r] / scale } else { 0i128 };
                assert!(acc == expected);
                pt += 1;
            }
            r += 1;
        }

        let mut orow = 0;
        while orow < K {
            let mut pt = 0;
            while pt < K {
                let k_pt = (pt + 1) as i128;
                let y = k_pt * k_pt;
                let mut y_pow = 1i128;
                let mut acc = 0i128;
                let mut d = 0;
                while d < ODD_LEN {
                    acc += odd_num[orow][d] * y_pow;
                    if d + 1 < ODD_LEN {
                        y_pow *= y;
                    }
                    d += 1;
                }
                let k_row = (orow + 1) as i128;
                let expected = if orow == pt {
                    odd_den[orow] / (2 * k_row)
                } else {
                    0i128
                };
                assert!(acc == expected);
                pt += 1;
            }
            orow += 1;
        }

        Self {
            even_num,
            even_den,
            odd_num,
            odd_den,
            has_inf,
        }
    }
}

/// Compile-time verified `Rank-11` Lagrange table (`deg <= 10`, $K = 5$, $\{0, \pm 1, \dots, \pm 5\}$).
pub const FP6_LAGRANGE_RANK11: EvenOddLagrangeTable<5, 6, 5> =
    EvenOddLagrangeTable::<5, 6, 5>::build(false);

/// Compile-time verified `Rank-18` Lagrange table (`deg <= 17`, $K = 8$, $\{0, \pm 1, \dots, \pm 8, \infty\}$).
pub const FP12_LAGRANGE_RANK18_AFFINE: EvenOddLagrangeTable<8, 9, 9> =
    EvenOddLagrangeTable::<8, 9, 9>::build(true);

/// Compile-time verified `Rank-19` Lagrange table (`deg <= 18`, $K = 9$, $\{0, \pm 1, \dots, \pm 9\}$).
pub const FP12_LAGRANGE_RANK19_UNIT: EvenOddLagrangeTable<9, 10, 9> =
    EvenOddLagrangeTable::<9, 10, 9>::build(false);

/// Compile-time verified `Rank-21` Lagrange table (`deg <= 20`, $K = 10$, $\{0, \pm 1, \dots, \pm 10\}$).
pub const FP12_LAGRANGE_RANK21_PROJ: EvenOddLagrangeTable<10, 11, 10> =
    EvenOddLagrangeTable::<10, 11, 10>::build(false);

/// Compile-time verified `Rank-23` Lagrange table (`deg <= 22`, $K = 11$, $\{0, \pm 1, \dots, \pm 11\}$).
pub const FP12_LAGRANGE_RANK23_FULL: EvenOddLagrangeTable<11, 12, 11> =
    EvenOddLagrangeTable::<11, 12, 11>::build(false);

/// Folded modular weight matrices over `F` for Zcash `BLS12-381` `Fp6` (`v^6 - 2v^3 + 2 = 0`)
/// and `Fp12` (`w^12 - 2w^6 + 2 = 0`) minimum-rank bilinear schedules.
#[derive(Clone, Debug)]
pub struct Bls12381TowerWeights<F: PrimeFieldOps> {
    pub inv_two: F,
    pub inv_six: F,
    /// `Fp6` `Rank-11` folded weights: since `v^6 = 2v^3 - 2` mixes parity (`v^7 = 2v^4 - 2v`,
    /// `v^9 = 2v^6 - 2v^3 = 2v^3 - 4`), all 6 output coordinates read `[even(6), odd(5)]` (`11` modes).
    pub fp6_rank11: [[F; 11]; 6],
    /// `Fp12` `Rank-23` folded even (`6 x 12`) and odd (`6 x 11`) weights (`w^12 = 2w^6 - 2` preserves parity!).
    pub fp12_rank23_even: [[F; 12]; 6],
    pub fp12_rank23_odd: [[F; 11]; 6],
    /// `Fp12` `Rank-18` normalized untwisted-`G1` affine `mul_by_014` (`9` even + `9` odd = `18` muls).
    pub fp12_rank18_even: [[F; 9]; 6],
    pub fp12_rank18_odd: [[F; 9]; 6],
    /// `Fp12` `Rank-19` unit-prepared `mul_by_014_unit` (`10` even + `9` odd = `19` muls).
    pub fp12_rank19_even: [[F; 10]; 6],
    pub fp12_rank19_odd: [[F; 9]; 6],
    /// `Fp12` `Rank-21` general projective `mul_by_014` (`11` even + `10` odd = `21` muls).
    pub fp12_rank21_even: [[F; 11]; 6],
    pub fp12_rank21_odd: [[F; 10]; 6],
}

fn fold_fp6_poly_i128(unreduced: &[i128; 11]) -> [i128; 6] {
    // Reduce degree <= 10 polynomial modulo (v^6 - 2*v^3 + 2 = 0 => v^6 = 2*v^3 - 2).
    let mut r = *unreduced;
    let mut deg = 10usize;
    while deg >= 6 {
        let c = r[deg];
        if c != 0 {
            let shift = deg - 6;
            r[shift] -= 2 * c;
            r[shift + 3] += 2 * c;
            r[deg] = 0;
        }
        deg -= 1;
    }
    [r[0], r[1], r[2], r[3], r[4], r[5]]
}

fn fold_fp12_half_parity_i128<const LEN: usize>(half: &[i128; LEN]) -> [i128; 6] {
    // Both C_even(w^2) and w * C_odd(w^2) satisfy Y^6 = w^12 = 2*w^6 - 2 = 2*Y^3 - 2!
    // Hence reducing in Y = w^2 uses the exact trinomial Y^6 - 2*Y^3 + 2 = 0!
    assert!(LEN <= 12);
    let mut buf = [0i128; 12];
    let mut i = 0;
    while i < LEN {
        buf[i] = half[i];
        i += 1;
    }
    let mut deg = 11usize;
    while deg >= 6 {
        let c = buf[deg];
        if c != 0 {
            let shift = deg - 6;
            buf[shift] -= 2 * c;
            buf[shift + 3] += 2 * c;
            buf[deg] = 0;
        }
        deg -= 1;
    }
    [buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]]
}

fn build_fp12_folded_pair<
    F: PrimeFieldOps,
    const K: usize,
    const EVEN_LEN: usize,
    const ODD_LEN: usize,
>(
    tbl: &EvenOddLagrangeTable<K, EVEN_LEN, ODD_LEN>,
) -> ([[F; EVEN_LEN]; 6], [[F; ODD_LEN]; 6]) {
    let mut even_out = [[F::zero(); EVEN_LEN]; 6];
    let mut col = 0;
    while col < EVEN_LEN {
        let inv_den = F::from_i128(tbl.even_den[col]).inv_const();
        let folded = fold_fp12_half_parity_i128(&tbl.even_num[col]);
        let mut u = 0;
        while u < 6 {
            even_out[u][col] = F::from_i128(folded[u]).scale_const(inv_den);
            u += 1;
        }
        col += 1;
    }

    let mut odd_out = [[F::zero(); ODD_LEN]; 6];
    let mut ocol = 0;
    while ocol < ODD_LEN {
        let inv_den = F::from_i128(tbl.odd_den[ocol]).inv_const();
        let folded = fold_fp12_half_parity_i128(&tbl.odd_num[ocol]);
        let mut u = 0;
        while u < 6 {
            odd_out[u][ocol] = F::from_i128(folded[u]).scale_const(inv_den);
            u += 1;
        }
        ocol += 1;
    }

    (even_out, odd_out)
}

impl<F: PrimeFieldOps> Bls12381TowerWeights<F> {
    /// Precompute all folded modular interpolation constants over `F` (requires $\gcd(22!, p) = 1$,
    /// i.e., any prime $p > 23$, which holds for `BLS12-381`, `Pallas`, `Vesta`, `BN254`, etc.).
    pub fn new() -> Self {
        let inv_two = F::from_u64(2).inv_const();
        let inv_six = F::from_u64(6).inv_const();

        let mut fp6_rank11 = [[F::zero(); 11]; 6];
        let mut idx = 0;
        while idx < 6 {
            let inv_den = F::from_i128(FP6_LAGRANGE_RANK11.even_den[idx]).inv_const();
            let mut unred = [0i128; 11];
            let mut d = 0;
            while d < 6 {
                unred[2 * d] = FP6_LAGRANGE_RANK11.even_num[idx][d];
                d += 1;
            }
            let folded = fold_fp6_poly_i128(&unred);
            let mut k = 0;
            while k < 6 {
                fp6_rank11[k][idx] = F::from_i128(folded[k]).scale_const(inv_den);
                k += 1;
            }
            idx += 1;
        }

        let mut oidx = 0;
        while oidx < 5 {
            let inv_den = F::from_i128(FP6_LAGRANGE_RANK11.odd_den[oidx]).inv_const();
            let mut unred = [0i128; 11];
            let mut d = 0;
            while d < 5 {
                unred[2 * d + 1] = FP6_LAGRANGE_RANK11.odd_num[oidx][d];
                d += 1;
            }
            let folded = fold_fp6_poly_i128(&unred);
            let mut k = 0;
            while k < 6 {
                fp6_rank11[k][6 + oidx] = F::from_i128(folded[k]).scale_const(inv_den);
                k += 1;
            }
            oidx += 1;
        }

        let (fp12_rank23_even, fp12_rank23_odd) =
            build_fp12_folded_pair(&FP12_LAGRANGE_RANK23_FULL);
        let (fp12_rank18_even, fp12_rank18_odd) =
            build_fp12_folded_pair(&FP12_LAGRANGE_RANK18_AFFINE);
        let (fp12_rank19_even, fp12_rank19_odd) =
            build_fp12_folded_pair(&FP12_LAGRANGE_RANK19_UNIT);
        let (fp12_rank21_even, fp12_rank21_odd) =
            build_fp12_folded_pair(&FP12_LAGRANGE_RANK21_PROJ);

        Self {
            inv_two,
            inv_six,
            fp6_rank11,
            fp12_rank23_even,
            fp12_rank23_odd,
            fp12_rank18_even,
            fp12_rank18_odd,
            fp12_rank19_even,
            fp12_rank19_odd,
            fp12_rank21_even,
            fp12_rank21_odd,
        }
    }
}

impl<F: PrimeFieldOps> Default for Bls12381TowerWeights<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn eval_half_poly6<F: PrimeFieldOps>(p: &[F; 6], start: usize, y: i64) -> F {
    // Evaluate p[start] + p[start+2]*y + p[start+4]*y^2 via Horner (`0` mul gates)
    let mut acc = p[start + 4];
    acc = acc.mul_small_i64(y).add(p[start + 2]);
    acc.mul_small_i64(y).add(p[start])
}

#[inline]
fn eval_half_poly12<F: PrimeFieldOps>(p: &[F; 12], start: usize, max_deg: usize, y: i64) -> F {
    // Evaluate sum_{2*j + start <= max_deg} p[2*j + start] * y^j via Horner (`0` mul gates)
    if max_deg < start {
        return F::zero();
    }
    let top_j = (max_deg - start) / 2;
    let mut acc = p[start + 2 * top_j];
    let mut j = top_j;
    while j > 0 {
        j -= 1;
        acc = acc.mul_small_i64(y).add(p[start + 2 * j]);
    }
    acc
}

fn eval_fp12_even_odd<
    F: PrimeFieldOps,
    const K: usize,
    const EVEN_LEN: usize,
    const ODD_LEN: usize,
>(
    a: &[F; 12],
    b: &[F; 12],
    max_deg_a: usize,
    max_deg_b: usize,
    has_inf: bool,
    even_w: &[[F; EVEN_LEN]; 6],
    odd_w: &[[F; ODD_LEN]; 6],
) -> [F; 12] {
    let mut even_modes = [F::zero(); EVEN_LEN];
    let mut odd_modes = [F::zero(); ODD_LEN];

    even_modes[0] = a[0].mul(b[0]);

    let mut k = 1usize;
    while k <= K {
        let k64 = k as i64;
        let y64 = k64 * k64;
        let ea = eval_half_poly12(a, 0, max_deg_a, y64);
        let oa = eval_half_poly12(a, 1, max_deg_a, y64).mul_small_i64(k64);
        let eb = eval_half_poly12(b, 0, max_deg_b, y64);
        let ob = eval_half_poly12(b, 1, max_deg_b, y64).mul_small_i64(k64);

        let p_pos = ea.add(oa).mul(eb.add(ob));
        let p_neg = ea.sub(oa).mul(eb.sub(ob));
        even_modes[k] = p_pos.add(p_neg);
        odd_modes[k - 1] = p_pos.sub(p_neg);
        k += 1;
    }

    if has_inf {
        odd_modes[K] = a[max_deg_a].mul(b[max_deg_b]);
    }

    let mut out = [F::zero(); 12];
    let mut u = 0usize;
    while u < 6 {
        let mut acc_e = F::zero();
        let mut c = 0usize;
        while c < EVEN_LEN {
            acc_e = acc_e.add(even_modes[c].scale_const(even_w[u][c]));
            c += 1;
        }
        out[2 * u] = acc_e;

        let mut acc_o = F::zero();
        let mut oc = 0usize;
        while oc < ODD_LEN {
            acc_o = acc_o.add(odd_modes[oc].scale_const(odd_w[u][oc]));
            oc += 1;
        }
        out[2 * u + 1] = acc_o;
        u += 1;
    }
    out
}

// ============================================================================
// 2. Zcash BLS12-381 Tower Gadgets: Fp2 (Rank-3), Fp6 (Rank-11), Fp12 (Rank-23 & 014 Rank-18)
// ============================================================================

/// Quadratic extension $\mathbb{F}_{p^2} = \mathbb{F}_p[u] / (u^2 + 1)$ (`c0 + c1 * u`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp2<F: PrimeFieldOps> {
    pub c0: F,
    pub c1: F,
}

#[allow(clippy::should_implement_trait)]
impl<F: PrimeFieldOps> Fp2<F> {
    #[inline]
    pub fn new(c0: F, c1: F) -> Self {
        Self { c0, c1 }
    }

    #[inline]
    pub fn zero() -> Self {
        Self {
            c0: F::zero(),
            c1: F::zero(),
        }
    }

    #[inline]
    pub fn one() -> Self {
        Self {
            c0: F::one(),
            c1: F::zero(),
        }
    }

    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
        }
    }

    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
        }
    }

    #[inline]
    pub fn neg(self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    #[inline]
    pub fn double(self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
        }
    }

    #[inline]
    pub fn scale_const_fp(self, c: F) -> Self {
        Self {
            c0: self.c0.scale_const(c),
            c1: self.c1.scale_const(c),
        }
    }

    /// Multiply by cubic non-residue $\xi = u + 1$ in $\mathbb{F}_p[u]/(u^2 + 1)$:
    /// $(c_0 + c_1 u)(1 + u) = (c_0 - c_1) + (c_0 + c_1) u$ (`0` multiplications).
    #[inline]
    pub fn mul_by_nonresidue(self) -> Self {
        Self {
            c0: self.c0.sub(self.c1),
            c1: self.c0.add(self.c1),
        }
    }

    /// Reference schoolbook multiplication (`4` `F::mul` calls).
    #[inline]
    pub fn mul_schoolbook4(self, rhs: Self) -> Self {
        let a0b0 = self.c0.mul(rhs.c0);
        let a1b1 = self.c1.mul(rhs.c1);
        let a0b1 = self.c0.mul(rhs.c1);
        let a1b0 = self.c1.mul(rhs.c0);
        Self {
            c0: a0b0.sub(a1b1),
            c1: a0b1.add(a1b0),
        }
    }

    /// Optimal Winograd / Gauss **Rank-3** multiplication (`3` `F::mul` calls).
    #[inline]
    pub fn mul_rank3(self, rhs: Self) -> Self {
        let m0 = self.c0.mul(rhs.c0);
        let m1 = self.c1.mul(rhs.c1);
        let m2 = self.c0.add(self.c1).mul(rhs.c0.add(rhs.c1));
        Self {
            c0: m0.sub(m1),
            c1: m2.sub(m0).sub(m1),
        }
    }

    /// Optimal **Rank-2** complex squaring (`2` `F::mul` calls).
    #[inline]
    pub fn square_rank2(self) -> Self {
        let c0 = self.c0.add(self.c1).mul(self.c0.sub(self.c1));
        let c1 = self.c0.mul(self.c1).double();
        Self { c0, c1 }
    }
}

/// Sextic extension $\mathbb{F}_{p^6} = \mathbb{F}_{p^2}[v] / (v^3 - (u + 1))$ (`c0 + c1*v + c2*v^2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp6<F: PrimeFieldOps> {
    pub c0: Fp2<F>,
    pub c1: Fp2<F>,
    pub c2: Fp2<F>,
}

#[allow(clippy::should_implement_trait)]
impl<F: PrimeFieldOps> Fp6<F> {
    #[inline]
    pub fn new(c0: Fp2<F>, c1: Fp2<F>, c2: Fp2<F>) -> Self {
        Self { c0, c1, c2 }
    }

    #[inline]
    pub fn zero() -> Self {
        Self {
            c0: Fp2::zero(),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }

    #[inline]
    pub fn one() -> Self {
        Self {
            c0: Fp2::one(),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }

    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
            c2: self.c2.add(rhs.c2),
        }
    }

    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
            c2: self.c2.sub(rhs.c2),
        }
    }

    #[inline]
    pub fn neg(self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    /// Multiply by quadratic non-residue $v$ in $\mathbb{F}_{p^6}$:
    /// $v (c_0 + c_1 v + c_2 v^2) = \xi c_2 + c_0 v + c_1 v^2$ (`0` multiplications).
    #[inline]
    pub fn mul_by_nonresidue(self) -> Self {
        Self {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }

    /// Division-free unimodular ($\det = \pm 1$) isomorphism into $\mathbb{F}_p[v]/(v^6 - 2v^3 + 2)$:
    /// since $u = v^3 - 1$, $\sum_{j=0}^2 (a_j + b_j u) v^j = \sum_{j=0}^2 (a_j - b_j) v^j + \sum_{j=0}^2 b_j v^{j+3}$.
    #[inline]
    pub fn to_simple_basis(&self) -> [F; 6] {
        [
            self.c0.c0.sub(self.c0.c1),
            self.c1.c0.sub(self.c1.c1),
            self.c2.c0.sub(self.c2.c1),
            self.c0.c1,
            self.c1.c1,
            self.c2.c1,
        ]
    }

    /// Inverse unimodular isomorphism from $\mathbb{F}_p[v]/(v^6 - 2v^3 + 2)$ back to canonical `Fp6`.
    #[inline]
    pub fn from_simple_basis(p: &[F; 6]) -> Self {
        Self {
            c0: Fp2::new(p[0].add(p[3]), p[3]),
            c1: Fp2::new(p[1].add(p[4]), p[4]),
            c2: Fp2::new(p[2].add(p[5]), p[5]),
        }
    }

    /// Definitional 9-product `Fp2::mul_schoolbook4` reference (`36` `F::mul` calls).
    pub fn mul_schoolbook_ref(self, rhs: Self) -> Self {
        let a = [self.c0, self.c1, self.c2];
        let b = [rhs.c0, rhs.c1, rhs.c2];
        let mut prod = [Fp2::zero(); 5];
        for i in 0..3 {
            for j in 0..3 {
                prod[i + j] = prod[i + j].add(a[i].mul_schoolbook4(b[j]));
            }
        }
        let c0 = prod[0].add(prod[3].mul_by_nonresidue());
        let c1 = prod[1].add(prod[4].mul_by_nonresidue());
        let c2 = prod[2];
        Self { c0, c1, c2 }
    }

    /// Standard 6-`Fp2` Karatsuba tower baseline (`6 * 3 = 18` `F::mul` calls).
    pub fn mul_schoolbook18(self, rhs: Self) -> Self {
        let v0 = self.c0.mul_rank3(rhs.c0);
        let v1 = self.c1.mul_rank3(rhs.c1);
        let v2 = self.c2.mul_rank3(rhs.c2);

        let c01 = self
            .c0
            .add(self.c1)
            .mul_rank3(rhs.c0.add(rhs.c1))
            .sub(v0)
            .sub(v1);
        let c12 = self
            .c1
            .add(self.c2)
            .mul_rank3(rhs.c1.add(rhs.c2))
            .sub(v1)
            .sub(v2);
        let c02 = self
            .c0
            .add(self.c2)
            .mul_rank3(rhs.c0.add(rhs.c2))
            .sub(v0)
            .sub(v2);

        Self {
            c0: v0.add(c12.mul_by_nonresidue()),
            c1: c01.add(v2.mul_by_nonresidue()),
            c2: c02.add(v1),
        }
    }

    /// Toom-3 $\times$ Rank-3 `Fp2` baseline at $\{0, 1, -1, 2, \infty\}$ (`5 * 3 = 15` `F::mul` calls).
    pub fn mul_karatsuba15(self, rhs: Self, weights: &Bls12381TowerWeights<F>) -> Self {
        let v0 = self.c0.mul_rank3(rhs.c0);
        let v_inf = self.c2.mul_rank3(rhs.c2);

        let a_sum02 = self.c0.add(self.c2);
        let b_sum02 = rhs.c0.add(rhs.c2);
        let v1 = a_sum02.add(self.c1).mul_rank3(b_sum02.add(rhs.c1));
        let v_neg1 = a_sum02.sub(self.c1).mul_rank3(b_sum02.sub(rhs.c1));

        let a2 = self.c0.add(self.c1.double()).add(self.c2.double().double());
        let b2 = rhs.c0.add(rhs.c1.double()).add(rhs.c2.double().double());
        let v2 = a2.mul_rank3(b2);

        let e_sum = v1.add(v_neg1).scale_const_fp(weights.inv_two);
        let o_sum = v1.sub(v_neg1).scale_const_fp(weights.inv_two);
        let d2 = e_sum.sub(v0).sub(v_inf);

        let v_inf_16 = v_inf.double().double().double().double();
        let d3_num = v2
            .sub(v0)
            .sub(d2.double().double())
            .sub(v_inf_16)
            .sub(o_sum.double());
        let d3 = d3_num.scale_const_fp(weights.inv_six);
        let d1 = o_sum.sub(d3);

        Self {
            c0: v0.add(d3.mul_by_nonresidue()),
            c1: d1.add(v_inf.mul_by_nonresidue()),
            c2: d2,
        }
    }

    /// Winograd / Alder–Strassen optimal **Rank-11** multiplication (`11` `F::mul` calls,
    /// `-38.89%` vs `18` and `-26.67%` vs `15`).
    pub fn mul_rank11(self, rhs: Self, weights: &Bls12381TowerWeights<F>) -> Self {
        let pa = self.to_simple_basis();
        let pb = rhs.to_simple_basis();

        let mut modes = [F::zero(); 11];
        modes[0] = pa[0].mul(pb[0]);

        let mut k = 1usize;
        while k <= 5 {
            let k64 = k as i64;
            let y64 = k64 * k64;
            let ea = eval_half_poly6(&pa, 0, y64);
            let oa = eval_half_poly6(&pa, 1, y64).mul_small_i64(k64);
            let eb = eval_half_poly6(&pb, 0, y64);
            let ob = eval_half_poly6(&pb, 1, y64).mul_small_i64(k64);

            let p_pos = ea.add(oa).mul(eb.add(ob));
            let p_neg = ea.sub(oa).mul(eb.sub(ob));
            modes[k] = p_pos.add(p_neg);
            modes[5 + k] = p_pos.sub(p_neg);
            k += 1;
        }

        let mut out_poly = [F::zero(); 6];
        for (u, row) in weights.fp6_rank11.iter().enumerate() {
            let mut acc = F::zero();
            for (m, &w) in modes.iter().zip(row.iter()) {
                acc = acc.add(m.scale_const(w));
            }
            out_poly[u] = acc;
        }
        Self::from_simple_basis(&out_poly)
    }

    /// Sparse `01` multiplication $(c_0 + c_1 v + c_2 v^2)(d_0 + d_1 v)$ (`5 * 3 = 15` `F::mul` calls).
    pub fn mul_by_01_karatsuba15(self, d0: Fp2<F>, d1: Fp2<F>) -> Self {
        let t0 = self.c0.mul_rank3(d0);
        let t1 = self.c1.mul_rank3(d1);
        let c1 = self.c0.add(self.c1).mul_rank3(d0.add(d1)).sub(t0).sub(t1);
        let t21 = self.c2.mul_rank3(d1);
        let t20 = self.c2.mul_rank3(d0);
        Self {
            c0: t0.add(t21.mul_by_nonresidue()),
            c1,
            c2: t20.add(t1),
        }
    }

    /// Monomial `1` multiplication $(c_0 + c_1 v + c_2 v^2)(d_1 v)$ (`3 * 3 = 9` `F::mul` calls).
    pub fn mul_by_1_karatsuba9(self, d1: Fp2<F>) -> Self {
        Self {
            c0: self.c2.mul_rank3(d1).mul_by_nonresidue(),
            c1: self.c0.mul_rank3(d1),
            c2: self.c1.mul_rank3(d1),
        }
    }
}

/// Dodecic pairing target extension $\mathbb{F}_{p^{12}} = \mathbb{F}_{p^6}[w] / (w^2 - v)$ (`c0 + c1*w`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp12<F: PrimeFieldOps> {
    pub c0: Fp6<F>,
    pub c1: Fp6<F>,
}

#[allow(clippy::should_implement_trait)]
impl<F: PrimeFieldOps> Fp12<F> {
    #[inline]
    pub fn new(c0: Fp6<F>, c1: Fp6<F>) -> Self {
        Self { c0, c1 }
    }

    #[inline]
    pub fn zero() -> Self {
        Self {
            c0: Fp6::zero(),
            c1: Fp6::zero(),
        }
    }

    #[inline]
    pub fn one() -> Self {
        Self {
            c0: Fp6::one(),
            c1: Fp6::zero(),
        }
    }

    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
        }
    }

    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
        }
    }

    /// Division-free unimodular ($\det = \pm 1$) isomorphism into $\mathbb{F}_p[w]/(w^{12} - 2w^6 + 2)$:
    /// since $v = w^2$ and $u = w^6 - 1$, `w^0=c0.c0`, `w^1=c1.c0`, `w^2=c0.c1`, `w^3=c1.c1`,
    /// `w^4=c0.c2`, `w^5=c1.c2`.
    #[inline]
    pub fn to_simple_basis(&self) -> [F; 12] {
        let pairs = [
            self.c0.c0, self.c1.c0, self.c0.c1, self.c1.c1, self.c0.c2, self.c1.c2,
        ];
        [
            pairs[0].c0.sub(pairs[0].c1),
            pairs[1].c0.sub(pairs[1].c1),
            pairs[2].c0.sub(pairs[2].c1),
            pairs[3].c0.sub(pairs[3].c1),
            pairs[4].c0.sub(pairs[4].c1),
            pairs[5].c0.sub(pairs[5].c1),
            pairs[0].c1,
            pairs[1].c1,
            pairs[2].c1,
            pairs[3].c1,
            pairs[4].c1,
            pairs[5].c1,
        ]
    }

    /// Inverse unimodular isomorphism from $\mathbb{F}_p[w]/(w^{12} - 2w^6 + 2)$ back to `Fp12`.
    #[inline]
    pub fn from_simple_basis(p: &[F; 12]) -> Self {
        let w0 = Fp2::new(p[0].add(p[6]), p[6]);
        let w1 = Fp2::new(p[1].add(p[7]), p[7]);
        let w2 = Fp2::new(p[2].add(p[8]), p[8]);
        let w3 = Fp2::new(p[3].add(p[9]), p[9]);
        let w4 = Fp2::new(p[4].add(p[10]), p[10]);
        let w5 = Fp2::new(p[5].add(p[11]), p[11]);
        Self {
            c0: Fp6::new(w0, w2, w4),
            c1: Fp6::new(w1, w3, w5),
        }
    }

    /// Multiply by $v = w^2$ in $\mathbb{F}_{p^{12}}$ (`0` multiplications).
    #[inline]
    pub fn mul_by_v(self) -> Self {
        Self {
            c0: self.c0.mul_by_nonresidue(),
            c1: self.c1.mul_by_nonresidue(),
        }
    }

    /// Definitional schoolbook tower reference (`144` `F::mul` calls).
    pub fn mul_schoolbook_ref(self, rhs: Self) -> Self {
        let c00 = self.c0.mul_schoolbook_ref(rhs.c0);
        let c11 = self.c1.mul_schoolbook_ref(rhs.c1);
        let c01 = self.c0.mul_schoolbook_ref(rhs.c1);
        let c10 = self.c1.mul_schoolbook_ref(rhs.c0);
        Self {
            c0: c00.add(c11.mul_by_nonresidue()),
            c1: c01.add(c10),
        }
    }

    /// Standard $3 \times 6 \times 3$ Karatsuba baseline (`54` `F::mul` calls).
    pub fn mul_karatsuba54(self, rhs: Self) -> Self {
        let t0 = self.c0.mul_schoolbook18(rhs.c0);
        let t1 = self.c1.mul_schoolbook18(rhs.c1);
        let t01 = self
            .c0
            .add(self.c1)
            .mul_schoolbook18(rhs.c0.add(rhs.c1))
            .sub(t0)
            .sub(t1);
        Self {
            c0: t0.add(t1.mul_by_nonresidue()),
            c1: t01,
        }
    }

    /// Winograd / Alder–Strassen optimal **Rank-23** multiplication (`23` `F::mul` calls,
    /// `-57.41%` vs `54` Karatsuba).
    pub fn mul_rank23(self, rhs: Self, weights: &Bls12381TowerWeights<F>) -> Self {
        let pa = self.to_simple_basis();
        let pb = rhs.to_simple_basis();
        let out_poly = eval_fp12_even_odd::<F, 11, 12, 11>(
            &pa,
            &pb,
            11,
            11,
            false,
            &weights.fp12_rank23_even,
            &weights.fp12_rank23_odd,
        );
        Self::from_simple_basis(&out_poly)
    }

    /// Direct expansion matching `zkcrypto/bls12_381`'s `Fp12::mul_by_014` (`18` `Fp2` products = `54` `F::mul`s).
    pub fn mul_by_014_schoolbook54(self, c0: Fp2<F>, c1: Fp2<F>, c4: Fp2<F>) -> Self {
        let xc1 = c1.mul_by_nonresidue();
        let xc4 = c4.mul_by_nonresidue();
        let a = self.c0;
        let b = self.c1;
        let sum3 = |x0: Fp2<F>, y0: Fp2<F>, x1: Fp2<F>, y1: Fp2<F>, x2: Fp2<F>, y2: Fp2<F>| {
            x0.mul_rank3(y0).add(x1.mul_rank3(y1)).add(x2.mul_rank3(y2))
        };
        Self {
            c0: Fp6::new(
                sum3(a.c0, c0, a.c2, xc1, b.c1, xc4),
                sum3(a.c0, c1, a.c1, c0, b.c2, xc4),
                sum3(a.c1, c1, a.c2, c0, b.c0, c4),
            ),
            c1: Fp6::new(
                sum3(a.c2, xc4, b.c0, c0, b.c2, xc1),
                sum3(a.c0, c4, b.c0, c1, b.c1, c0),
                sum3(a.c1, c4, b.c1, c1, b.c2, c0),
            ),
        }
    }

    /// Aranha et al. Karatsuba sparse `mul_by_014` (`13` `Fp2` products = `39` `F::mul`s).
    pub fn mul_by_014_karatsuba39(self, c0: Fp2<F>, c1: Fp2<F>, c4: Fp2<F>) -> Self {
        let p0 = self.c0.mul_by_01_karatsuba15(c0, c1);
        let p1 = self.c1.mul_by_1_karatsuba9(c4);
        let p01 = self
            .c0
            .add(self.c1)
            .mul_by_01_karatsuba15(c0, c1.add(c4))
            .sub(p0)
            .sub(p1);
        Self {
            c0: p0.add(p1.mul_by_nonresidue()),
            c1: p01,
        }
    }

    /// **Rank-18** sparse `mul_by_014` for normalized untwisted-`G1` affine Miller-loop lines
    /// $\ell(P) = 1 + c_1 v + y_P v w$ (`c0 = 1`, `c1: Fp2`, `y_p: F`):
    /// computes `self + v * (self * (c1 + y_p * w))`, where $\deg_w(c_1 + y_P w) = 6$, requiring
    /// **18 `F::mul` calls** (`-66.67%` vs `54` Karatsuba / `zkcrypto` schoolbook, `-53.85%` vs `39`).
    pub fn mul_by_014_rank18(self, c1: Fp2<F>, y_p: F, weights: &Bls12381TowerWeights<F>) -> Self {
        let pa = self.to_simple_basis();
        let mut pb = [F::zero(); 12];
        // c1 + y_p * w = (c1.c0 - c1.c1) + y_p * w + c1.c1 * w^6  (degree 6 in w!)
        pb[0] = c1.c0.sub(c1.c1);
        pb[1] = y_p;
        pb[6] = c1.c1;

        let prod_poly = eval_fp12_even_odd::<F, 8, 9, 9>(
            &pa,
            &pb,
            11,
            6,
            true,
            &weights.fp12_rank18_even,
            &weights.fp12_rank18_odd,
        );
        let shifted = Self::from_simple_basis(&prod_poly).mul_by_v();
        self.add(shifted)
    }

    /// **Rank-19** sparse `mul_by_014_unit` matching `zkcrypto/bls12_381`'s prepared `G2` line
    /// $1 + c_1 v + c_4 v w$ (`c0 = 1`, `c1: Fp2`, `c4: Fp2`):
    /// $\deg_w(c_1 + c_4 w) = 7 \implies$ **19 `F::mul` calls**.
    pub fn mul_by_014_unit_rank19(
        self,
        c1: Fp2<F>,
        c4: Fp2<F>,
        weights: &Bls12381TowerWeights<F>,
    ) -> Self {
        let pa = self.to_simple_basis();
        let mut pb = [F::zero(); 12];
        // c1 + c4 * w = (c1.c0 - c1.c1) + (c4.c0 - c4.c1)*w + c1.c1*w^6 + c4.c1*w^7 (deg 7)
        pb[0] = c1.c0.sub(c1.c1);
        pb[1] = c4.c0.sub(c4.c1);
        pb[6] = c1.c1;
        pb[7] = c4.c1;

        let prod_poly = eval_fp12_even_odd::<F, 9, 10, 9>(
            &pa,
            &pb,
            11,
            7,
            false,
            &weights.fp12_rank19_even,
            &weights.fp12_rank19_odd,
        );
        let shifted = Self::from_simple_basis(&prod_poly).mul_by_v();
        self.add(shifted)
    }

    /// **Rank-21** general projective `mul_by_014` (`self * (c0 + c1*v + c4*v*w)` with arbitrary
    /// `c0, c1, c4: Fp2`): $\deg_w(c_0 + c_1 w^2 + c_4 w^3) = 9 \implies$ **21 `F::mul` calls**
    /// (`-61.11%` vs `54`, `-46.15%` vs `39`).
    pub fn mul_by_014_projective_rank21(
        self,
        c0: Fp2<F>,
        c1: Fp2<F>,
        c4: Fp2<F>,
        weights: &Bls12381TowerWeights<F>,
    ) -> Self {
        let pa = self.to_simple_basis();
        let mut pb = [F::zero(); 12];
        pb[0] = c0.c0.sub(c0.c1);
        pb[2] = c1.c0.sub(c1.c1);
        pb[3] = c4.c0.sub(c4.c1);
        pb[6] = c0.c1;
        pb[8] = c1.c1;
        pb[9] = c4.c1;

        let out_poly = eval_fp12_even_odd::<F, 10, 11, 10>(
            &pa,
            &pb,
            11,
            9,
            false,
            &weights.fp12_rank21_even,
            &weights.fp12_rank21_odd,
        );
        Self::from_simple_basis(&out_poly)
    }
}

// ============================================================================
// 3. Exact 1024-Bit Unsigned Arithmetic (`U1024`) & Curve Modulus Constants
// ============================================================================

/// Self-contained `#![no_std]` 1024-bit unsigned integer (`16 x u64` little-endian)
/// for exact `Consensys/gnark#1951`-style `posMax` / `negMax` / `maxQuo` / `quoBits` arithmetic
/// over 255-bit Zcash `Pasta` and 381-bit `BLS12-381` moduli.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U1024(pub [u64; 16]);

impl U1024 {
    pub const ZERO: Self = Self([0u64; 16]);
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    pub const fn from_u64(v: u64) -> Self {
        let mut arr = [0u64; 16];
        arr[0] = v;
        Self(arr)
    }

    pub const fn from_limbs4(limbs: [u64; 4]) -> Self {
        let mut arr = [0u64; 16];
        arr[0] = limbs[0];
        arr[1] = limbs[1];
        arr[2] = limbs[2];
        arr[3] = limbs[3];
        Self(arr)
    }

    pub const fn from_limbs6(limbs: [u64; 6]) -> Self {
        let mut arr = [0u64; 16];
        arr[0] = limbs[0];
        arr[1] = limbs[1];
        arr[2] = limbs[2];
        arr[3] = limbs[3];
        arr[4] = limbs[4];
        arr[5] = limbs[5];
        Self(arr)
    }

    pub const fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < 16 {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    pub const fn bit_len(&self) -> u32 {
        let mut i = 16;
        while i > 0 {
            i -= 1;
            if self.0[i] != 0 {
                return (i as u32) * 64 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    pub const fn bit(&self, idx: u32) -> bool {
        if idx >= 1024 {
            return false;
        }
        let word = (idx / 64) as usize;
        let bit = idx % 64;
        ((self.0[word] >> bit) & 1) != 0
    }

    pub const fn set_bit(&mut self, idx: u32) {
        if idx < 1024 {
            let word = (idx / 64) as usize;
            let bit = idx % 64;
            self.0[word] |= 1u64 << bit;
        }
    }

    pub const fn pow2_minus_1(bits: u32) -> Self {
        assert!(bits <= 1024);
        if bits == 0 {
            return Self::ZERO;
        }
        let mut out = [0u64; 16];
        let full_words = (bits / 64) as usize;
        let rem_bits = bits % 64;
        let mut i = 0;
        while i < full_words {
            out[i] = u64::MAX;
            i += 1;
        }
        if rem_bits > 0 {
            out[full_words] = (1u64 << rem_bits) - 1;
        }
        Self(out)
    }

    pub const fn cmp_const(&self, rhs: &Self) -> i8 {
        let mut i = 16;
        while i > 0 {
            i -= 1;
            if self.0[i] > rhs.0[i] {
                return 1;
            }
            if self.0[i] < rhs.0[i] {
                return -1;
            }
        }
        0
    }

    pub const fn max_const(self, rhs: Self) -> Self {
        if self.cmp_const(&rhs) >= 0 {
            self
        } else {
            rhs
        }
    }

    pub const fn add_const(self, rhs: Self) -> Self {
        let mut out = [0u64; 16];
        let mut carry = 0u128;
        let mut i = 0;
        while i < 16 {
            let sum = (self.0[i] as u128) + (rhs.0[i] as u128) + carry;
            out[i] = sum as u64;
            carry = sum >> 64;
            i += 1;
        }
        assert!(carry == 0);
        Self(out)
    }

    pub const fn sub_const(self, rhs: Self) -> Self {
        assert!(self.cmp_const(&rhs) >= 0);
        let mut out = [0u64; 16];
        let mut borrow = 0i128;
        let mut i = 0;
        while i < 16 {
            let diff = (self.0[i] as i128) - (rhs.0[i] as i128) - borrow;
            if diff < 0 {
                out[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                out[i] = diff as u64;
                borrow = 0;
            }
            i += 1;
        }
        assert!(borrow == 0);
        Self(out)
    }

    pub const fn shl1_with_lsb(self, lsb: bool) -> Self {
        let mut out = [0u64; 16];
        let mut carry = if lsb { 1u64 } else { 0u64 };
        let mut i = 0;
        while i < 16 {
            let next_carry = self.0[i] >> 63;
            out[i] = (self.0[i] << 1) | carry;
            carry = next_carry;
            i += 1;
        }
        assert!(carry == 0);
        Self(out)
    }

    pub const fn mul_const(self, rhs: Self) -> Self {
        let mut out = [0u64; 16];
        let mut i = 0;
        while i < 16 {
            if self.0[i] != 0 {
                let mut carry = 0u128;
                let mut j = 0;
                while j + i < 16 {
                    let prod =
                        (out[i + j] as u128) + (self.0[i] as u128) * (rhs.0[j] as u128) + carry;
                    out[i + j] = prod as u64;
                    carry = prod >> 64;
                    j += 1;
                }
                assert!(carry == 0);
                // Ensure truncated upper words had zero contribution
                while j < 16 {
                    assert!(rhs.0[j] == 0);
                    j += 1;
                }
            }
            i += 1;
        }
        Self(out)
    }

    /// Exact bitwise integer quotient & remainder `(self / divisor, self % divisor)`.
    pub const fn div_rem_const(self, divisor: Self) -> (Self, Self) {
        assert!(!divisor.is_zero());
        if self.cmp_const(&divisor) < 0 {
            return (Self::ZERO, self);
        }
        let mut quo = Self::ZERO;
        let mut rem = Self::ZERO;
        let mut bit = self.bit_len();
        while bit > 0 {
            bit -= 1;
            rem = rem.shl1_with_lsb(self.bit(bit));
            if rem.cmp_const(&divisor) >= 0 {
                rem = rem.sub_const(divisor);
                quo.set_bit(bit);
            }
        }
        (quo, rem)
    }

    pub const fn div_ceil_const(self, divisor: Self) -> Self {
        let (q, r) = self.div_rem_const(divisor);
        if r.is_zero() {
            q
        } else {
            q.add_const(Self::ONE)
        }
    }
}

/// Zcash `BLS12-381` base field prime $p$ (`381` bits, little-endian `[u64; 6]`).
pub const BLS12_381_FP_MODULUS: U1024 = U1024::from_limbs6([
    0xB9FE_FFFF_FFFF_AAAB,
    0x1EAB_FFFE_B153_FFFF,
    0x6730_D2A0_F6B0_F624,
    0x6477_4B84_F385_12BF,
    0x4B1B_A7B6_434B_ACD7,
    0x1A01_11EA_397F_E69A,
]);

/// Zcash `Pallas` base field (= `Vesta` scalar field) prime $p_P$ (`255` bits, `[u64; 4]`).
pub const PALLAS_BASE_MODULUS: U1024 = U1024::from_limbs4([
    0x992D_30ED_0000_0001,
    0x2246_98FC_094C_F91B,
    0x0000_0000_0000_0000,
    0x4000_0000_0000_0000,
]);

/// Zcash `Vesta` base field (= `Pallas` scalar field) prime $p_V$ (`255` bits, `[u64; 4]`).
pub const VESTA_BASE_MODULUS: U1024 = U1024::from_limbs4([
    0x8C46_EB21_0000_0001,
    0x2246_98FC_0994_A8DD,
    0x0000_0000_0000_0000,
    0x4000_0000_0000_0000,
]);

/// `BabyBear` prime $q = 2^{31} - 2^{27} + 1 = 2013265921$ (`31` bits) for small-field CRT audits.
pub const BABYBEAR_MODULUS_U1024: U1024 = U1024::from_u64(2_013_265_921);

// ============================================================================
// 4. Exact `Consensys/gnark#1951` `quoBits` & CRT Carry-Bound Calculator
// ============================================================================

/// Exact integer/CRT soundness & bit-width diagnosis for a non-native polynomial or bilinear
/// relation $\mathrm{LHS} = r + s \cdot k \cdot p$ over a native SNARK/Halo2 scalar field of
/// bit-length `native_field_bits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrtQuoCarryAnalysis {
    pub num_limbs: u32,
    pub limb_bits: u32,
    pub mod_bits: u32,
    pub quo_bits: u32,
    pub nb_quo_limbs: u32,
    pub top_quo_limb_bits: u32,
    pub naive_full_limb_quo_bits: u32,
    pub quo_bits_saved_vs_naive: u32,
    pub has_k_neg: bool,
    pub w_discrepancy_bits: u32,
    pub crt_low_carries: u32,
    pub total_carry_limbs: u32,
    pub carry_bound_bits: u32,
    pub max_sound_carry_bits: u32,
    pub exceeds_carry_soundness_limit: bool,
    /// `true` when $2 \cdot \mathrm{limb\_bits} \ge \mathrm{native\_field\_bits} - 1$ and
    /// `top_quo_limb_bits < limb_bits`, meaning unmasked full-limb `packLimbs` allows malicious
    /// modulo-$q$ quotient wrap-around (the exact bug caught & fixed in `Consensys/gnark#1951`).
    pub unmasked_full_limb_quo_unsound: bool,
}

/// Compute exact `Consensys/gnark#1951` `quoBits`, `packLimbsWithWidth` top-limb width,
/// `mvLowCarries` / `crtLowCarries`, and signed carry range bounds from exact `U1024` bounds.
#[allow(clippy::too_many_arguments)]
pub const fn analyze_crt_quo_and_carries(
    modulus: U1024,
    pos_max: U1024,
    neg_max: U1024,
    max_lhs_limbs: u32,
    limb_bits: u32,
    native_field_bits: u32,
    lhs_shifted_carry_bits: u32,
    assert_zero: bool,
) -> CrtQuoCarryAnalysis {
    assert!(limb_bits > 0 && native_field_bits >= limb_bits + 3);
    let mod_bits = modulus.bit_len();
    let num_limbs = mod_bits.div_ceil(limb_bits);

    let (pos_quo, _) = pos_max.div_rem_const(modulus);
    let neg_quo = if neg_max.is_zero() {
        U1024::ZERO
    } else {
        neg_max.div_ceil_const(modulus)
    };
    let max_quo = pos_quo.max_const(neg_quo);
    let quo_bits = max_quo.bit_len();
    let nb_quo_limbs = if quo_bits == 0 {
        0
    } else {
        quo_bits.div_ceil(limb_bits)
    };
    let top_quo_limb_bits = if nb_quo_limbs == 0 {
        0
    } else {
        quo_bits - (nb_quo_limbs - 1) * limb_bits
    };
    let naive_full_limb_quo_bits = nb_quo_limbs * limb_bits;
    let quo_bits_saved_vs_naive = naive_full_limb_quo_bits - quo_bits;
    let has_k_neg = (!neg_max.is_zero()) && (nb_quo_limbs > 0);

    // Exact `mvLowCarries` / `crtLowCarries` certificate from `gnark#1951`:
    // With `packLimbsWithWidth(ret[:nbQuoLimbs], quoBits)`, any witness satisfies `k <= 2^quoBits - 1`.
    let kp_max = U1024::pow2_minus_1(quo_bits).mul_const(modulus);
    let pos_delta = if has_k_neg {
        pos_max.add_const(kp_max)
    } else {
        pos_max
    };
    let rem_max = if assert_zero {
        U1024::ZERO
    } else {
        modulus.sub_const(U1024::ONE)
    };
    let neg_delta = neg_max.add_const(kp_max).add_const(rem_max);
    let w_discrepancy_bits = pos_delta.max_const(neg_delta).bit_len();

    let q_bits_lower_bound = native_field_bits - 1;
    let remaining_bits = w_discrepancy_bits.saturating_sub(q_bits_lower_bound);
    let rhs_limbs = if nb_quo_limbs == 0 {
        num_limbs
    } else {
        num_limbs + nb_quo_limbs - 1
    };
    let max_rel_limbs = if max_lhs_limbs > rhs_limbs {
        max_lhs_limbs
    } else {
        rhs_limbs
    };
    let total_carry_limbs = max_rel_limbs.saturating_sub(1);
    let req_low = remaining_bits.div_ceil(limb_bits);
    let crt_low_carries = if req_low < total_carry_limbs {
        req_low
    } else {
        total_carry_limbs
    };

    // Carry bit-length bound (`mvCarryBound` / `mulCarryBound` in `gnark#1951`):
    let min_quo_mod = if nb_quo_limbs < num_limbs {
        nb_quo_limbs
    } else {
        num_limbs
    };
    let kp_coef = limb_bits + (32 - (min_quo_mod + 1).leading_zeros());
    let kp_val = if nb_quo_limbs == 0 { 1 } else { quo_bits + 1 };
    let kp_term = if kp_coef < kp_val { kp_coef } else { kp_val };
    let lhs_term = lhs_shifted_carry_bits;
    let base_carry = if lhs_term > kp_term {
        lhs_term
    } else {
        kp_term
    };
    let carry_bound_bits = base_carry + 2;
    let max_sound_carry_bits = native_field_bits - 2 - limb_bits;
    let exceeds_carry_soundness_limit = carry_bound_bits > max_sound_carry_bits;

    let unmasked_full_limb_quo_unsound = (2 * limb_bits >= native_field_bits - 1)
        && (top_quo_limb_bits > 0 && top_quo_limb_bits < limb_bits);

    CrtQuoCarryAnalysis {
        num_limbs,
        limb_bits,
        mod_bits,
        quo_bits,
        nb_quo_limbs,
        top_quo_limb_bits,
        naive_full_limb_quo_bits,
        quo_bits_saved_vs_naive,
        has_k_neg,
        w_discrepancy_bits,
        crt_low_carries,
        total_carry_limbs,
        carry_bound_bits,
        max_sound_carry_bits,
        exceeds_carry_soundness_limit,
        unmasked_full_limb_quo_unsound,
    }
}

// ============================================================================
// 5. PlonKish `Halo2LookupCostModel` (`FlexGate` + `RangeChip`)
// ============================================================================

/// Non-native `BLS12-381` `Fp12` multiplication schedules compared in [`Halo2LookupCostModel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halo2Fp12ScheduleKind {
    /// Standard $3 \times 6 \times 3$ Karatsuba tower (`54` `Fp` muls, `6`-bit UV slack, `0` pre-reductions).
    Schoolbook54,
    /// $3 \times 12$ `Fp12`-over-`Fp6(CRT-12)` tower (`36` `Fp` muls, `23`-bit UV slack, `0` pre-reductions).
    Karatsuba36,
    /// Certified Pareto-optimal Cyclotomic/Linear CRT (`30` `Fp` muls, `45`-bit UV slack, `0` pre-reductions).
    Crt30,
    /// Minimum-rank Vandermonde (`{-11..10, inf}`, `23` `Fp` muls, `77`-bit UV slack — triggers pre-reductions!).
    Rank23,
}

impl Halo2Fp12ScheduleKind {
    pub const ALL: [Self; 4] = [
        Self::Schoolbook54,
        Self::Karatsuba36,
        Self::Crt30,
        Self::Rank23,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Schoolbook54 => "Schoolbook-54",
            Self::Karatsuba36 => "Karatsuba-36",
            Self::Crt30 => "CRT-30",
            Self::Rank23 => "Rank-23",
        }
    }

    pub const fn base_fp_muls(self) -> u32 {
        match self {
            Self::Schoolbook54 => 54,
            Self::Karatsuba36 => 36,
            Self::Crt30 => 30,
            Self::Rank23 => 23,
        }
    }

    pub const fn max_uv_slack_bits(self) -> u32 {
        match self {
            Self::Schoolbook54 => 6,
            Self::Karatsuba36 => 23,
            Self::Crt30 => 45,
            Self::Rank23 => 77,
        }
    }

    pub const fn out_wz_plus_d_bits(self) -> u32 {
        match self {
            Self::Schoolbook54 => 4,
            Self::Karatsuba36 => 25,
            Self::Crt30 => 52,
            Self::Rank23 => 113,
        }
    }

    /// Approximate deduplicated linear combination `FlexGate` steps per limb for `(U*a, V*b, W_z*m)`.
    pub const fn linear_comb_ops_per_limb(self) -> u32 {
        match self {
            Self::Schoolbook54 => 92,
            Self::Karatsuba36 => 118,
            Self::Crt30 => 136,
            Self::Rank23 => 198,
        }
    }
}

/// Detailed Halo2 `FlexGate` + `RangeChip` cell count breakdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Halo2CellBreakdown {
    pub lookup_bits: u32,
    pub limb_bits: u32,
    pub num_limbs: u32,
    pub range_lookup_cells: u32,
    pub flex_gate_cells: u32,
    pub total_cells: u32,
    pub quo_bits: u32,
    pub crt_low_carries: u32,
    pub naive_total_cells: u32,
    pub cells_saved_by_exact_quo_bits: u32,
}

/// Complete `BLS12-381` `Fp12` Halo2 non-native cost report for a given schedule and chip config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Halo2Fp12CostReport {
    pub schedule: Halo2Fp12ScheduleKind,
    pub lookup_bits: u32,
    pub limb_bits: u32,
    pub num_limbs: u32,
    pub base_fp_muls: u32,
    pub pre_mul_reductions: u32,
    pub range_lookup_cells: u32,
    pub flex_gate_cells: u32,
    pub total_cells: u32,
    pub mul_quo_bits: u32,
    pub mul_crt_low_carries: u32,
    pub mul_carry_bound_bits: u32,
}

/// Exact PlonKish cell calculator modeling `halo2-lib` / Zcash `Halo2` vertical `FlexGate`
/// (`q * (a + b * c - d) = 0`, `1 + 3 * steps` cells per contiguous chain) + `RangeChip`
/// (`lookup_bits` in `{8, 12, 16}`, `limb_bits` in `{88, 64}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Halo2LookupCostModel {
    pub lookup_bits: u32,
    pub limb_bits: u32,
    pub native_field_bits: u32,
}

impl Halo2LookupCostModel {
    /// Construct a `Halo2LookupCostModel` for Zcash `Pasta` (`native_field_bits = 255`).
    /// Supports `lookup_bits` in `{8, 12, 16}` and `limb_bits` in `{88, 64}`.
    pub const fn new_pasta(lookup_bits: u32, limb_bits: u32) -> Self {
        assert!(lookup_bits == 8 || lookup_bits == 12 || lookup_bits == 16);
        assert!(limb_bits == 88 || limb_bits == 64);
        Self {
            lookup_bits,
            limb_bits,
            native_field_bits: 255,
        }
    }

    /// Exact `(lookup_cells, flex_gate_cells)` for `RangeChip::range_check(x, bits)`:
    /// decomposes `x` into `k = ceil(bits / lookup_bits)` lookup cells and recomposes via
    /// `k - 1` chained constant-mul-add steps (`1 + 3 * (k - 1)` `FlexGate` cells when `k >= 2`).
    #[inline]
    pub const fn range_check_cells(&self, bits: u32) -> (u32, u32) {
        if bits == 0 {
            return (0, 0);
        }
        let k = bits.div_ceil(self.lookup_bits);
        if k <= 1 {
            (1, 0)
        } else {
            (k, 1 + 3 * (k - 1))
        }
    }

    /// Range-check a multi-limb witness packed to `total_bits` (`packLimbsWithWidth`).
    pub const fn packed_limbs_range_cells(&self, total_bits: u32) -> (u32, u32) {
        if total_bits == 0 {
            return (0, 0);
        }
        let nb_limbs = total_bits.div_ceil(self.limb_bits);
        let top_bits = total_bits - (nb_limbs - 1) * self.limb_bits;
        let (low_l, low_g) = self.range_check_cells(self.limb_bits);
        let (top_l, top_g) = self.range_check_cells(top_bits);
        (
            (nb_limbs - 1) * low_l + top_l,
            (nb_limbs - 1) * low_g + top_g,
        )
    }

    /// Estimate wrong-field `a * b = r + k * p` CRT reduction cells for Zcash `Pasta`
    /// (`Pallas` emulated in `Vesta` or `Vesta` emulated in `Pallas`), comparing exact
    /// `gnark#1951` `quoBits` + `crtLowCarries` against naive full-limb quotient & full-carry checks.
    pub const fn estimate_pasta_wrong_field_mul(&self, wrong_modulus: U1024) -> Halo2CellBreakdown {
        let p_minus_1 = wrong_modulus.sub_const(U1024::ONE);
        let pos_max = p_minus_1.mul_const(p_minus_1);
        let num_limbs = wrong_modulus.bit_len().div_ceil(self.limb_bits);
        let ab_conv_bits = 32 - num_limbs.leading_zeros();

        let crt = analyze_crt_quo_and_carries(
            wrong_modulus,
            pos_max,
            U1024::ZERO,
            2 * num_limbs - 1,
            self.limb_bits,
            self.native_field_bits,
            self.limb_bits + ab_conv_bits,
            false,
        );
        assert!(!crt.exceeds_carry_soundness_limit);

        // Remainder `r` (< p, packed to mod_bits) + Quotient `k` (packed to exact `quo_bits`)
        // + `crt_low_carries` signed carries (each `carry_bound_bits + 1` bits):
        let (rem_l, rem_g) = self.packed_limbs_range_cells(crt.mod_bits);
        let (quo_l, quo_g) = self.packed_limbs_range_cells(crt.quo_bits);
        let (car_l, car_g) = self.range_check_cells(crt.carry_bound_bits + 1);

        let range_lookup_cells = rem_l + quo_l + crt.crt_low_carries * car_l;
        // Schoolbook limb products (`L^2` mul-adds) + `k * p` (`L * nb_quo` mul-adds)
        // + carry shift checks (`crt_low_carries * 2` steps) + native modulus evaluation (`3 * L` steps):
        let arith_ops = num_limbs * num_limbs
            + num_limbs * crt.nb_quo_limbs
            + 2 * crt.crt_low_carries
            + 3 * num_limbs;
        let flex_gate_cells = rem_g + quo_g + crt.crt_low_carries * car_g + (1 + 3 * arith_ops);
        let total_cells = range_lookup_cells + flex_gate_cells;

        // Naive baseline: full `nb_quo_limbs * limb_bits` quotient + all `total_carry_limbs` range-checked
        // with `+1 bit per term` loose bound (`carry_bound_bits + 2`):
        let (naive_quo_l, naive_quo_g) =
            self.packed_limbs_range_cells(crt.naive_full_limb_quo_bits);
        let (naive_car_l, naive_car_g) = self.range_check_cells(crt.carry_bound_bits + 3);
        let naive_lookup = rem_l + naive_quo_l + crt.total_carry_limbs * naive_car_l;
        let naive_arith_ops = num_limbs * num_limbs
            + num_limbs * crt.nb_quo_limbs
            + 2 * crt.total_carry_limbs
            + 3 * num_limbs;
        let naive_flex =
            rem_g + naive_quo_g + crt.total_carry_limbs * naive_car_g + (1 + 3 * naive_arith_ops);
        let naive_total_cells = naive_lookup + naive_flex;

        Halo2CellBreakdown {
            lookup_bits: self.lookup_bits,
            limb_bits: self.limb_bits,
            num_limbs,
            range_lookup_cells,
            flex_gate_cells,
            total_cells,
            quo_bits: crt.quo_bits,
            crt_low_carries: crt.crt_low_carries,
            naive_total_cells,
            cells_saved_by_exact_quo_bits: naive_total_cells - total_cells,
        }
    }

    /// Estimate full non-native `BLS12-381` `Fp12` multiplication cells on Halo2 (`FlexGate` + `RangeChip`)
    /// for `Schoolbook-54`, `Karatsuba-36`, `CRT-30`, and `Rank-23`.
    pub const fn estimate_bls12_381_fp12_mul(
        &self,
        schedule: Halo2Fp12ScheduleKind,
    ) -> Halo2Fp12CostReport {
        let p = BLS12_381_FP_MODULUS;
        let p_minus_1 = p.sub_const(U1024::ONE);
        let p_sq = p_minus_1.mul_const(p_minus_1);
        let num_limbs = p.bit_len().div_ceil(self.limb_bits);
        let l_bits = 32 - num_limbs.leading_zeros();

        let uv_slack = schedule.max_uv_slack_bits();
        let base_muls = schedule.base_fp_muls();

        // Check carry-ceiling / limb-packing envelope:
        // In 64-bit 2-limb packed CRT (`gnark` / Halo2 packed carry) the product slack budget is 56 bits;
        // in 88-bit single-limb CRT (`halo2-ecc` 5x88-bit), `limb_bits + uv_slack + l_bits + 2 <= 165`
        // leaves `165 - 88 - 3 - 2 = 72` bits before carry wrap-around, and even below 72 bits wide
        // `77`-bit Vandermonde slack overflows `253 - 88 = 165` bits (`88 + 77 + 3 + 2 = 170 > 165`)!
        let slack_budget = if self.limb_bits == 64 {
            56u32
        } else {
            self.native_field_bits - 2 - 2 * self.limb_bits - l_bits - 2
        };

        let (pre_mul_reductions, eff_uv_slack) = if uv_slack > slack_budget {
            // Exactly as in `zk_bilinear/cost_models.py`, high-node Vandermonde evaluations (`Rank-23`)
            // trigger `22` mandatory pre-multiplication `Fp` modular reductions!
            (22u32, 4u32)
        } else {
            (0u32, uv_slack)
        };

        // Multiply `p_sq` by `2^eff_uv_slack` (bounded via `pow2_minus_1(eff_uv_slack + 1)`):
        let uv_scale = U1024::from_u64(1u64 << eff_uv_slack);
        let mul_pos_max = p_sq.mul_const(uv_scale);
        let mul_crt = analyze_crt_quo_and_carries(
            p,
            mul_pos_max,
            U1024::ZERO,
            2 * num_limbs - 1,
            self.limb_bits,
            self.native_field_bits,
            self.limb_bits + eff_uv_slack + l_bits,
            false,
        );
        assert!(!mul_crt.exceeds_carry_soundness_limit);

        // Per-`Fp`-mul cell cost (`r` witness + `k` witness + `crt_low_carries` + limb Toom/schoolbook gates):
        let (rem_l, rem_g) = self.packed_limbs_range_cells(mul_crt.mod_bits);
        let (quo_l, quo_g) = self.packed_limbs_range_cells(mul_crt.quo_bits);
        let (car_l, car_g) = self.range_check_cells(mul_crt.carry_bound_bits + 1);
        let per_mul_lookup = rem_l + quo_l + mul_crt.crt_low_carries * car_l;
        let per_mul_arith_ops = num_limbs * num_limbs
            + num_limbs * mul_crt.nb_quo_limbs
            + 2 * mul_crt.crt_low_carries
            + 2 * num_limbs;
        let per_mul_flex =
            rem_g + quo_g + mul_crt.crt_low_carries * car_g + (1 + 3 * per_mul_arith_ops);

        // Cost of each mandatory pre-multiplication `Reduce()` (when `uv_slack > slack_budget`):
        let red_scale = U1024::from_u64(1u64 << (uv_slack / 2));
        let red_pos_max = p_minus_1.mul_const(red_scale);
        let red_crt = analyze_crt_quo_and_carries(
            p,
            red_pos_max,
            U1024::ZERO,
            num_limbs,
            self.limb_bits,
            self.native_field_bits,
            uv_slack / 2,
            false,
        );
        let (rquo_l, rquo_g) = self.packed_limbs_range_cells(red_crt.quo_bits);
        let (rcar_l, rcar_g) = self.range_check_cells(red_crt.carry_bound_bits + 1);
        let per_red_lookup = rem_l + rquo_l + red_crt.crt_low_carries * rcar_l;
        let per_red_ops =
            num_limbs * red_crt.nb_quo_limbs + 2 * red_crt.crt_low_carries + num_limbs;
        let per_red_flex =
            rem_g + rquo_g + red_crt.crt_low_carries * rcar_g + (1 + 3 * per_red_ops);

        // Output linear reconstruction `W_z * m - D * c = q_W * p` across the `12` `Fp` output coordinates.
        // Mirroring `zk_bilinear/cost_models.py`: when `out_bits <= limb_bits` (`Schoolbook-54`, `Karatsuba-36`,
        // `CRT-30` where `52 <= 64 <= 88`), `W_z` entries are single-limb constants (`const_chunks == 1`);
        // when `out_bits > limb_bits` (`Rank-23` where `113 > 88 > 64`), `W_z` entries split into
        // `const_chunks = ceil(out_bits / limb_bits) == 2` limb words, multiplying output `FlexGate`
        // convolution work by `const_chunks` and widening `max_lhs_limbs` to `num_limbs + const_chunks - 1`.
        let out_bits = schedule.out_wz_plus_d_bits();
        let const_chunks = out_bits.div_ceil(self.limb_bits);
        let out_scale = U1024::pow2_minus_1(out_bits).add_const(U1024::ONE);
        let out_bound = p_minus_1.mul_const(out_scale);
        let out_crt = analyze_crt_quo_and_carries(
            p,
            out_bound,
            out_bound,
            num_limbs + const_chunks - 1,
            self.limb_bits,
            self.native_field_bits,
            if const_chunks == 1 {
                out_bits
            } else {
                self.limb_bits + (out_bits - self.limb_bits) + 2
            },
            false,
        );
        let (oquo_l, oquo_g) = self.packed_limbs_range_cells(out_crt.quo_bits);
        let (ocar_l, ocar_g) = self.range_check_cells(out_crt.carry_bound_bits + 1);
        let per_out_lookup = rem_l + oquo_l + out_crt.crt_low_carries * ocar_l;
        let per_out_ops = num_limbs * out_crt.nb_quo_limbs
            + 2 * out_crt.crt_low_carries
            + 2 * num_limbs * const_chunks
            + 1;
        let per_out_flex =
            rem_g + oquo_g + out_crt.crt_low_carries * ocar_g + (1 + 3 * per_out_ops);

        let w_comb_factor = if const_chunks == 1 {
            1
        } else {
            const_chunks * 2
        };
        let linear_flex = 1 + 3 * (num_limbs * schedule.linear_comb_ops_per_limb() * w_comb_factor);

        let range_lookup_cells =
            base_muls * per_mul_lookup + pre_mul_reductions * per_red_lookup + 12 * per_out_lookup;
        let flex_gate_cells = base_muls * per_mul_flex
            + pre_mul_reductions * per_red_flex
            + 12 * per_out_flex
            + linear_flex;

        Halo2Fp12CostReport {
            schedule,
            lookup_bits: self.lookup_bits,
            limb_bits: self.limb_bits,
            num_limbs,
            base_fp_muls: base_muls,
            pre_mul_reductions,
            range_lookup_cells,
            flex_gate_cells,
            total_cells: range_lookup_cells + flex_gate_cells,
            mul_quo_bits: mul_crt.quo_bits,
            mul_crt_low_carries: mul_crt.crt_low_carries,
            mul_carry_bound_bits: mul_crt.carry_bound_bits,
        }
    }
}

// ============================================================================
// 6. Concrete `#![no_std]` Prime Fields & Exhaustive Unit Tests
// ============================================================================

/// Fast concrete prime field $p = 1{,}000{,}003$ where $u^2 + 1$, $v^6 - 2v^3 + 2$, and
/// $w^{12} - 2w^6 + 2$ are all irreducible over $\mathbb{F}_p$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastPrime1000003(pub u64);

impl FastPrime1000003 {
    pub const MODULUS: u64 = 1_000_003;

    #[inline]
    pub const fn new(v: u64) -> Self {
        Self(v % Self::MODULUS)
    }
}

impl PrimeFieldOps for FastPrime1000003 {
    #[inline]
    fn zero() -> Self {
        Self(0)
    }

    #[inline]
    fn one() -> Self {
        Self(1)
    }

    #[inline]
    fn from_u64(v: u64) -> Self {
        Self(v % Self::MODULUS)
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let s = self.0 + rhs.0;
        Self(if s >= Self::MODULUS {
            s - Self::MODULUS
        } else {
            s
        })
    }

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(if self.0 >= rhs.0 {
            self.0 - rhs.0
        } else {
            Self::MODULUS - rhs.0 + self.0
        })
    }

    #[inline]
    fn neg(self) -> Self {
        if self.0 == 0 {
            self
        } else {
            Self(Self::MODULUS - self.0)
        }
    }

    #[inline]
    fn scale_const(self, constant: Self) -> Self {
        Self(((self.0 as u128 * constant.0 as u128) % (Self::MODULUS as u128)) as u64)
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(((self.0 as u128 * rhs.0 as u128) % (Self::MODULUS as u128)) as u64)
    }

    fn inv_const(self) -> Self {
        assert!(self.0 != 0);
        let mut base = self;
        let mut exp = Self::MODULUS - 2;
        let mut acc = Self::one();
        while exp > 0 {
            if (exp & 1) != 0 {
                acc = acc.scale_const(base);
            }
            base = base.scale_const(base);
            exp >>= 1;
        }
        acc
    }
}

/// 4x`u64` (`[u64; 4]` + `u128` limb accumulator) Zcash `Pallas` 255-bit base field
/// $p_P = \text{0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001}$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PallasFp(pub [u64; 4]);

impl PallasFp {
    pub const MOD_LIMBS: [u64; 4] = [
        0x992D_30ED_0000_0001,
        0x2246_98FC_094C_F91B,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ];

    pub fn from_raw_reduced(limbs: [u64; 4]) -> Self {
        let (_, rem) = U1024::from_limbs4(limbs).div_rem_const(PALLAS_BASE_MODULUS);
        Self([rem.0[0], rem.0[1], rem.0[2], rem.0[3]])
    }

    #[inline]
    fn gte_mod(a: &[u64; 4]) -> bool {
        let mut i = 4;
        while i > 0 {
            i -= 1;
            if a[i] > Self::MOD_LIMBS[i] {
                return true;
            }
            if a[i] < Self::MOD_LIMBS[i] {
                return false;
            }
        }
        true
    }

    #[inline]
    fn mul_u128_schoolbook(a: &[u64; 4], b: &[u64; 4]) -> Self {
        let mut prod = [0u64; 16];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let acc = (prod[i + j] as u128) + (a[i] as u128) * (b[j] as u128) + carry;
                prod[i + j] = acc as u64;
                carry = acc >> 64;
            }
            prod[i + 4] = carry as u64;
        }
        let (_, rem) = U1024(prod).div_rem_const(PALLAS_BASE_MODULUS);
        Self([rem.0[0], rem.0[1], rem.0[2], rem.0[3]])
    }
}

impl PrimeFieldOps for PallasFp {
    #[inline]
    fn zero() -> Self {
        Self([0, 0, 0, 0])
    }

    #[inline]
    fn one() -> Self {
        Self([1, 0, 0, 0])
    }

    #[inline]
    fn from_u64(v: u64) -> Self {
        Self([v, 0, 0, 0])
    }

    fn add(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, slot) in out.iter_mut().enumerate() {
            let sum = (self.0[i] as u128) + (rhs.0[i] as u128) + carry;
            *slot = sum as u64;
            carry = sum >> 64;
        }
        if carry != 0 || Self::gte_mod(&out) {
            let mut borrow = 0i128;
            for (slot, &m) in out.iter_mut().zip(Self::MOD_LIMBS.iter()) {
                let diff = (*slot as i128) - (m as i128) - borrow;
                if diff < 0 {
                    *slot = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    *slot = diff as u64;
                    borrow = 0;
                }
            }
        }
        Self(out)
    }

    fn sub(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = 0i128;
        for (i, slot) in out.iter_mut().enumerate() {
            let diff = (self.0[i] as i128) - (rhs.0[i] as i128) - borrow;
            if diff < 0 {
                *slot = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                *slot = diff as u64;
                borrow = 0;
            }
        }
        if borrow != 0 {
            let mut carry = 0u128;
            for (slot, &m) in out.iter_mut().zip(Self::MOD_LIMBS.iter()) {
                let sum = (*slot as u128) + (m as u128) + carry;
                *slot = sum as u64;
                carry = sum >> 64;
            }
        }
        Self(out)
    }

    fn neg(self) -> Self {
        if self.0 == [0, 0, 0, 0] {
            self
        } else {
            Self(Self::MOD_LIMBS).sub(self)
        }
    }

    #[inline]
    fn scale_const(self, constant: Self) -> Self {
        Self::mul_u128_schoolbook(&self.0, &constant.0)
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self::mul_u128_schoolbook(&self.0, &rhs.0)
    }

    fn inv_const(self) -> Self {
        assert!(self.0 != [0, 0, 0, 0]);
        // Fermat little theorem: self^(p - 2) mod p
        let p_minus_2 = PALLAS_BASE_MODULUS.sub_const(U1024::from_u64(2));
        let mut base = self;
        let mut acc = Self::one();
        let top = p_minus_2.bit_len();
        for bit in 0..top {
            if p_minus_2.bit(bit) {
                acc = acc.scale_const(base);
            }
            if bit + 1 < top {
                base = base.scale_const(base);
            }
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    static GLOBAL_MUL_COUNTER: AtomicU32 = AtomicU32::new(0);
    static GLOBAL_CONST_SCALE_COUNTER: AtomicU32 = AtomicU32::new(0);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CountingField<F: PrimeFieldOps>(F);

    impl<F: PrimeFieldOps> CountingField<F> {
        fn reset() {
            GLOBAL_MUL_COUNTER.store(0, Ordering::SeqCst);
            GLOBAL_CONST_SCALE_COUNTER.store(0, Ordering::SeqCst);
        }

        fn mul_count() -> u32 {
            GLOBAL_MUL_COUNTER.load(Ordering::SeqCst)
        }
    }

    impl<F: PrimeFieldOps> PrimeFieldOps for CountingField<F> {
        fn zero() -> Self {
            Self(F::zero())
        }
        fn one() -> Self {
            Self(F::one())
        }
        fn from_u64(v: u64) -> Self {
            Self(F::from_u64(v))
        }
        fn add(self, rhs: Self) -> Self {
            Self(self.0.add(rhs.0))
        }
        fn sub(self, rhs: Self) -> Self {
            Self(self.0.sub(rhs.0))
        }
        fn neg(self) -> Self {
            Self(self.0.neg())
        }
        fn scale_const(self, constant: Self) -> Self {
            GLOBAL_CONST_SCALE_COUNTER.fetch_add(1, Ordering::SeqCst);
            Self(self.0.scale_const(constant.0))
        }
        fn mul(self, rhs: Self) -> Self {
            GLOBAL_MUL_COUNTER.fetch_add(1, Ordering::SeqCst);
            Self(self.0.mul(rhs.0))
        }
        fn inv_const(self) -> Self {
            Self(self.0.inv_const())
        }
    }

    struct XorShift64(u64);
    impl XorShift64 {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn fp6_from_slice<F: PrimeFieldOps>(c: &[F; 6]) -> Fp6<F> {
        Fp6::new(
            Fp2::new(c[0], c[1]),
            Fp2::new(c[2], c[3]),
            Fp2::new(c[4], c[5]),
        )
    }

    fn fp12_from_slice<F: PrimeFieldOps>(c: &[F; 12]) -> Fp12<F> {
        Fp12::new(
            Fp6::new(
                Fp2::new(c[0], c[1]),
                Fp2::new(c[2], c[3]),
                Fp2::new(c[4], c[5]),
            ),
            Fp6::new(
                Fp2::new(c[6], c[7]),
                Fp2::new(c[8], c[9]),
                Fp2::new(c[10], c[11]),
            ),
        )
    }

    #[test]
    fn test_exact_mul_counts_and_basis_completeness_fast_prime() {
        type CF = CountingField<FastPrime1000003>;
        let weights = Bls12381TowerWeights::<CF>::new();

        // 1. Verify exact `PrimeFieldOps::mul` gate counts on every kernel
        let a2 = Fp2::new(CF::from_u64(12345), CF::from_u64(67890));
        let b2 = Fp2::new(CF::from_u64(54321), CF::from_u64(98765));

        CF::reset();
        let ref2 = a2.mul_schoolbook4(b2);
        assert_eq!(CF::mul_count(), 4);

        CF::reset();
        let got2 = a2.mul_rank3(b2);
        assert_eq!(CF::mul_count(), 3);
        assert_eq!(got2, ref2);

        CF::reset();
        let sq2 = a2.square_rank2();
        assert_eq!(CF::mul_count(), 2);
        assert_eq!(sq2, a2.mul_schoolbook4(a2));

        let a6 = fp6_from_slice(&[
            CF::from_u64(11),
            CF::from_u64(22),
            CF::from_u64(33),
            CF::from_u64(44),
            CF::from_u64(55),
            CF::from_u64(66),
        ]);
        let b6 = fp6_from_slice(&[
            CF::from_u64(101),
            CF::from_u64(202),
            CF::from_u64(303),
            CF::from_u64(404),
            CF::from_u64(505),
            CF::from_u64(606),
        ]);
        let ref6 = a6.mul_schoolbook_ref(b6);

        CF::reset();
        assert_eq!(a6.mul_schoolbook18(b6), ref6);
        assert_eq!(CF::mul_count(), 18);

        CF::reset();
        assert_eq!(a6.mul_karatsuba15(b6, &weights), ref6);
        assert_eq!(CF::mul_count(), 15);

        CF::reset();
        assert_eq!(a6.mul_rank11(b6, &weights), ref6);
        assert_eq!(CF::mul_count(), 11);

        let a12 = fp12_from_slice(&[
            CF::from_u64(3),
            CF::from_u64(14),
            CF::from_u64(15),
            CF::from_u64(92),
            CF::from_u64(65),
            CF::from_u64(35),
            CF::from_u64(89),
            CF::from_u64(79),
            CF::from_u64(32),
            CF::from_u64(38),
            CF::from_u64(46),
            CF::from_u64(26),
        ]);
        let b12 = fp12_from_slice(&[
            CF::from_u64(27),
            CF::from_u64(18),
            CF::from_u64(28),
            CF::from_u64(182),
            CF::from_u64(84),
            CF::from_u64(59),
            CF::from_u64(4),
            CF::from_u64(52),
            CF::from_u64(353),
            CF::from_u64(60),
            CF::from_u64(287),
            CF::from_u64(47),
        ]);
        let ref12 = a12.mul_schoolbook_ref(b12);

        CF::reset();
        assert_eq!(a12.mul_karatsuba54(b12), ref12);
        assert_eq!(CF::mul_count(), 54);

        CF::reset();
        assert_eq!(a12.mul_rank23(b12, &weights), ref12);
        assert_eq!(CF::mul_count(), 23);

        // Sparse `mul_by_014` gate counts & algebraic equivalence:
        let c0 = Fp2::new(CF::from_u64(777), CF::from_u64(888));
        let c1 = Fp2::new(CF::from_u64(999), CF::from_u64(111));
        let c4 = Fp2::new(CF::from_u64(222), CF::from_u64(333));
        let y_p = CF::from_u64(444_555);

        let sparse_proj_12 = Fp12::new(
            Fp6::new(c0, c1, Fp2::zero()),
            Fp6::new(Fp2::zero(), c4, Fp2::zero()),
        );
        let ref_014_proj = a12.mul_schoolbook_ref(sparse_proj_12);

        CF::reset();
        assert_eq!(a12.mul_by_014_schoolbook54(c0, c1, c4), ref_014_proj);
        assert_eq!(CF::mul_count(), 54);

        CF::reset();
        assert_eq!(a12.mul_by_014_karatsuba39(c0, c1, c4), ref_014_proj);
        assert_eq!(CF::mul_count(), 39);

        CF::reset();
        assert_eq!(
            a12.mul_by_014_projective_rank21(c0, c1, c4, &weights),
            ref_014_proj
        );
        assert_eq!(CF::mul_count(), 21);

        let sparse_unit_12 = Fp12::new(
            Fp6::new(Fp2::one(), c1, Fp2::zero()),
            Fp6::new(Fp2::zero(), c4, Fp2::zero()),
        );
        let ref_014_unit = a12.mul_schoolbook_ref(sparse_unit_12);
        CF::reset();
        assert_eq!(a12.mul_by_014_unit_rank19(c1, c4, &weights), ref_014_unit);
        assert_eq!(CF::mul_count(), 19);

        let c4_yp = Fp2::new(y_p, CF::zero());
        let sparse_aff_12 = Fp12::new(
            Fp6::new(Fp2::one(), c1, Fp2::zero()),
            Fp6::new(Fp2::zero(), c4_yp, Fp2::zero()),
        );
        let ref_014_aff = a12.mul_schoolbook_ref(sparse_aff_12);
        CF::reset();
        assert_eq!(a12.mul_by_014_rank18(c1, y_p, &weights), ref_014_aff);
        assert_eq!(CF::mul_count(), 18);

        // 2. Exhaustive basis-pair completeness over FastPrime1000003 (`36` Fp6 + `144` Fp12 + `36` 014)
        let fast_w = Bls12381TowerWeights::<FastPrime1000003>::new();
        for i in 0..6 {
            let mut ea = [FastPrime1000003::zero(); 6];
            ea[i] = FastPrime1000003::one();
            let fa = fp6_from_slice(&ea);
            assert_eq!(Fp6::from_simple_basis(&fa.to_simple_basis()), fa);
            for j in 0..6 {
                let mut eb = [FastPrime1000003::zero(); 6];
                eb[j] = FastPrime1000003::one();
                let fb = fp6_from_slice(&eb);
                assert_eq!(fa.mul_rank11(fb, &fast_w), fa.mul_schoolbook_ref(fb));
            }
        }

        for i in 0..12 {
            let mut ea = [FastPrime1000003::zero(); 12];
            ea[i] = FastPrime1000003::one();
            let fa = fp12_from_slice(&ea);
            assert_eq!(Fp12::from_simple_basis(&fa.to_simple_basis()), fa);
            for j in 0..12 {
                let mut eb = [FastPrime1000003::zero(); 12];
                eb[j] = FastPrime1000003::one();
                let fb = fp12_from_slice(&eb);
                assert_eq!(fa.mul_rank23(fb, &fast_w), fa.mul_schoolbook_ref(fb));
            }
        }

        // Boundary `(p - 1)` & 256 random fuzz pairs
        let p_max = FastPrime1000003(FastPrime1000003::MODULUS - 1);
        let max12 = fp12_from_slice(&[p_max; 12]);
        assert_eq!(
            max12.mul_rank23(max12, &fast_w),
            max12.mul_schoolbook_ref(max12)
        );

        let mut rng = XorShift64(0xDEC0_DED1_2026_1122);
        for _ in 0..256 {
            let ra: [FastPrime1000003; 12] =
                core::array::from_fn(|_| FastPrime1000003::new(rng.next()));
            let rb: [FastPrime1000003; 12] =
                core::array::from_fn(|_| FastPrime1000003::new(rng.next()));
            let fa = fp12_from_slice(&ra);
            let fb = fp12_from_slice(&rb);
            assert_eq!(fa.mul_rank23(fb, &fast_w), fa.mul_karatsuba54(fb));

            let rc1 = Fp2::new(
                FastPrime1000003::new(rng.next()),
                FastPrime1000003::new(rng.next()),
            );
            let ryp = FastPrime1000003::new(rng.next());
            assert_eq!(
                fa.mul_by_014_rank18(rc1, ryp, &fast_w),
                fa.mul_by_014_karatsuba39(Fp2::one(), rc1, Fp2::new(ryp, FastPrime1000003::zero()))
            );
        }
    }

    #[test]
    fn test_pallas_4xu64_u128_harness_fp2_fp6_fp12_and_014() {
        let weights = Bls12381TowerWeights::<PallasFp>::new();

        // Test `(p_Pallas - 1)` worst-case 255-bit limb boundary across all 12 coordinates!
        let p_minus_1 = PallasFp([
            0x992D_30ED_0000_0000,
            0x2246_98FC_094C_F91B,
            0x0000_0000_0000_0000,
            0x4000_0000_0000_0000,
        ]);
        assert_eq!(p_minus_1.add(PallasFp::one()), PallasFp::zero());
        assert_eq!(
            p_minus_1.mul(p_minus_1),
            PallasFp::one(),
            "(p - 1)^2 == 1 mod p_Pallas"
        );

        let max6 = fp6_from_slice(&[p_minus_1; 6]);
        assert_eq!(max6.mul_rank11(max6, &weights), max6.mul_schoolbook18(max6));
        assert_eq!(
            max6.mul_karatsuba15(max6, &weights),
            max6.mul_schoolbook18(max6)
        );

        let max12 = fp12_from_slice(&[p_minus_1; 12]);
        assert_eq!(
            max12.mul_rank23(max12, &weights),
            max12.mul_karatsuba54(max12)
        );

        // 64 full 255-bit random `PallasFp` fuzz pairs across Fp6, Fp12, and sparse `mul_by_014`
        let mut rng = XorShift64(0x5A17_A5FA_11A5_0001);
        for _ in 0..64 {
            let mut next_pallas = || {
                PallasFp::from_raw_reduced([
                    rng.next(),
                    rng.next(),
                    rng.next(),
                    rng.next() & 0x3FFF_FFFF_FFFF_FFFF,
                ])
            };
            let ra: [PallasFp; 12] = core::array::from_fn(|_| next_pallas());
            let rb: [PallasFp; 12] = core::array::from_fn(|_| next_pallas());
            let fa = fp12_from_slice(&ra);
            let fb = fp12_from_slice(&rb);

            assert_eq!(
                fa.c0.mul_rank11(fb.c0, &weights),
                fa.c0.mul_schoolbook18(fb.c0)
            );
            assert_eq!(fa.mul_rank23(fb, &weights), fa.mul_karatsuba54(fb));

            let c0 = Fp2::new(next_pallas(), next_pallas());
            let c1 = Fp2::new(next_pallas(), next_pallas());
            let c4 = Fp2::new(next_pallas(), next_pallas());
            let yp = next_pallas();

            assert_eq!(
                fa.mul_by_014_rank18(c1, yp, &weights),
                fa.mul_by_014_karatsuba39(Fp2::one(), c1, Fp2::new(yp, PallasFp::zero()))
            );
            assert_eq!(
                fa.mul_by_014_unit_rank19(c1, c4, &weights),
                fa.mul_by_014_karatsuba39(Fp2::one(), c1, c4)
            );
            assert_eq!(
                fa.mul_by_014_projective_rank21(c0, c1, c4, &weights),
                fa.mul_by_014_karatsuba39(c0, c1, c4)
            );
        }
    }

    #[test]
    fn test_halo2_lookup_cost_model_and_gnark1951_quo_bits_soundness() {
        // 1. Verify `gnark#1951` small-field excess-quotient-bit soundness catch on BabyBear (`F = 31b`, `t = 22b`):
        // Emulate `Pallas` (`255b`) over BabyBear (`31b`) with `t = 22`-bit limbs (`2*22 = 44 >= 30`!):
        let p_pallas_m1 = PALLAS_BASE_MODULUS.sub_const(U1024::ONE);
        let bb_check = analyze_crt_quo_and_carries(
            PALLAS_BASE_MODULUS,
            p_pallas_m1.mul_const(U1024::from_u64(7)), // e.g., checkZero `7*a = k*p` -> `maxQuo = 6` (`quoBits = 3 < 22`)
            U1024::ZERO,
            12,
            22,
            31,
            3,
            true,
        );
        assert_eq!(bb_check.quo_bits, 3);
        assert_eq!(bb_check.top_quo_limb_bits, 3);
        assert!(
            bb_check.unmasked_full_limb_quo_unsound,
            "2t = 44 >= F - 1 = 30 with top_quo_limb_bits = 3 < 22 MUST flag unmasked quo wrap-around!"
        );

        // Conversely, over 255-bit Pasta with 88-bit or 64-bit limbs (`2*88 = 176 < 254`), `unmasked_full_limb_quo_unsound` is false,
        // while exact `quoBits` still saves lookup cells vs naive `nbQuoLimbs * limb_bits`!
        for &lookup_bits in &[8u32, 12, 16] {
            for &limb_bits in &[88u32, 64] {
                let model = Halo2LookupCostModel::new_pasta(lookup_bits, limb_bits);

                let pallas_wf = model.estimate_pasta_wrong_field_mul(PALLAS_BASE_MODULUS);
                let vesta_wf = model.estimate_pasta_wrong_field_mul(VESTA_BASE_MODULUS);
                assert_eq!(pallas_wf.num_limbs, if limb_bits == 88 { 3 } else { 4 });
                assert_eq!(pallas_wf.quo_bits, 255);
                assert!(pallas_wf.cells_saved_by_exact_quo_bits > 0);
                assert_eq!(pallas_wf.total_cells, vesta_wf.total_cells);

                let c_sb54 = model.estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Schoolbook54);
                let c_k36 = model.estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Karatsuba36);
                let c_crt30 = model.estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Crt30);
                let c_r23 = model.estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Rank23);

                assert_eq!(c_crt30.num_limbs, if limb_bits == 88 { 5 } else { 6 });
                assert_eq!(c_sb54.pre_mul_reductions, 0);
                assert_eq!(c_k36.pre_mul_reductions, 0);
                assert_eq!(c_crt30.pre_mul_reductions, 0);
                assert_eq!(c_r23.pre_mul_reductions, 22);

                // Verify `CRT-30` is the strict global winner across EVERY `(lookup_bits, limb_bits)` pair!
                assert!(
                    c_crt30.total_cells < c_k36.total_cells
                        && c_k36.total_cells < c_sb54.total_cells,
                    "CRT-30 ({}) < Karatsuba-36 ({}) < Schoolbook-54 ({}) failed at lookup={}, limb={}",
                    c_crt30.total_cells,
                    c_k36.total_cells,
                    c_sb54.total_cells,
                    lookup_bits,
                    limb_bits
                );
                assert!(
                    c_crt30.total_cells < c_r23.total_cells,
                    "CRT-30 ({}) must beat pre-reduction-penalized Rank-23 ({}) at lookup={}, limb={}",
                    c_crt30.total_cells,
                    c_r23.total_cells,
                    lookup_bits,
                    limb_bits
                );
            }
        }

        // Verify higher `lookup_bits` strictly decreases total cells (`16 < 12 < 8`)
        let c8 = Halo2LookupCostModel::new_pasta(8, 88)
            .estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Crt30);
        let c12 = Halo2LookupCostModel::new_pasta(12, 88)
            .estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Crt30);
        let c16 = Halo2LookupCostModel::new_pasta(16, 88)
            .estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Crt30);
        assert!(c16.total_cells < c12.total_cells && c12.total_cells < c8.total_cells);

        // Pin exact deterministic PlonKish cell totals across lookup_bits in {8, 12, 16} & limb_bits in {88, 64}
        assert_eq!(c8.total_cells, 39_451);
        assert_eq!(c12.total_cells, 29_899);
        assert_eq!(c16.total_cells, 24_475);
        assert_eq!(
            Halo2LookupCostModel::new_pasta(16, 88)
                .estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Schoolbook54)
                .total_cells,
            33_787
        );
        assert_eq!(
            Halo2LookupCostModel::new_pasta(16, 64)
                .estimate_bls12_381_fp12_mul(Halo2Fp12ScheduleKind::Crt30)
                .total_cells,
            28_231
        );
        assert_eq!(
            Halo2LookupCostModel::new_pasta(16, 88)
                .estimate_pasta_wrong_field_mul(PALLAS_BASE_MODULUS)
                .total_cells,
            290
        );
    }

    #[test]
    fn test_adversarial_weight_tamper_detected() {
        let base_w = Bls12381TowerWeights::<FastPrime1000003>::new();
        let one = FastPrime1000003::one();
        let two = FastPrime1000003::new(2);

        let a6 = fp6_from_slice(&[two, one, two, one, two, one]);
        let mut bad_w6 = base_w.clone();
        bad_w6.fp6_rank11[0][0] = bad_w6.fp6_rank11[0][0].add(one);
        assert_ne!(a6.mul_rank11(a6, &bad_w6), a6.mul_schoolbook_ref(a6));

        let a12 = fp12_from_slice(&[two, one, two, one, two, one, two, one, two, one, two, one]);
        let mut bad_w12 = base_w.clone();
        bad_w12.fp12_rank23_even[0][0] = bad_w12.fp12_rank23_even[0][0].add(one);
        assert_ne!(a12.mul_rank23(a12, &bad_w12), a12.mul_schoolbook_ref(a12));

        let mut bad_w18 = base_w;
        bad_w18.fp12_rank18_odd[0][0] = bad_w18.fp12_rank18_odd[0][0].add(one);
        let c1 = Fp2::new(FastPrime1000003::new(3), FastPrime1000003::new(5));
        let yp = FastPrime1000003::new(7);
        assert_ne!(
            a12.mul_by_014_rank18(c1, yp, &bad_w18),
            a12.mul_by_014_karatsuba39(Fp2::one(), c1, Fp2::new(yp, FastPrime1000003::zero()))
        );
    }
}
