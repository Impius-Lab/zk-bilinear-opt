//! Zero-overflow `no_std` extension-field multiplication kernels and generic degree-2
//! AIR constraint evaluators for StarkWare `stwo` (`CM31`, `QM31`) and `Plonky3` / `SP1`
//! (`BabyBear^4`, `BabyBear^5`, `KoalaBear^4`, `KoalaBear^8`, `Goldilocks^{2,4,5}`).
//!
//! Every kernel in [`generated`] is algebraically certified across all `d^2` basis pairs
//! against Winograd / Alder-Strassen `2d - 1` optimal bilinear decompositions, with exact
//! intermediate accumulator bounds (`< 2^63` for 31-bit primes, `< 2^128` for Goldilocks).

#![no_std]

pub mod generated;
pub use generated::*;

pub const M31_P: u32 = (1u32 << 31) - 1;
pub const BABYBEAR_P: u32 = (1u32 << 31) - (1u32 << 27) + 1;
pub const KOALABEAR_P: u32 = (1u32 << 31) - (1u32 << 24) + 1;
pub const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

/// Minimal trait abstracting `Plonky3` (`AirBuilder::Expr`) and `stwo` (`EvalAtRow`)
/// symbolic constraint expressions where constant scalar multiplication is degree-0
/// (free in constraint degree) and variable multiplication has degree 2.
pub trait SymbolicFieldExpr: Clone {
    fn zero() -> Self;
    fn add_assign(&mut self, rhs: Self);
    fn sub_assign(&mut self, rhs: Self);
    fn scale_signed(&self, coeff: i64) -> Self;
    fn mul_expr(&self, rhs: &Self) -> Self;
}

/// Generic degree-2 bilinear constraint evaluator checking `D * c == W_z * (U a (*) V b)`.
/// Requires `R = 2d - 1` bilinear witness products `m[0..R]` when chaining inside degree-2 AIRs,
/// or evaluates `c` directly as degree-2 polynomials in `(a, b)` with zero extra columns!
pub fn eval_bilinear_direct<E: SymbolicFieldExpr, const D_DIM: usize, const R_RANK: usize>(
    a: &[E; D_DIM],
    b: &[E; D_DIM],
    u_mat: &[[i64; D_DIM]; R_RANK],
    v_mat: &[[i64; D_DIM]; R_RANK],
    wz_mat: &[[i64; R_RANK]; D_DIM],
) -> [E; D_DIM] {
    let mut m: [E; R_RANK] = core::array::from_fn(|_| E::zero());
    let mut l = 0;
    while l < R_RANK {
        let mut ua = E::zero();
        let mut vb = E::zero();
        let mut i = 0;
        while i < D_DIM {
            if u_mat[l][i] != 0 {
                ua.add_assign(a[i].scale_signed(u_mat[l][i]));
            }
            if v_mat[l][i] != 0 {
                vb.add_assign(b[i].scale_signed(v_mat[l][i]));
            }
            i += 1;
        }
        m[l] = ua.mul_expr(&vb);
        l += 1;
    }

    core::array::from_fn(|k| {
        let mut acc = E::zero();
        let mut idx = 0;
        while idx < R_RANK {
            if wz_mat[k][idx] != 0 {
                acc.add_assign(m[idx].scale_signed(wz_mat[k][idx]));
            }
            idx += 1;
        }
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ref_binomial_u32<const D: usize>(a: &[u32; D], b: &[u32; D], w: u64, p: u64) -> [u32; D] {
        let mut prod = [0u64; 2 * D];
        for i in 0..D {
            for j in 0..D {
                prod[i + j] = (prod[i + j] + (a[i] as u64) * (b[j] as u64)) % p;
            }
        }
        let mut out = [0u32; D];
        for i in 0..D {
            let folded = (prod[i] + ((prod[i + D] * w) % p)) % p;
            out[i] = folded as u32;
        }
        out
    }

    fn ref_qm31(a: &[u32; 4], b: &[u32; 4]) -> [u32; 4] {
        let p = M31_P as i64;
        let cm_mul = |x0: i64, x1: i64, y0: i64, y1: i64| -> (i64, i64) {
            ((x0 * y0 - x1 * y1).rem_euclid(p), (x0 * y1 + x1 * y0).rem_euclid(p))
        };
        let (ac0, ac1) = cm_mul(a[0] as i64, a[1] as i64, b[0] as i64, b[1] as i64);
        let (bd0, bd1) = cm_mul(a[2] as i64, a[3] as i64, b[2] as i64, b[3] as i64);
        let bd_xi0 = (2 * bd0 - bd1).rem_euclid(p);
        let bd_xi1 = (bd0 + 2 * bd1).rem_euclid(p);
        let (ad0, ad1) = cm_mul(a[0] as i64, a[1] as i64, b[2] as i64, b[3] as i64);
        let (bc0, bc1) = cm_mul(a[2] as i64, a[3] as i64, b[0] as i64, b[1] as i64);
        [
            ((ac0 + bd_xi0) % p) as u32,
            ((ac1 + bd_xi1) % p) as u32,
            ((ad0 + bc0) % p) as u32,
            ((ad1 + bc1) % p) as u32,
        ]
    }

    #[test]
    fn test_qm31_rank7_vs_ref_and_max_overflow() {
        let max_v = [M31_P - 1; 4];
        assert_eq!(mul_qm31_rank7(&max_v, &max_v), ref_qm31(&max_v, &max_v));
        assert_eq!(mul_qm31_rank7(&max_v, &max_v), mul_qm31_karatsuba9(&max_v, &max_v));
    }

    #[test]
    fn test_plonky3_extensions_max_vectors() {
        let bb4_max = [BABYBEAR_P - 1; 4];
        assert_eq!(
            mul_babybear4_rank7(&bb4_max, &bb4_max),
            ref_binomial_u32(&bb4_max, &bb4_max, 11, BABYBEAR_P as u64)
        );
        let bb5_max = [BABYBEAR_P - 1; 5];
        assert_eq!(
            mul_babybear5_rank9(&bb5_max, &bb5_max),
            ref_binomial_u32(&bb5_max, &bb5_max, 2, BABYBEAR_P as u64)
        );
        let kb4_max = [KOALABEAR_P - 1; 4];
        assert_eq!(
            mul_koalabear4_rank7(&kb4_max, &kb4_max),
            ref_binomial_u32(&kb4_max, &kb4_max, 3, KOALABEAR_P as u64)
        );
        let kb8_max = [KOALABEAR_P - 1; 8];
        assert_eq!(
            mul_koalabear8_rank15(&kb8_max, &kb8_max),
            ref_binomial_u32(&kb8_max, &kb8_max, 3, KOALABEAR_P as u64)
        );
    }

    fn ref_binomial_u64<const D: usize>(a: &[u64; D], b: &[u64; D], w: u128, p: u128) -> [u64; D] {
        let mut prod = [0u128; 2 * D];
        for i in 0..D {
            for j in 0..D {
                let term = ((a[i] as u128) * (b[j] as u128)) % p;
                prod[i + j] = (prod[i + j] + term) % p;
            }
        }
        let mut out = [0u64; D];
        for i in 0..D {
            let folded = (prod[i] + ((prod[i + D] * w) % p)) % p;
            out[i] = folded as u64;
        }
        out
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct M31Expr(u32);

    impl SymbolicFieldExpr for M31Expr {
        fn zero() -> Self {
            Self(0)
        }
        fn add_assign(&mut self, rhs: Self) {
            self.0 = (((self.0 as u64) + (rhs.0 as u64)) % (M31_P as u64)) as u32;
        }
        fn sub_assign(&mut self, rhs: Self) {
            self.0 = (((self.0 as i64) - (rhs.0 as i64)).rem_euclid(M31_P as i64)) as u32;
        }
        fn scale_signed(&self, coeff: i64) -> Self {
            let v = ((self.0 as i64) * coeff).rem_euclid(M31_P as i64);
            Self(v as u32)
        }
        fn mul_expr(&self, rhs: &Self) -> Self {
            Self((((self.0 as u64) * (rhs.0 as u64)) % (M31_P as u64)) as u32)
        }
    }

    #[test]
    fn test_cm31_goldilocks_and_eval_bilinear_direct() {
        let cm_max = [M31_P - 1; 2];
        let cm_got = mul_cm31_rank3(&cm_max, &cm_max);
        assert_eq!(cm_got, [0, 2]);

        let u_cm: [[i64; 2]; 3] = [[1, 0], [0, 1], [1, 1]];
        let v_cm: [[i64; 2]; 3] = [[1, 0], [0, 1], [1, 1]];
        let wz_cm: [[i64; 3]; 2] = [[1, -1, 0], [-1, -1, 1]];
        let expr_a = [M31Expr(cm_max[0]), M31Expr(cm_max[1])];
        let expr_out = eval_bilinear_direct(&expr_a, &expr_a, &u_cm, &v_cm, &wz_cm);
        assert_eq!([expr_out[0].0, expr_out[1].0], cm_got);

        let gl2_max = [GOLDILOCKS_P - 1; 2];
        assert_eq!(
            mul_goldilocks2_rank3(&gl2_max, &gl2_max),
            ref_binomial_u64(&gl2_max, &gl2_max, 7, GOLDILOCKS_P as u128)
        );
        let gl4_max = [GOLDILOCKS_P - 1; 4];
        assert_eq!(
            mul_goldilocks4_rank7(&gl4_max, &gl4_max),
            ref_binomial_u64(&gl4_max, &gl4_max, 7, GOLDILOCKS_P as u128)
        );
        let gl5_max = [GOLDILOCKS_P - 1; 5];
        assert_eq!(
            mul_goldilocks5_rank9(&gl5_max, &gl5_max),
            ref_binomial_u64(&gl5_max, &gl5_max, 3, GOLDILOCKS_P as u128)
        );
    }
}
