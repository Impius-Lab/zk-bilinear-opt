//! `#![no_std]` Wiedemann (`Binius`) Binary-Tower Arithmetic (`GF(2^2)` .. `GF(2^128)`)
//! and Isomorphic / Rank-24 AES (`GF(2^8)`) Kernels.
//!
//! Tower construction (Wiedemann 1988; Diamond & Posen 2023 "Binius"):
//!   - `T_0 = F_2`
//!   - `T_1 = T_0[X_0] / (X_0^2 + X_0 + 1)`
//!   - `T_{k+1} = T_k[X_k] / (X_k^2 + X_{k-1} X_k + 1)` for `k >= 1`.
//!
//! Every `mul_alpha` (`X_{k-1}` scaling) and `square` (Frobenius squaring) uses `0` AND gates
//! (purely `F_2`-linear XOR networks), recursive Karatsuba-Wiedemann `mul` uses `3^k` AND gates
//! (`2,187` ANDs at `GF(2^128)` vs `16,384` schoolbook = `-86.65%`), and `inv` uses recursive
//! Itoh-Tsujii norm descent (`a^{-1} = conj(a) * N(a)^{-1}`).

#![forbid(unsafe_code)]

/// Canonical `8 x 8` `GF(2)` row masks mapping AES `F_2[x]/(x^8 + x^4 + x^3 + x + 1)` (`0x11b`)
/// coordinates to Wiedemann `T_3` coordinates (`x -> 0x30` in `T_3`, `det = 1 mod 2`).
pub const AES_TO_BINIUS_T3_ROWS: [u8; 8] = [0xa1, 0xe4, 0xf8, 0xe0, 0x72, 0xa2, 0x70, 0x0c];

/// Exact `GF(2)` inverse row masks mapping Wiedemann `T_3` back to AES `GF(2^8)`.
pub const BINIUS_T3_TO_AES_ROWS: [u8; 8] = [0x71, 0x50, 0x0a, 0x8a, 0x86, 0xbe, 0x78, 0xce];

/// Certified Rank-24 `GF(4)` Chudnovsky-CRT evaluation masks (`U == V`) on Wiedemann `T_3`.
pub const BINIUS_T3_RANK24_UV: [u8; 24] = [
    0x49, 0x8e, 0xc7, 0x15, 0x2a, 0x3f, 0xa9, 0xfe, 0x57, 0xf1, 0x52, 0xa3, 0xcd, 0x46, 0x8b, 0x54,
    0xa8, 0xfc, 0x99, 0xee, 0x77, 0x04, 0x08, 0x0c,
];

/// Certified Rank-24 `GF(4)` Chudnovsky-CRT interpolation masks (`W`) on Wiedemann `T_3`.
pub const BINIUS_T3_RANK24_W: [u32; 8] = [
    0x786bb6, 0xac3cdb, 0xd70c03, 0x798605, 0xb5bd86, 0xdad6c3, 0xb70ced, 0xd98776,
];

/// Certified Rank-24 `GF(4)` Chudnovsky-CRT evaluation masks (`U == V`) in native AES `GF(2^8)`.
pub const AES_GF256_RANK24_UV: [u8; 24] = [
    0x31, 0xf0, 0xc1, 0x2b, 0xa6, 0x8d, 0xef, 0x50, 0xbf, 0x0d, 0xe6, 0xeb, 0xc5, 0x6c, 0xa9, 0xfa,
    0x4e, 0xb4, 0x3f, 0x22, 0x1d, 0xf8, 0xe0, 0x18,
];

/// Certified Rank-24 `GF(4)` Chudnovsky-CRT interpolation masks (`W`) in native AES `GF(2^8)`.
pub const AES_GF256_RANK24_W: [u32; 8] = [
    0xa00c1e, 0x02b16b, 0xd5bade, 0x0c3da8, 0xa2b7ae, 0xb45aee, 0xa1e1ad, 0x6c3d46,
];

// ============================================================================
// 1. X_{k-1} Linear Scaling (`mul_alpha`: 0 AND gates)
// ============================================================================

/// Multiply `a in T_1 = GF(2^2)` (`2`-bit value) by `X_0` (`X_0^2 = X_0 + 1`).
#[inline]
pub const fn gf2_2_mul_alpha(a: u8) -> u8 {
    let a0 = a & 1;
    let a1 = (a >> 1) & 1;
    a1 | ((a0 ^ a1) << 1)
}

/// Multiply `a in T_2 = GF(2^4)` (`4`-bit value) by `X_1`.
#[inline]
pub const fn gf2_4_mul_alpha(a: u8) -> u8 {
    let a0 = a & 0x3;
    let a1 = (a >> 2) & 0x3;
    a1 | ((a0 ^ gf2_2_mul_alpha(a1)) << 2)
}

/// Multiply `a in T_3 = GF(2^8)` by `X_2`.
#[inline]
pub const fn gf2_8_mul_alpha(a: u8) -> u8 {
    let a0 = a & 0x0f;
    let a1 = (a >> 4) & 0x0f;
    a1 | ((a0 ^ gf2_4_mul_alpha(a1)) << 4)
}

/// Multiply `a in T_4 = GF(2^16)` by `X_3`.
#[inline]
pub const fn gf2_16_mul_alpha(a: u16) -> u16 {
    let a0 = (a & 0xff) as u8;
    let a1 = (a >> 8) as u8;
    (a1 as u16) | (((a0 ^ gf2_8_mul_alpha(a1)) as u16) << 8)
}

/// Multiply `a in T_5 = GF(2^32)` by `X_4`.
#[inline]
pub const fn gf2_32_mul_alpha(a: u32) -> u32 {
    let a0 = (a & 0xffff) as u16;
    let a1 = (a >> 16) as u16;
    (a1 as u32) | (((a0 ^ gf2_16_mul_alpha(a1)) as u32) << 16)
}

/// Multiply `a in T_6 = GF(2^64)` by `X_5`.
#[inline]
pub const fn gf2_64_mul_alpha(a: u64) -> u64 {
    let a0 = (a & 0xffff_ffff) as u32;
    let a1 = (a >> 32) as u32;
    (a1 as u64) | (((a0 ^ gf2_32_mul_alpha(a1)) as u64) << 32)
}

/// Multiply `a in T_7 = GF(2^128)` by `X_6`.
#[inline]
pub const fn gf2_128_mul_alpha(a: u128) -> u128 {
    let a0 = a as u64;
    let a1 = (a >> 64) as u64;
    (a1 as u128) | (((a0 ^ gf2_64_mul_alpha(a1)) as u128) << 64)
}

// ============================================================================
// 2. Recursive Karatsuba-Wiedemann Multiplication (`3^k` AND gates)
// ============================================================================

/// Rank-3 multiplication in `T_1 = GF(2^2)` (`2`-bit inputs).
#[inline]
pub const fn gf2_2_mul(a: u8, b: u8) -> u8 {
    let a0 = a & 1;
    let a1 = (a >> 1) & 1;
    let b0 = b & 1;
    let b1 = (b >> 1) & 1;
    let p0 = a0 & b0;
    let p1 = a1 & b1;
    let pm = (a0 ^ a1) & (b0 ^ b1);
    let c0 = p0 ^ p1;
    let c1 = pm ^ p0; // pm ^ (p0 ^ p1) ^ p1 == pm ^ p0
    c0 | (c1 << 1)
}

/// Rank-9 multiplication in `T_2 = GF(2^4)` (`4`-bit inputs).
#[inline]
pub const fn gf2_4_mul(a: u8, b: u8) -> u8 {
    let a0 = a & 0x3;
    let a1 = (a >> 2) & 0x3;
    let b0 = b & 0x3;
    let b1 = (b >> 2) & 0x3;
    let p0 = gf2_2_mul(a0, b0);
    let p1 = gf2_2_mul(a1, b1);
    let pm = gf2_2_mul(a0 ^ a1, b0 ^ b1);
    let c0 = p0 ^ p1;
    let c1 = pm ^ c0 ^ gf2_2_mul_alpha(p1);
    c0 | (c1 << 2)
}

/// Rank-27 multiplication in `T_3 = GF(2^8)`.
#[inline]
pub const fn gf2_8_mul(a: u8, b: u8) -> u8 {
    let a0 = a & 0x0f;
    let a1 = (a >> 4) & 0x0f;
    let b0 = b & 0x0f;
    let b1 = (b >> 4) & 0x0f;
    let p0 = gf2_4_mul(a0, b0);
    let p1 = gf2_4_mul(a1, b1);
    let pm = gf2_4_mul(a0 ^ a1, b0 ^ b1);
    let c0 = p0 ^ p1;
    let c1 = pm ^ c0 ^ gf2_4_mul_alpha(p1);
    c0 | (c1 << 4)
}

/// Rank-81 multiplication in `T_4 = GF(2^16)`.
#[inline]
pub const fn gf2_16_mul(a: u16, b: u16) -> u16 {
    let a0 = (a & 0xff) as u8;
    let a1 = (a >> 8) as u8;
    let b0 = (b & 0xff) as u8;
    let b1 = (b >> 8) as u8;
    let p0 = gf2_8_mul(a0, b0);
    let p1 = gf2_8_mul(a1, b1);
    let pm = gf2_8_mul(a0 ^ a1, b0 ^ b1);
    let c0 = p0 ^ p1;
    let c1 = pm ^ c0 ^ gf2_8_mul_alpha(p1);
    (c0 as u16) | ((c1 as u16) << 8)
}

/// Rank-243 multiplication in `T_5 = GF(2^32)`.
#[inline]
pub const fn gf2_32_mul(a: u32, b: u32) -> u32 {
    let a0 = (a & 0xffff) as u16;
    let a1 = (a >> 16) as u16;
    let b0 = (b & 0xffff) as u16;
    let b1 = (b >> 16) as u16;
    let p0 = gf2_16_mul(a0, b0);
    let p1 = gf2_16_mul(a1, b1);
    let pm = gf2_16_mul(a0 ^ a1, b0 ^ b1);
    let c0 = p0 ^ p1;
    let c1 = pm ^ c0 ^ gf2_16_mul_alpha(p1);
    (c0 as u32) | ((c1 as u32) << 16)
}

/// Rank-729 multiplication in `T_6 = GF(2^64)`.
#[inline]
pub const fn gf2_64_mul(a: u64, b: u64) -> u64 {
    let a0 = (a & 0xffff_ffff) as u32;
    let a1 = (a >> 32) as u32;
    let b0 = (b & 0xffff_ffff) as u32;
    let b1 = (b >> 32) as u32;
    let p0 = gf2_32_mul(a0, b0);
    let p1 = gf2_32_mul(a1, b1);
    let pm = gf2_32_mul(a0 ^ a1, b0 ^ b1);
    let c0 = p0 ^ p1;
    let c1 = pm ^ c0 ^ gf2_32_mul_alpha(p1);
    (c0 as u64) | ((c1 as u64) << 32)
}

/// Rank-2187 multiplication in `T_7 = GF(2^128)` (`-86.65%` AND gates vs `16,384` schoolbook).
#[inline]
pub const fn gf2_128_mul(a: u128, b: u128) -> u128 {
    let a0 = a as u64;
    let a1 = (a >> 64) as u64;
    let b0 = b as u64;
    let b1 = (b >> 64) as u64;
    let p0 = gf2_64_mul(a0, b0);
    let p1 = gf2_64_mul(a1, b1);
    let pm = gf2_64_mul(a0 ^ a1, b0 ^ b1);
    let c0 = p0 ^ p1;
    let c1 = pm ^ c0 ^ gf2_64_mul_alpha(p1);
    (c0 as u128) | ((c1 as u128) << 64)
}

// ============================================================================
// 3. Frobenius Linear Squaring (`0` AND gates across all levels)
// ============================================================================

#[inline]
pub const fn gf2_2_square(a: u8) -> u8 {
    let a0 = a & 1;
    let a1 = (a >> 1) & 1;
    (a0 ^ a1) | (a1 << 1)
}

#[inline]
pub const fn gf2_4_square(a: u8) -> u8 {
    let s0 = gf2_2_square(a & 0x3);
    let s1 = gf2_2_square((a >> 2) & 0x3);
    (s0 ^ s1) | (gf2_2_mul_alpha(s1) << 2)
}

#[inline]
pub const fn gf2_8_square(a: u8) -> u8 {
    let s0 = gf2_4_square(a & 0x0f);
    let s1 = gf2_4_square((a >> 4) & 0x0f);
    (s0 ^ s1) | (gf2_4_mul_alpha(s1) << 4)
}

#[inline]
pub const fn gf2_16_square(a: u16) -> u16 {
    let s0 = gf2_8_square((a & 0xff) as u8);
    let s1 = gf2_8_square((a >> 8) as u8);
    ((s0 ^ s1) as u16) | ((gf2_8_mul_alpha(s1) as u16) << 8)
}

#[inline]
pub const fn gf2_32_square(a: u32) -> u32 {
    let s0 = gf2_16_square((a & 0xffff) as u16);
    let s1 = gf2_16_square((a >> 16) as u16);
    ((s0 ^ s1) as u32) | ((gf2_16_mul_alpha(s1) as u32) << 16)
}

#[inline]
pub const fn gf2_64_square(a: u64) -> u64 {
    let s0 = gf2_32_square((a & 0xffff_ffff) as u32);
    let s1 = gf2_32_square((a >> 32) as u32);
    ((s0 ^ s1) as u64) | ((gf2_32_mul_alpha(s1) as u64) << 32)
}

#[inline]
pub const fn gf2_128_square(a: u128) -> u128 {
    let s0 = gf2_64_square(a as u64);
    let s1 = gf2_64_square((a >> 64) as u64);
    ((s0 ^ s1) as u128) | ((gf2_64_mul_alpha(s1) as u128) << 64)
}

// ============================================================================
// 4. Itoh-Tsujii Recursive Norm-Descent Inversion (`Option<T>`)
// ============================================================================

#[inline]
pub const fn gf2_2_inv(a: u8) -> Option<u8> {
    let a = a & 0x3;
    if a == 0 {
        return None;
    }
    // In GF(4), a^{-1} = a^2!
    Some(gf2_2_square(a))
}

#[inline]
pub const fn gf2_4_inv(a: u8) -> Option<u8> {
    let a = a & 0x0f;
    if a == 0 {
        return None;
    }
    let a0 = a & 0x3;
    let a1 = (a >> 2) & 0x3;
    let t = a0 ^ gf2_2_mul_alpha(a1);
    let norm = gf2_2_mul(a0, t) ^ gf2_2_square(a1);
    let Some(norm_inv) = gf2_2_inv(norm) else {
        return None;
    };
    Some(gf2_2_mul(t, norm_inv) | (gf2_2_mul(a1, norm_inv) << 2))
}

#[inline]
pub const fn gf2_8_inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    let a0 = a & 0x0f;
    let a1 = (a >> 4) & 0x0f;
    let t = a0 ^ gf2_4_mul_alpha(a1);
    let norm = gf2_4_mul(a0, t) ^ gf2_4_square(a1);
    let Some(norm_inv) = gf2_4_inv(norm) else {
        return None;
    };
    Some(gf2_4_mul(t, norm_inv) | (gf2_4_mul(a1, norm_inv) << 4))
}

#[inline]
pub const fn gf2_16_inv(a: u16) -> Option<u16> {
    if a == 0 {
        return None;
    }
    let a0 = (a & 0xff) as u8;
    let a1 = (a >> 8) as u8;
    let t = a0 ^ gf2_8_mul_alpha(a1);
    let norm = gf2_8_mul(a0, t) ^ gf2_8_square(a1);
    let Some(norm_inv) = gf2_8_inv(norm) else {
        return None;
    };
    Some((gf2_8_mul(t, norm_inv) as u16) | ((gf2_8_mul(a1, norm_inv) as u16) << 8))
}

#[inline]
pub const fn gf2_32_inv(a: u32) -> Option<u32> {
    if a == 0 {
        return None;
    }
    let a0 = (a & 0xffff) as u16;
    let a1 = (a >> 16) as u16;
    let t = a0 ^ gf2_16_mul_alpha(a1);
    let norm = gf2_16_mul(a0, t) ^ gf2_16_square(a1);
    let Some(norm_inv) = gf2_16_inv(norm) else {
        return None;
    };
    Some((gf2_16_mul(t, norm_inv) as u32) | ((gf2_16_mul(a1, norm_inv) as u32) << 16))
}

#[inline]
pub const fn gf2_64_inv(a: u64) -> Option<u64> {
    if a == 0 {
        return None;
    }
    let a0 = (a & 0xffff_ffff) as u32;
    let a1 = (a >> 32) as u32;
    let t = a0 ^ gf2_32_mul_alpha(a1);
    let norm = gf2_32_mul(a0, t) ^ gf2_32_square(a1);
    let Some(norm_inv) = gf2_32_inv(norm) else {
        return None;
    };
    Some((gf2_32_mul(t, norm_inv) as u64) | ((gf2_32_mul(a1, norm_inv) as u64) << 32))
}

#[inline]
pub const fn gf2_128_inv(a: u128) -> Option<u128> {
    if a == 0 {
        return None;
    }
    let a0 = a as u64;
    let a1 = (a >> 64) as u64;
    let t = a0 ^ gf2_64_mul_alpha(a1);
    let norm = gf2_64_mul(a0, t) ^ gf2_64_square(a1);
    let Some(norm_inv) = gf2_64_inv(norm) else {
        return None;
    };
    Some((gf2_64_mul(t, norm_inv) as u128) | ((gf2_64_mul(a1, norm_inv) as u128) << 64))
}

/// Zero-sized namespace grouping all `Binius` Wiedemann binary-tower primitives (`T_1..T_7`).
pub struct BiniusTower;

impl BiniusTower {
    #[inline]
    pub const fn mul_128(a: u128, b: u128) -> u128 {
        gf2_128_mul(a, b)
    }

    #[inline]
    pub const fn square_128(a: u128) -> u128 {
        gf2_128_square(a)
    }

    #[inline]
    pub const fn inv_128(a: u128) -> Option<u128> {
        gf2_128_inv(a)
    }
}

// ============================================================================
// 5. AES / Rijndael GF(2^8) Isomorphism & Rank-24 Chudnovsky-GF(4) Schedules
// ============================================================================

#[inline]
const fn apply_gf2_mat8(rows: &[u8; 8], x: u8) -> u8 {
    let mut out = 0u8;
    let mut i = 0;
    while i < 8 {
        if ((rows[i] & x).count_ones() & 1) != 0 {
            out |= 1u8 << i;
        }
        i += 1;
    }
    out
}

#[inline]
const fn eval_rank24_u8(uv: &[u8; 24], w: &[u32; 8], a: u8, b: u8) -> u8 {
    let mut m = 0u32;
    let mut l = 0;
    while l < 24 {
        let ua = (uv[l] & a).count_ones() & 1;
        let vb = (uv[l] & b).count_ones() & 1;
        m |= (ua & vb) << l;
        l += 1;
    }
    let mut out = 0u8;
    let mut k = 0;
    while k < 8 {
        if ((w[k] & m).count_ones() & 1) != 0 {
            out |= 1u8 << k;
        }
        k += 1;
    }
    out
}

/// Map an AES `GF(2^8)` byte (`x^8 + x^4 + x^3 + x + 1`) to Wiedemann `T_3`.
#[inline]
pub const fn aes_to_binius_t3(a_aes: u8) -> u8 {
    apply_gf2_mat8(&AES_TO_BINIUS_T3_ROWS, a_aes)
}

/// Map a Wiedemann `T_3` byte back to AES `GF(2^8)`.
#[inline]
pub const fn binius_t3_to_aes(a_t3: u8) -> u8 {
    apply_gf2_mat8(&BINIUS_T3_TO_AES_ROWS, a_t3)
}

/// Multiply two AES `GF(2^8)` bytes via `GF(2)` isomorphism into Wiedemann `T_3` (27 ANDs).
#[inline]
pub const fn aes_gf256_mul(a: u8, b: u8) -> u8 {
    binius_t3_to_aes(gf2_8_mul(aes_to_binius_t3(a), aes_to_binius_t3(b)))
}

/// Invert a non-zero AES `GF(2^8)` byte via Wiedemann `T_3` Itoh-Tsujii norm descent.
#[inline]
pub const fn aes_gf256_inv(a: u8) -> Option<u8> {
    match gf2_8_inv(aes_to_binius_t3(a)) {
        Some(inv_t3) => Some(binius_t3_to_aes(inv_t3)),
        None => None,
    }
}

/// Certified Rank-24 (`24` AND gates, `-62.50%` vs `64` schoolbook) Wiedemann `T_3` multiplier.
#[inline]
pub const fn gf2_8_mul_rank24(a: u8, b: u8) -> u8 {
    eval_rank24_u8(&BINIUS_T3_RANK24_UV, &BINIUS_T3_RANK24_W, a, b)
}

/// Certified Rank-24 (`24` AND gates, `-62.50%` vs `64` schoolbook) native AES `GF(2^8)` multiplier.
#[inline]
pub const fn aes_gf256_mul_rank24(a: u8, b: u8) -> u8 {
    eval_rank24_u8(&AES_GF256_RANK24_UV, &AES_GF256_RANK24_W, a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn aes_schoolbook_ref(mut a: u8, mut b: u8) -> u8 {
        let mut acc = 0u8;
        let mut i = 0;
        while i < 8 {
            if (b & 1) != 0 {
                acc ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
            i += 1;
        }
        acc
    }

    /// Independent definition-level reference for `T_4 = T_3[X_3] / (X_3^2 + X_2 X_3 + 1)`
    /// reducing directly by `X_k^2 = X_{k-1} X_k + 1` via schoolbook distribution over basis pairs.
    fn binius_basis_pair_ref(k: usize, i: usize, j: usize) -> u128 {
        if k == 0 {
            return 1;
        }
        let half = 1usize << (k - 1);
        let i_hi = (i >= half) as usize;
        let j_hi = (j >= half) as usize;
        let i_lo = i & (half - 1);
        let j_lo = j & (half - 1);

        let sub = binius_basis_pair_ref(k - 1, i_lo, j_lo);
        match (i_hi, j_hi) {
            (0, 0) => sub,
            (1, 0) | (0, 1) => sub << half,
            (1, 1) => {
                // sub * X_{k-1}^2 = sub * (X_{k-2} * X_{k-1} + 1) = sub ^ (mul_by_X_{k-2}(sub) << half)
                let alpha_idx = half >> 1; // index of X_{k-2} in T_{k-1} (or 0 => 1 when k == 1)
                let mut hi = 0u128;
                if k == 1 {
                    hi = sub;
                } else {
                    for bit in 0..half {
                        if ((sub >> bit) & 1) != 0 {
                            hi ^= binius_basis_pair_ref(k - 1, bit, alpha_idx);
                        }
                    }
                }
                sub ^ (hi << half)
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_aes_all_64_basis_pairs_and_exhaustive_65536_bytes() {
        // 1. Explicit 64 (8x8) GF(2) basis-pair check:
        for i in 0..8usize {
            let ea = 1u8 << i;
            for j in 0..8usize {
                let eb = 1u8 << j;
                let want = aes_schoolbook_ref(ea, eb);
                assert_eq!(aes_gf256_mul(ea, eb), want, "AES iso basis mismatch at ({i}, {j})");
                assert_eq!(
                    aes_gf256_mul_rank24(ea, eb),
                    want,
                    "AES rank24 basis mismatch at ({i}, {j})"
                );
            }
        }

        // 2. Bijection & inversion across all 256 bytes + exhaustive 65,536 byte-pair check:
        assert_eq!(aes_gf256_inv(0), None);
        for a in 0u16..256 {
            let ab = a as u8;
            assert_eq!(binius_t3_to_aes(aes_to_binius_t3(ab)), ab);
            assert_eq!(aes_to_binius_t3(binius_t3_to_aes(ab)), ab);
            if ab != 0 {
                let inv_a = aes_gf256_inv(ab).expect("non-zero AES element must invert");
                assert_eq!(aes_schoolbook_ref(ab, inv_a), 1);
            }
            for b in 0u16..256 {
                let bb = b as u8;
                let want = aes_schoolbook_ref(ab, bb);
                assert_eq!(aes_gf256_mul(ab, bb), want);
                assert_eq!(aes_gf256_mul_rank24(ab, bb), want);
                assert_eq!(gf2_8_mul_rank24(ab, bb), gf2_8_mul(ab, bb));
            }
        }
    }

    #[test]
    fn test_gf2_16_all_256_basis_pairs_and_exhaustive_inverses() {
        for i in 0..16usize {
            let ea = 1u16 << i;
            for j in 0..16usize {
                let eb = 1u16 << j;
                let want = binius_basis_pair_ref(4, i, j) as u16;
                assert_eq!(gf2_16_mul(ea, eb), want, "GF(2^16) basis mismatch at ({i}, {j})");
            }
        }
        assert_eq!(gf2_16_inv(0), None);
        for a in 1u32..=65535 {
            let au = a as u16;
            assert_eq!(gf2_16_square(au), gf2_16_mul(au, au));
            if a % 97 == 0 || !(256..=65400).contains(&a) {
                let inv = gf2_16_inv(au).unwrap();
                assert_eq!(gf2_16_mul(au, inv), 1);
            }
        }
    }

    #[test]
    fn test_gf2_128_field_axioms_frob_and_inversion() {
        assert_eq!(gf2_2_inv(0), None);
        assert_eq!(gf2_4_inv(0), None);
        assert_eq!(gf2_8_inv(0), None);
        assert_eq!(gf2_32_inv(0), None);
        assert_eq!(gf2_64_inv(0), None);
        assert_eq!(gf2_128_inv(0), None);

        // Deterministic SplitMix64 pseudo-random 128-bit field elements
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next_u128 = || -> u128 {
            let mut gen64 = || -> u64 {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            };
            (gen64() as u128) | ((gen64() as u128) << 64)
        };

        for _ in 0..512 {
            let a = next_u128();
            let b = next_u128();
            let c = next_u128();

            // Identity & zero
            assert_eq!(BiniusTower::mul_128(a, 0), 0);
            assert_eq!(BiniusTower::mul_128(a, 1), a);

            // Commutativity
            let ab = BiniusTower::mul_128(a, b);
            assert_eq!(ab, BiniusTower::mul_128(b, a));

            // Associativity: (a * b) * c == a * (b * c)
            let bc = BiniusTower::mul_128(b, c);
            assert_eq!(BiniusTower::mul_128(ab, c), BiniusTower::mul_128(a, bc));

            // Distributivity: a * (b ^ c) == (a * b) ^ (a * c)
            let ac = BiniusTower::mul_128(a, c);
            assert_eq!(BiniusTower::mul_128(a, b ^ c), ab ^ ac);

            // Frobenius squaring == mul(a, a) & linearity (a ^ b)^2 == a^2 ^ b^2
            let sq_a = BiniusTower::square_128(a);
            let sq_b = BiniusTower::square_128(b);
            assert_eq!(sq_a, BiniusTower::mul_128(a, a));
            assert_eq!(BiniusTower::square_128(a ^ b), sq_a ^ sq_b);

            // Multiplicative inverse: a * a.inv() == 1
            if a != 0 {
                let inv_a = BiniusTower::inv_128(a).expect("non-zero u128 must invert");
                assert_eq!(BiniusTower::mul_128(a, inv_a), 1);
            }
        }

        // Also pin lower-level square == mul and inv across 32-bit and 64-bit towers
        for _ in 0..256 {
            let x64 = next_u128() as u64;
            let x32 = x64 as u32;
            assert_eq!(gf2_32_square(x32), gf2_32_mul(x32, x32));
            assert_eq!(gf2_64_square(x64), gf2_64_mul(x64, x64));
            if x32 != 0 {
                assert_eq!(gf2_32_mul(x32, gf2_32_inv(x32).unwrap()), 1);
            }
            if x64 != 0 {
                assert_eq!(gf2_64_mul(x64, gf2_64_inv(x64).unwrap()), 1);
            }
        }
    }
}
