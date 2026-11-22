// Exact zero-allocation [6]uint64 CIOS Montgomery base-field and step-by-step
// tower arithmetic for BLS12-377 (verified over BW6-761 in Consensys/gnark).
package gogadgets

import (
	"math/big"
	"math/bits"
)

// Fp377 represents an element of F_p for BLS12-377 in Montgomery form (x * 2^384 mod p)
// across 6 little-endian 64-bit limbs.
type Fp377 [6]uint64

// BLS12377Modulus is P_BLS12_377 = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001.
var BLS12377Modulus = Fp377{
	0x8508c00000000001,
	0x170b5d4430000000,
	0x1ef3622fba094800,
	0x1a22d9f300f5138f,
	0xc63b05c06ca1493b,
	0x01ae3a4617c510ea,
}

// bls12377InvNeg = -p^{-1} mod 2^64.
const bls12377InvNeg uint64 = 0x8508bfffffffffff

// BLS12377OneMont = 2^384 mod p (multiplicative identity 1 in Montgomery form).
var BLS12377OneMont = Fp377{
	0x02cdffffffffff68,
	0x51409f837fffffb1,
	0x9f7db3a98a7d3ff2,
	0x7b4e97b76e7c6305,
	0x4cf495bf803c84e8,
	0x008d6661e2fdf49a,
}

// bls12377R2 = 2^768 mod p (for converting standard residues into Montgomery form).
var bls12377R2 = Fp377{
	0xb786686c9400cd22,
	0x0329fcaab00431b1,
	0x22a5f11162d6b46d,
	0xbfdf7d03827dc3ac,
	0x837e92f041790bf9,
	0x006dfccb1e914b88,
}

// BLS12377PrimeBig returns the exact BLS12-377 base prime as a *big.Int.
func BLS12377PrimeBig() *big.Int {
	return mustBigInt("258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177")
}

// Fp377FromBigInt converts an arbitrary *big.Int into canonical Montgomery [6]uint64 form.
func Fp377FromBigInt(v *big.Int) Fp377 {
	p := BLS12377PrimeBig()
	red := new(big.Int).Mod(v, p)
	var raw Fp377
	words := red.Bits()
	if bits.UintSize == 64 {
		for i := 0; i < len(words) && i < 6; i++ {
			raw[i] = uint64(words[i])
		}
	} else {
		tmp := new(big.Int).Set(red)
		mask := new(big.Int).SetUint64(^uint64(0))
		for i := 0; i < 6; i++ {
			limb := new(big.Int).And(tmp, mask)
			raw[i] = limb.Uint64()
			tmp.Rsh(tmp, 64)
		}
	}
	return fp377MontMul(raw, bls12377R2)
}

// ToBigInt converts an Fp377 element from Montgomery form back to a canonical *big.Int in [0, p-1].
func (z Fp377) ToBigInt() *big.Int {
	raw := fp377MontMul(z, Fp377{1, 0, 0, 0, 0, 0})
	out := new(big.Int)
	for i := 5; i >= 0; i-- {
		out.Lsh(out, 64)
		out.Add(out, new(big.Int).SetUint64(raw[i]))
	}
	return out
}

func fp377SubModIfGTE(t Fp377) Fp377 {
	var d Fp377
	var borrow uint64
	d[0], borrow = bits.Sub64(t[0], BLS12377Modulus[0], 0)
	d[1], borrow = bits.Sub64(t[1], BLS12377Modulus[1], borrow)
	d[2], borrow = bits.Sub64(t[2], BLS12377Modulus[2], borrow)
	d[3], borrow = bits.Sub64(t[3], BLS12377Modulus[3], borrow)
	d[4], borrow = bits.Sub64(t[4], BLS12377Modulus[4], borrow)
	d[5], borrow = bits.Sub64(t[5], BLS12377Modulus[5], borrow)
	if borrow == 0 {
		return d
	}
	return t
}

func fp377Add(a, b Fp377) Fp377 {
	var s Fp377
	var c uint64
	s[0], c = bits.Add64(a[0], b[0], 0)
	s[1], c = bits.Add64(a[1], b[1], c)
	s[2], c = bits.Add64(a[2], b[2], c)
	s[3], c = bits.Add64(a[3], b[3], c)
	s[4], c = bits.Add64(a[4], b[4], c)
	s[5], _ = bits.Add64(a[5], b[5], c)
	return fp377SubModIfGTE(s)
}

func fp377Sub(a, b Fp377) Fp377 {
	var d Fp377
	var borrow uint64
	d[0], borrow = bits.Sub64(a[0], b[0], 0)
	d[1], borrow = bits.Sub64(a[1], b[1], borrow)
	d[2], borrow = bits.Sub64(a[2], b[2], borrow)
	d[3], borrow = bits.Sub64(a[3], b[3], borrow)
	d[4], borrow = bits.Sub64(a[4], b[4], borrow)
	d[5], borrow = bits.Sub64(a[5], b[5], borrow)
	if borrow != 0 {
		var c uint64
		d[0], c = bits.Add64(d[0], BLS12377Modulus[0], 0)
		d[1], c = bits.Add64(d[1], BLS12377Modulus[1], c)
		d[2], c = bits.Add64(d[2], BLS12377Modulus[2], c)
		d[3], c = bits.Add64(d[3], BLS12377Modulus[3], c)
		d[4], c = bits.Add64(d[4], BLS12377Modulus[4], c)
		d[5], _ = bits.Add64(d[5], BLS12377Modulus[5], c)
	}
	return d
}

func fp377Neg(a Fp377) Fp377 {
	if (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]) == 0 {
		return Fp377{}
	}
	var d Fp377
	var borrow uint64
	d[0], borrow = bits.Sub64(BLS12377Modulus[0], a[0], 0)
	d[1], borrow = bits.Sub64(BLS12377Modulus[1], a[1], borrow)
	d[2], borrow = bits.Sub64(BLS12377Modulus[2], a[2], borrow)
	d[3], borrow = bits.Sub64(BLS12377Modulus[3], a[3], borrow)
	d[4], borrow = bits.Sub64(BLS12377Modulus[4], a[4], borrow)
	d[5], _ = bits.Sub64(BLS12377Modulus[5], a[5], borrow)
	return d
}

// mac64 computes (lo, hi) = x*y + z + carry without 128-bit overflow:
// max value is (2^64-1)^2 + 2*(2^64-1) = 2^128 - 1.
func mac64(x, y, z, carry uint64) (lo, hi uint64) {
	pHi, pLo := bits.Mul64(x, y)
	sLo, c1 := bits.Add64(pLo, z, 0)
	sLo, c2 := bits.Add64(sLo, carry, 0)
	return sLo, pHi + c1 + c2
}

// fp377MontMul performs exact 6-limb spare-bit CIOS Montgomery multiplication
// (a * b * 2^{-384} mod p), exploiting P_BLS12_377 < 2^377 < 2^383.
func fp377MontMul(a, b Fp377) Fp377 {
	var t Fp377
	for i := 0; i < 6; i++ {
		var carry uint64
		t[0], carry = mac64(a[i], b[0], t[0], 0)
		t[1], carry = mac64(a[i], b[1], t[1], carry)
		t[2], carry = mac64(a[i], b[2], t[2], carry)
		t[3], carry = mac64(a[i], b[3], t[3], carry)
		t[4], carry = mac64(a[i], b[4], t[4], carry)
		t[5], carry = mac64(a[i], b[5], t[5], carry)
		carryA := carry

		m := t[0] * bls12377InvNeg
		_, carry = mac64(m, BLS12377Modulus[0], t[0], 0)
		t[0], carry = mac64(m, BLS12377Modulus[1], t[1], carry)
		t[1], carry = mac64(m, BLS12377Modulus[2], t[2], carry)
		t[2], carry = mac64(m, BLS12377Modulus[3], t[3], carry)
		t[3], carry = mac64(m, BLS12377Modulus[4], t[4], carry)
		t[4], carry = mac64(m, BLS12377Modulus[5], t[5], carry)
		t[5] = carryA + carry
	}
	return fp377SubModIfGTE(t)
}

// fp377Mul executes a bilinear variable-by-variable base-field multiplication in Fp377.
func fp377Mul(a, b Fp377) Fp377 {
	return fp377MontMul(a, b)
}

// fp377ScaleConst executes linear constant scaling by a fixed Montgomery constant in Fp377.
func fp377ScaleConst(a, cMont Fp377) Fp377 {
	return fp377MontMul(a, cMont)
}

func fp377MulByNeg5(x Fp377) Fp377 {
	x2 := fp377Add(x, x)
	x4 := fp377Add(x2, x2)
	x5 := fp377Add(x4, x)
	return fp377Neg(x5)
}

// ---------------------------------------------------------------------------
// Step-by-Step [6]uint64 Reference Tower Arithmetic for BLS12-377
// E2 = Fp[u]/(u^2 + 5), E6 = E2[v]/(v^3 - u), E12 = E6[w]/(w^2 - v)
// ---------------------------------------------------------------------------

// RefMulBLS12377Fp2U64 computes step-by-step E2 multiplication (u^2 = -5) in [6]uint64 limbs.
func RefMulBLS12377Fp2U64(a, b [2]Fp377) [2]Fp377 {
	ac := fp377Mul(a[0], b[0])
	bd := fp377Mul(a[1], b[1])
	ad := fp377Mul(a[0], b[1])
	bc := fp377Mul(a[1], b[0])
	return [2]Fp377{
		fp377Add(ac, fp377MulByNeg5(bd)),
		fp377Add(ad, bc),
	}
}

func fp377E2MulByU(x [2]Fp377) [2]Fp377 {
	return [2]Fp377{fp377MulByNeg5(x[1]), x[0]}
}

// RefMulBLS12377Fp6TowerU64 computes step-by-step E6 = E2[v]/(v^3 - u) tower multiplication.
func RefMulBLS12377Fp6TowerU64(a, b [6]Fp377) [6]Fp377 {
	var c [5][2]Fp377
	for i := 0; i < 3; i++ {
		ai := [2]Fp377{a[2*i], a[2*i+1]}
		for j := 0; j < 3; j++ {
			bj := [2]Fp377{b[2*j], b[2*j+1]}
			prod := RefMulBLS12377Fp2U64(ai, bj)
			c[i+j][0] = fp377Add(c[i+j][0], prod[0])
			c[i+j][1] = fp377Add(c[i+j][1], prod[1])
		}
	}
	for k := 3; k < 5; k++ {
		sh := fp377E2MulByU(c[k])
		c[k-3][0] = fp377Add(c[k-3][0], sh[0])
		c[k-3][1] = fp377Add(c[k-3][1], sh[1])
	}
	return [6]Fp377{c[0][0], c[0][1], c[1][0], c[1][1], c[2][0], c[2][1]}
}

// RefMulBLS12377Fp12TowerU64 computes step-by-step E12 = E6[w]/(w^2 - v) tower multiplication.
func RefMulBLS12377Fp12TowerU64(a, b [12]Fp377) [12]Fp377 {
	var a0, a1, b0, b1 [6]Fp377
	copy(a0[:], a[:6])
	copy(a1[:], a[6:])
	copy(b0[:], b[:6])
	copy(b1[:], b[6:])

	p00 := RefMulBLS12377Fp6TowerU64(a0, b0)
	p11 := RefMulBLS12377Fp6TowerU64(a1, b1)
	p01 := RefMulBLS12377Fp6TowerU64(a0, b1)
	p10 := RefMulBLS12377Fp6TowerU64(a1, b0)

	uB2 := fp377E2MulByU([2]Fp377{p11[4], p11[5]})
	vp11 := [6]Fp377{uB2[0], uB2[1], p11[0], p11[1], p11[2], p11[3]}

	var out [12]Fp377
	for i := 0; i < 6; i++ {
		out[i] = fp377Add(p00[i], vp11[i])
		out[6+i] = fp377Add(p01[i], p10[i])
	}
	return out
}
