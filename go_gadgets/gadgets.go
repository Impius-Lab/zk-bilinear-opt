// Package gogadgets provides exact native and gnark-compatible bilinear extension
// multiplication gadgets for QM31 (StarkWare stwo), BabyBear^4/5 & KoalaBear^4/8
// (Plonky3/SP1), and BN254 / BLS12-381 Fp6 & Fp12 pairing towers.
package gogadgets

import (
	"fmt"
	"math/big"
)

func mustBigInt(dec string) *big.Int {
	v, ok := new(big.Int).SetString(dec, 10)
	if !ok {
		panic(fmt.Sprintf("invalid decimal big.Int: %s", dec))
	}
	return v
}

func evalBilinearInt64(
	a, b []*big.Int,
	p, invD *big.Int,
	d, r int,
	uMat, vMat, wzMat [][]int64,
) []*big.Int {
	if len(a) != d || len(b) != d {
		panic(fmt.Sprintf("expected slices of length %d", d))
	}
	m := make([]*big.Int, r)
	tmp := new(big.Int)
	coef := new(big.Int)

	for l := 0; l < r; l++ {
		uAcc := new(big.Int)
		vAcc := new(big.Int)
		for i := 0; i < d; i++ {
			if uMat[l][i] != 0 {
				coef.SetInt64(uMat[l][i])
				tmp.Mul(coef, a[i])
				uAcc.Add(uAcc, tmp)
			}
			if vMat[l][i] != 0 {
				coef.SetInt64(vMat[l][i])
				tmp.Mul(coef, b[i])
				vAcc.Add(vAcc, tmp)
			}
		}
		uAcc.Mod(uAcc, p)
		vAcc.Mod(vAcc, p)
		prod := new(big.Int).Mul(uAcc, vAcc)
		prod.Mod(prod, p)
		m[l] = prod
	}

	out := make([]*big.Int, d)
	for k := 0; k < d; k++ {
		wAcc := new(big.Int)
		for l := 0; l < r; l++ {
			if wzMat[k][l] != 0 {
				coef.SetInt64(wzMat[k][l])
				tmp.Mul(coef, m[l])
				wAcc.Add(wAcc, tmp)
			}
		}
		wAcc.Mod(wAcc, p)
		wAcc.Mul(wAcc, invD)
		wAcc.Mod(wAcc, p)
		out[k] = wAcc
	}
	return out
}

func evalBilinearBigWz(
	a, b []*big.Int,
	p, invD *big.Int,
	d, r int,
	uMat, vMat [][]int64,
	wzStr [][]string,
) []*big.Int {
	if len(a) != d || len(b) != d {
		panic(fmt.Sprintf("expected slices of length %d", d))
	}
	m := make([]*big.Int, r)
	tmp := new(big.Int)
	coef := new(big.Int)

	for l := 0; l < r; l++ {
		uAcc := new(big.Int)
		vAcc := new(big.Int)
		for i := 0; i < d; i++ {
			if uMat[l][i] != 0 {
				coef.SetInt64(uMat[l][i])
				tmp.Mul(coef, a[i])
				uAcc.Add(uAcc, tmp)
			}
			if vMat[l][i] != 0 {
				coef.SetInt64(vMat[l][i])
				tmp.Mul(coef, b[i])
				vAcc.Add(vAcc, tmp)
			}
		}
		uAcc.Mod(uAcc, p)
		vAcc.Mod(vAcc, p)
		prod := new(big.Int).Mul(uAcc, vAcc)
		prod.Mod(prod, p)
		m[l] = prod
	}

	out := make([]*big.Int, d)
	for k := 0; k < d; k++ {
		wAcc := new(big.Int)
		for l := 0; l < r; l++ {
			wCoef := mustBigInt(wzStr[k][l])
			if wCoef.Sign() != 0 {
				tmp.Mul(wCoef, m[l])
				wAcc.Add(wAcc, tmp)
			}
		}
		wAcc.Mod(wAcc, p)
		wAcc.Mul(wAcc, invD)
		wAcc.Mod(wAcc, p)
		out[k] = wAcc
	}
	return out
}

// ---------------------------------------------------------------------------
// Independent Textbook / Tower Reference Multipliers (Zero Shared Matrices)
// ---------------------------------------------------------------------------

// RefMulBinomial computes textbook schoolbook multiplication in F_p[X]/(X^d - w).
func RefMulBinomial(a, b []*big.Int, d int, w int64, p *big.Int) []*big.Int {
	prod := make([]*big.Int, 2*d-1)
	for i := range prod {
		prod[i] = new(big.Int)
	}
	tmp := new(big.Int)
	for i := 0; i < d; i++ {
		for j := 0; j < d; j++ {
			tmp.Mul(a[i], b[j])
			prod[i+j].Add(prod[i+j], tmp)
			prod[i+j].Mod(prod[i+j], p)
		}
	}
	wBig := big.NewInt(w)
	out := make([]*big.Int, d)
	for i := 0; i < d; i++ {
		out[i] = new(big.Int).Set(prod[i])
	}
	for k := d; k < 2*d-1; k++ {
		tmp.Mul(prod[k], wBig)
		out[k-d].Add(out[k-d], tmp)
		out[k-d].Mod(out[k-d], p)
	}
	return out
}

func refFp2Mul(a0, a1, b0, b1, p *big.Int) (*big.Int, *big.Int) {
	ac := new(big.Int).Mul(a0, b0)
	bd := new(big.Int).Mul(a1, b1)
	r0 := new(big.Int).Sub(ac, bd)
	r0.Mod(r0, p)

	ad := new(big.Int).Mul(a0, b1)
	bc := new(big.Int).Mul(a1, b0)
	r1 := new(big.Int).Add(ad, bc)
	r1.Mod(r1, p)
	return r0, r1
}

func refFp2MulXi(x0, x1 *big.Int, xi0 int64, p *big.Int) (*big.Int, *big.Int) {
	xi := big.NewInt(xi0)
	t0 := new(big.Int).Mul(xi, x0)
	t0.Sub(t0, x1)
	t0.Mod(t0, p)

	t1 := new(big.Int).Mul(xi, x1)
	t1.Add(t1, x0)
	t1.Mod(t1, p)
	return t0, t1
}

// RefMulQM31 computes textbook StarkWare stwo QM31 = CM31[u]/(u^2 - (2 + i)).
func RefMulQM31(a, b []*big.Int, p *big.Int) []*big.Int {
	ac0, ac1 := refFp2Mul(a[0], a[1], b[0], b[1], p)
	bd0, bd1 := refFp2Mul(a[2], a[3], b[2], b[3], p)
	bx0, bx1 := refFp2MulXi(bd0, bd1, 2, p)
	ad0, ad1 := refFp2Mul(a[0], a[1], b[2], b[3], p)
	bc0, bc1 := refFp2Mul(a[2], a[3], b[0], b[1], p)

	o0 := new(big.Int).Add(ac0, bx0)
	o0.Mod(o0, p)
	o1 := new(big.Int).Add(ac1, bx1)
	o1.Mod(o1, p)
	o2 := new(big.Int).Add(ad0, bc0)
	o2.Mod(o2, p)
	o3 := new(big.Int).Add(ad1, bc1)
	o3.Mod(o3, p)
	return []*big.Int{o0, o1, o2, o3}
}

// RefMulFp6Tower computes textbook Fp6 = Fp2[v]/(v^3 - (xi0 + u)).
func RefMulFp6Tower(a, b []*big.Int, xi0 int64, p *big.Int) []*big.Int {
	c0 := make([]*big.Int, 5)
	c1 := make([]*big.Int, 5)
	for k := 0; k < 5; k++ {
		c0[k] = new(big.Int)
		c1[k] = new(big.Int)
	}
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			p0, p1 := refFp2Mul(a[2*i], a[2*i+1], b[2*j], b[2*j+1], p)
			c0[i+j].Add(c0[i+j], p0)
			c0[i+j].Mod(c0[i+j], p)
			c1[i+j].Add(c1[i+j], p1)
			c1[i+j].Mod(c1[i+j], p)
		}
	}
	for k := 3; k < 5; k++ {
		s0, s1 := refFp2MulXi(c0[k], c1[k], xi0, p)
		c0[k-3].Add(c0[k-3], s0)
		c0[k-3].Mod(c0[k-3], p)
		c1[k-3].Add(c1[k-3], s1)
		c1[k-3].Mod(c1[k-3], p)
	}
	return []*big.Int{c0[0], c1[0], c0[1], c1[1], c0[2], c1[2]}
}

// RefMulFp12Tower computes textbook Fp12 = Fp6[w]/(w^2 - v).
func RefMulFp12Tower(a, b []*big.Int, xi0 int64, p *big.Int) []*big.Int {
	a0, a1 := a[:6], a[6:]
	b0, b1 := b[:6], b[6:]
	p00 := RefMulFp6Tower(a0, b0, xi0, p)
	p11 := RefMulFp6Tower(a1, b1, xi0, p)
	p01 := RefMulFp6Tower(a0, b1, xi0, p)
	p10 := RefMulFp6Tower(a1, b0, xi0, p)

	// v * p11 = (xi * B2) + B0*v + B1*v^2
	xiB2_0, xiB2_1 := refFp2MulXi(p11[4], p11[5], xi0, p)
	vp11 := []*big.Int{xiB2_0, xiB2_1, p11[0], p11[1], p11[2], p11[3]}

	out := make([]*big.Int, 12)
	for i := 0; i < 6; i++ {
		out[i] = new(big.Int).Add(p00[i], vp11[i])
		out[i].Mod(out[i], p)
		out[6+i] = new(big.Int).Add(p01[i], p10[i])
		out[6+i].Mod(out[6+i], p)
	}
	return out
}

func refBLS12377Fp2Mul(a0, a1, b0, b1, p *big.Int) (*big.Int, *big.Int) {
	ac := new(big.Int).Mul(a0, b0)
	bd := new(big.Int).Mul(a1, b1)
	bd5 := new(big.Int).Mul(bd, big.NewInt(5))
	r0 := new(big.Int).Sub(ac, bd5)
	r0.Mod(r0, p)

	ad := new(big.Int).Mul(a0, b1)
	bc := new(big.Int).Mul(a1, b0)
	r1 := new(big.Int).Add(ad, bc)
	r1.Mod(r1, p)
	return r0, r1
}

func refBLS12377Fp2MulU(x0, x1, p *big.Int) (*big.Int, *big.Int) {
	// u * (x0 + x1*u) = -5*x1 + x0*u  (u^2 = -5)
	t0 := new(big.Int).Mul(x1, big.NewInt(-5))
	t0.Mod(t0, p)
	t1 := new(big.Int).Mod(x0, p)
	return t0, t1
}

// RefMulBLS12377Fp2Tower computes textbook BLS12-377 E2 = Fp[u]/(u^2 + 5).
func RefMulBLS12377Fp2Tower(a, b []*big.Int, p *big.Int) []*big.Int {
	r0, r1 := refBLS12377Fp2Mul(a[0], a[1], b[0], b[1], p)
	return []*big.Int{r0, r1}
}

// RefMulBLS12377Fp6Tower computes textbook gnark BLS12-377 E6 = E2[v]/(v^3 - u).
func RefMulBLS12377Fp6Tower(a, b []*big.Int, p *big.Int) []*big.Int {
	c0 := make([]*big.Int, 5)
	c1 := make([]*big.Int, 5)
	for k := 0; k < 5; k++ {
		c0[k] = new(big.Int)
		c1[k] = new(big.Int)
	}
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			p0, p1 := refBLS12377Fp2Mul(a[2*i], a[2*i+1], b[2*j], b[2*j+1], p)
			c0[i+j].Add(c0[i+j], p0)
			c0[i+j].Mod(c0[i+j], p)
			c1[i+j].Add(c1[i+j], p1)
			c1[i+j].Mod(c1[i+j], p)
		}
	}
	for k := 3; k < 5; k++ {
		s0, s1 := refBLS12377Fp2MulU(c0[k], c1[k], p)
		c0[k-3].Add(c0[k-3], s0)
		c0[k-3].Mod(c0[k-3], p)
		c1[k-3].Add(c1[k-3], s1)
		c1[k-3].Mod(c1[k-3], p)
	}
	return []*big.Int{c0[0], c1[0], c0[1], c1[1], c0[2], c1[2]}
}

// RefMulBLS12377Fp12Tower computes textbook gnark BLS12-377 E12 = E6[w]/(w^2 - v).
func RefMulBLS12377Fp12Tower(a, b []*big.Int, p *big.Int) []*big.Int {
	a0, a1 := a[:6], a[6:]
	b0, b1 := b[:6], b[6:]
	p00 := RefMulBLS12377Fp6Tower(a0, b0, p)
	p11 := RefMulBLS12377Fp6Tower(a1, b1, p)
	p01 := RefMulBLS12377Fp6Tower(a0, b1, p)
	p10 := RefMulBLS12377Fp6Tower(a1, b0, p)

	// v * p11 = (u * B2) + B0*v + B1*v^2
	uB2_0, uB2_1 := refBLS12377Fp2MulU(p11[4], p11[5], p)
	vp11 := []*big.Int{uB2_0, uB2_1, p11[0], p11[1], p11[2], p11[3]}

	out := make([]*big.Int, 12)
	for i := 0; i < 6; i++ {
		out[i] = new(big.Int).Add(p00[i], vp11[i])
		out[i].Mod(out[i], p)
		out[6+i] = new(big.Int).Add(p01[i], p10[i])
		out[6+i].Mod(out[6+i], p)
	}
	return out
}
