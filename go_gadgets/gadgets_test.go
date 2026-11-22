package gogadgets

import (
	"math/big"
	"math/rand"
	"testing"
)

func basisVec(d, idx int) []*big.Int {
	v := make([]*big.Int, d)
	for i := 0; i < d; i++ {
		if i == idx {
			v[i] = big.NewInt(1)
		} else {
			v[i] = big.NewInt(0)
		}
	}
	return v
}

func maxVec(d int, p *big.Int) []*big.Int {
	pm1 := new(big.Int).Sub(p, big.NewInt(1))
	v := make([]*big.Int, d)
	for i := 0; i < d; i++ {
		v[i] = new(big.Int).Set(pm1)
	}
	return v
}

func randVec(rng *rand.Rand, d int, p *big.Int) []*big.Int {
	v := make([]*big.Int, d)
	for i := 0; i < d; i++ {
		v[i] = new(big.Int).Rand(rng, p)
	}
	return v
}

func assertSliceEq(t *testing.T, label string, got, want []*big.Int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: len mismatch %d != %d", label, len(got), len(want))
	}
	for i := range got {
		if got[i].Cmp(want[i]) != 0 {
			t.Fatalf("%s: mismatch at coord %d: got %s, want %s", label, i, got[i], want[i])
		}
	}
}

func verifyGadgetComplete(
	t *testing.T,
	name string,
	d int,
	p *big.Int,
	fuzzSamples int,
	dut func(a, b []*big.Int) []*big.Int,
	ref func(a, b []*big.Int) []*big.Int,
) {
	t.Helper()
	// 1. Complete d^2 basis algebraic identity check
	for i := 0; i < d; i++ {
		ei := basisVec(d, i)
		for j := 0; j < d; j++ {
			ej := basisVec(d, j)
			assertSliceEq(t, name+" basis", dut(ei, ej), ref(ei, ej))
		}
	}
	// 2. Adversarial maximal input (p-1, ..., p-1), zero, and alternating (p-1, 0, ...)
	mv := maxVec(d, p)
	zv := make([]*big.Int, d)
	altA := make([]*big.Int, d)
	altB := make([]*big.Int, d)
	pm1 := new(big.Int).Sub(p, big.NewInt(1))
	for i := 0; i < d; i++ {
		zv[i] = big.NewInt(0)
		if i%2 == 0 {
			altA[i] = new(big.Int).Set(pm1)
			altB[i] = big.NewInt(0)
		} else {
			altA[i] = big.NewInt(0)
			altB[i] = new(big.Int).Set(pm1)
		}
	}
	assertSliceEq(t, name+" zero", dut(zv, mv), ref(zv, mv))
	assertSliceEq(t, name+" max(p-1)", dut(mv, mv), ref(mv, mv))
	assertSliceEq(t, name+" alternating", dut(altA, altB), ref(altA, altB))

	// 3. Deterministic randomized fuzzing
	rng := rand.New(rand.NewSource(20261121))
	for s := 0; s < fuzzSamples; s++ {
		ra := randVec(rng, d, p)
		rb := randVec(rng, d, p)
		assertSliceEq(t, name+" fuzz", dut(ra, rb), ref(ra, rb))
	}
}

func TestQM31StwoGadgets(t *testing.T) {
	p := mustBigInt("2147483647")
	ref := func(a, b []*big.Int) []*big.Int { return RefMulQM31(a, b, p) }
	verifyGadgetComplete(t, "QM31_Rank7", 4, p, 2000, MulQM31Rank7, ref)
	verifyGadgetComplete(t, "QM31_Karatsuba9", 4, p, 500, MulQM31Karatsuba9, ref)
}

func TestPlonky3Extensions(t *testing.T) {
	pBB := mustBigInt("2013265921")
	pKB := mustBigInt("2130706433")

	verifyGadgetComplete(
		t, "BabyBear4_Rank7", 4, pBB, 2000, MulBabyBear4Rank7,
		func(a, b []*big.Int) []*big.Int { return RefMulBinomial(a, b, 4, 11, pBB) },
	)
	verifyGadgetComplete(
		t, "BabyBear5_Rank9", 5, pBB, 2000, MulBabyBear5Rank9,
		func(a, b []*big.Int) []*big.Int { return RefMulBinomial(a, b, 5, 2, pBB) },
	)
	verifyGadgetComplete(
		t, "KoalaBear4_Rank7", 4, pKB, 2000, MulKoalaBear4Rank7,
		func(a, b []*big.Int) []*big.Int { return RefMulBinomial(a, b, 4, 3, pKB) },
	)
	verifyGadgetComplete(
		t, "KoalaBear8_Rank15", 8, pKB, 2000, MulKoalaBear8Rank15,
		func(a, b []*big.Int) []*big.Int { return RefMulBinomial(a, b, 8, 3, pKB) },
	)
}

func TestBN254PairingTowers(t *testing.T) {
	pBN := mustBigInt("21888242871839275222246405745257275088696311157297823662689037894645226208583")
	ref6 := func(a, b []*big.Int) []*big.Int { return RefMulFp6Tower(a, b, 9, pBN) }
	ref12 := func(a, b []*big.Int) []*big.Int { return RefMulFp12Tower(a, b, 9, pBN) }

	verifyGadgetComplete(t, "BN254_Fp6_Rank11", 6, pBN, 1000, MulBN254Fp6Rank11, ref6)
	verifyGadgetComplete(t, "BN254_Fp6_Tower18", 6, pBN, 300, MulBN254Fp6Tower18, ref6)

	verifyGadgetComplete(t, "BN254_Fp12_Tower33", 12, pBN, 500, MulBN254Fp12Tower33, ref12)
	verifyGadgetComplete(t, "BN254_Fp12_CRT30", 12, pBN, 500, MulBN254Fp12CRT30, ref12)
	verifyGadgetComplete(t, "BN254_Fp12_Rank23", 12, pBN, 500, MulBN254Fp12Rank23, ref12)
	verifyGadgetComplete(t, "BN254_Fp12_Tower54", 12, pBN, 300, MulBN254Fp12Tower54, ref12)
}

func TestBLS12381PairingTowers(t *testing.T) {
	pBLS := mustBigInt("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787")
	ref6 := func(a, b []*big.Int) []*big.Int { return RefMulFp6Tower(a, b, 1, pBLS) }
	ref12 := func(a, b []*big.Int) []*big.Int { return RefMulFp12Tower(a, b, 1, pBLS) }

	verifyGadgetComplete(t, "BLS12_381_Fp6_Rank11", 6, pBLS, 1000, MulBLS12381Fp6Rank11, ref6)
	verifyGadgetComplete(t, "BLS12_381_Fp6_Tower18", 6, pBLS, 300, MulBLS12381Fp6Tower18, ref6)

	verifyGadgetComplete(t, "BLS12_381_Fp12_Tower33", 12, pBLS, 500, MulBLS12381Fp12Tower33, ref12)
	verifyGadgetComplete(t, "BLS12_381_Fp12_CRT30", 12, pBLS, 500, MulBLS12381Fp12CRT30, ref12)
	verifyGadgetComplete(t, "BLS12_381_Fp12_Rank23", 12, pBLS, 500, MulBLS12381Fp12Rank23, ref12)
	verifyGadgetComplete(t, "BLS12_381_Fp12_Tower54", 12, pBLS, 300, MulBLS12381Fp12Tower54, ref12)
}

func TestBLS12377PairingTowers(t *testing.T) {
	p377 := BLS12377PrimeBig()
	ref2 := func(a, b []*big.Int) []*big.Int { return RefMulBLS12377Fp2Tower(a, b, p377) }
	ref6 := func(a, b []*big.Int) []*big.Int { return RefMulBLS12377Fp6Tower(a, b, p377) }
	ref12 := func(a, b []*big.Int) []*big.Int { return RefMulBLS12377Fp12Tower(a, b, p377) }

	verifyGadgetComplete(t, "BLS12_377_Fp2_Rank3", 2, p377, 1000, MulBLS12377Fp2Rank3, ref2)

	verifyGadgetComplete(t, "BLS12_377_Fp6_Rank11", 6, p377, 1000, MulBLS12377Fp6Rank11, ref6)
	verifyGadgetComplete(t, "BLS12_377_Fp6_Toom15", 6, p377, 500, MulBLS12377Fp6Toom15, ref6)
	verifyGadgetComplete(t, "BLS12_377_Fp6_Tower18", 6, p377, 300, MulBLS12377Fp6Tower18, ref6)

	verifyGadgetComplete(t, "BLS12_377_Fp12_Tower33", 12, p377, 500, MulBLS12377Fp12Tower33, ref12)
	verifyGadgetComplete(t, "BLS12_377_Fp12_CRT30", 12, p377, 500, MulBLS12377Fp12CRT30, ref12)
	verifyGadgetComplete(t, "BLS12_377_Fp12_Rank23", 12, p377, 1000, MulBLS12377Fp12Rank23, ref12)
	verifyGadgetComplete(t, "BLS12_377_Fp12_Toom45", 12, p377, 300, MulBLS12377Fp12Toom45, ref12)
	verifyGadgetComplete(t, "BLS12_377_Fp12_Tower54", 12, p377, 300, MulBLS12377Fp12Tower54, ref12)
}

func TestBLS12377U64LimbGadgets(t *testing.T) {
	p377 := BLS12377PrimeBig()
	pm1 := new(big.Int).Sub(p377, big.NewInt(1))

	// 1. Base-field [6]uint64 Montgomery arithmetic sanity & edge cases
	zero := Fp377FromBigInt(big.NewInt(0))
	one := Fp377FromBigInt(big.NewInt(1))
	maxElem := Fp377FromBigInt(pm1)
	if one != BLS12377OneMont {
		t.Fatalf("Fp377FromBigInt(1) != BLS12377OneMont: got %x", one)
	}
	if fp377Add(maxElem, one) != zero {
		t.Fatalf("(p-1) + 1 != 0 in Fp377")
	}
	if fp377Sub(zero, one) != maxElem {
		t.Fatalf("0 - 1 != p-1 in Fp377")
	}
	// (p-1)*(p-1) == 1 mod p
	if fp377Mul(maxElem, maxElem) != one {
		t.Fatalf("(p-1)*(p-1) != 1 in Fp377")
	}

	rng := rand.New(rand.NewSource(20261122))
	for s := 0; s < 2000; s++ {
		xa := new(big.Int).Rand(rng, p377)
		xb := new(big.Int).Rand(rng, p377)
		fa := Fp377FromBigInt(xa)
		fb := Fp377FromBigInt(xb)

		gotMul := fp377Mul(fa, fb).ToBigInt()
		wantMul := new(big.Int).Mul(xa, xb)
		wantMul.Mod(wantMul, p377)
		if gotMul.Cmp(wantMul) != 0 {
			t.Fatalf("fp377Mul mismatch: got %s, want %s", gotMul, wantMul)
		}

		gotAdd := fp377Add(fa, fb).ToBigInt()
		wantAdd := new(big.Int).Add(xa, xb)
		wantAdd.Mod(wantAdd, p377)
		if gotAdd.Cmp(wantAdd) != 0 {
			t.Fatalf("fp377Add mismatch: got %s, want %s", gotAdd, wantAdd)
		}

		gotSub := fp377Sub(fa, fb).ToBigInt()
		wantSub := new(big.Int).Sub(xa, xb)
		wantSub.Mod(wantSub, p377)
		if gotSub.Cmp(wantSub) != 0 {
			t.Fatalf("fp377Sub mismatch: got %s, want %s", gotSub, wantSub)
		}
	}

	// 2. E2 Rank-3 [6]uint64: all 4 basis pairs + max(p-1) + 1000 random trials
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			var ei, ej [2]Fp377
			ei[i] = one
			ej[j] = one
			if MulBLS12377Fp2Rank3U64(ei, ej) != RefMulBLS12377Fp2U64(ei, ej) {
				t.Fatalf("E2 U64 basis mismatch at (%d, %d)", i, j)
			}
		}
	}
	max2 := [2]Fp377{maxElem, maxElem}
	if MulBLS12377Fp2Rank3U64(max2, max2) != RefMulBLS12377Fp2U64(max2, max2) {
		t.Fatalf("E2 U64 max(p-1) mismatch")
	}
	for s := 0; s < 1000; s++ {
		var a2, b2 [2]Fp377
		aBig := randVec(rng, 2, p377)
		bBig := randVec(rng, 2, p377)
		for k := 0; k < 2; k++ {
			a2[k] = Fp377FromBigInt(aBig[k])
			b2[k] = Fp377FromBigInt(bBig[k])
		}
		got2 := MulBLS12377Fp2Rank3U64(a2, b2)
		ref2U64 := RefMulBLS12377Fp2U64(a2, b2)
		if got2 != ref2U64 {
			t.Fatalf("E2 U64 fuzz mismatch at sample %d", s)
		}
		ref2Big := RefMulBLS12377Fp2Tower(aBig, bBig, p377)
		for k := 0; k < 2; k++ {
			if got2[k].ToBigInt().Cmp(ref2Big[k]) != 0 {
				t.Fatalf("E2 U64 vs big.Int mismatch at sample %d coord %d", s, k)
			}
		}
	}

	// 3. E6 Rank-11 [6]uint64: all 36 basis pairs + max(p-1) + 1000 random trials
	for i := 0; i < 6; i++ {
		for j := 0; j < 6; j++ {
			var ei, ej [6]Fp377
			ei[i] = one
			ej[j] = one
			if MulBLS12377Fp6Rank11U64(ei, ej) != RefMulBLS12377Fp6TowerU64(ei, ej) {
				t.Fatalf("E6 U64 basis mismatch at (%d, %d)", i, j)
			}
		}
	}
	var max6 [6]Fp377
	for k := 0; k < 6; k++ {
		max6[k] = maxElem
	}
	if MulBLS12377Fp6Rank11U64(max6, max6) != RefMulBLS12377Fp6TowerU64(max6, max6) {
		t.Fatalf("E6 U64 max(p-1) mismatch")
	}
	for s := 0; s < 1000; s++ {
		var a6, b6 [6]Fp377
		aBig := randVec(rng, 6, p377)
		bBig := randVec(rng, 6, p377)
		for k := 0; k < 6; k++ {
			a6[k] = Fp377FromBigInt(aBig[k])
			b6[k] = Fp377FromBigInt(bBig[k])
		}
		got6 := MulBLS12377Fp6Rank11U64(a6, b6)
		ref6U64 := RefMulBLS12377Fp6TowerU64(a6, b6)
		if got6 != ref6U64 {
			t.Fatalf("E6 U64 fuzz mismatch at sample %d", s)
		}
		ref6Big := RefMulBLS12377Fp6Tower(aBig, bBig, p377)
		for k := 0; k < 6; k++ {
			if got6[k].ToBigInt().Cmp(ref6Big[k]) != 0 {
				t.Fatalf("E6 U64 vs big.Int mismatch at sample %d coord %d", s, k)
			}
		}
	}

	// 4. E12 Rank-23 [6]uint64: all 144 basis pairs + max(p-1) + 1000 random trials
	for i := 0; i < 12; i++ {
		for j := 0; j < 12; j++ {
			var ei, ej [12]Fp377
			ei[i] = one
			ej[j] = one
			if MulBLS12377Fp12Rank23U64(ei, ej) != RefMulBLS12377Fp12TowerU64(ei, ej) {
				t.Fatalf("E12 U64 basis mismatch at (%d, %d)", i, j)
			}
		}
	}
	var max12 [12]Fp377
	for k := 0; k < 12; k++ {
		max12[k] = maxElem
	}
	if MulBLS12377Fp12Rank23U64(max12, max12) != RefMulBLS12377Fp12TowerU64(max12, max12) {
		t.Fatalf("E12 U64 max(p-1) mismatch")
	}
	for s := 0; s < 1000; s++ {
		var a12, b12 [12]Fp377
		aBig := randVec(rng, 12, p377)
		bBig := randVec(rng, 12, p377)
		for k := 0; k < 12; k++ {
			a12[k] = Fp377FromBigInt(aBig[k])
			b12[k] = Fp377FromBigInt(bBig[k])
		}
		got12 := MulBLS12377Fp12Rank23U64(a12, b12)
		ref12U64 := RefMulBLS12377Fp12TowerU64(a12, b12)
		if got12 != ref12U64 {
			t.Fatalf("E12 U64 fuzz mismatch at sample %d", s)
		}
		ref12Big := RefMulBLS12377Fp12Tower(aBig, bBig, p377)
		for k := 0; k < 12; k++ {
			if got12[k].ToBigInt().Cmp(ref12Big[k]) != 0 {
				t.Fatalf("E12 U64 vs big.Int mismatch at sample %d coord %d", s, k)
			}
		}
	}
}
