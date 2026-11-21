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
	// 2. Adversarial maximal input (p-1, ..., p-1)
	mv := maxVec(d, p)
	assertSliceEq(t, name+" max(p-1)", dut(mv, mv), ref(mv, mv))

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
