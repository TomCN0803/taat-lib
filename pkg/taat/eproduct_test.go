package taat

import (
	"crypto/rand"
	"math/big"
	"testing"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	bn "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

const numEArgs = 100

func BenchmarkEProdNoOpt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		args := randEArgs(numEArgs)
		b.StartTimer()
		eProductNoOpt(args)
	}
}

func BenchmarkEProdOptMiller(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		args := randEArgs(numEArgs)
		b.StartTimer()
		eProduct(args, eProdOptMiller)
	}
}

func BenchmarkEProdOptMillerLoopUnroll(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		args := randEArgs(numEArgs)
		b.StartTimer()
		eProduct(args, eProdOptMillerLoopUnroll)
	}
}

func TestEProduct(t *testing.T) {
	t.Parallel()
	args := randEArgs(100)
	require.True(t, utils.Equals(eProduct(args, eProdOptMiller), eProductNoOpt(args)))
	require.True(t, utils.Equals(eProduct(args, eProdOptMillerLoopUnroll), eProductNoOpt(args)))
}

func randEArgs(n int) []*eArg {
	res := make([]*eArg, n)
	for i := range res {
		_, g1, _ := bn.RandomG1(rand.Reader)
		_, g2, _ := bn.RandomG2(rand.Reader)
		c, _ := rand.Int(rand.Reader, bn.Order)
		res[i] = &eArg{g1, g2, c}
	}

	return res
}

func eProductNoOpt(args []*eArg) *bn.GT {
	res := new(bn.GT).ScalarBaseMult(big.NewInt(0))
	for _, arg := range args {
		bk := new(bn.GT).ScalarMult(bn.Pair(arg.a, arg.b), arg.c)
		res.Add(res, bk)
	}
	return res
}