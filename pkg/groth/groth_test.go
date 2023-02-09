package groth_test

import (
	"crypto/rand"
	"testing"

	"github.com/TomCN0803/taat-lib/pkg/groth"
	bn "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

const (
	n2    = 100
	n1    = 100
	msize = 100
)

func TestGroth(t *testing.T) {
	t.Parallel()

	sp := groth.Setup(n1, n2)
	sk, pk := groth.GenKeyPair(nil)
	testCases := []struct {
		name string
	}{
		{
			"happy path in G1",
		},
		{
			"happy path in G2",
		},
	}

	for i, tc := range testCases {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inG1 := i == 0
			var m []any
			if inG1 {
				m = randnG1s(msize)
			} else {
				m = randnG2s(msize)
			}
			msg, err := groth.NewMessage(m)
			require.NoError(t, err)
			sig := groth.NewSignature(sp, sk, msg)
			require.NoError(t, sig.Verify(sp, pk, msg))
			sig.Randomize(nil)
			require.NoError(t, sig.Verify(sp, pk, msg))
			rho, _ := rand.Int(rand.Reader, bn.Order)
			sig.Randomize(rho)
			require.NoError(t, sig.Verify(sp, pk, msg))
		})
	}

}

func randnG1s(n int) []any {
	res := make([]any, n)
	for i := range res {
		_, res[i], _ = bn.RandomG1(rand.Reader)
	}

	return res
}

func randnG2s(n int) []any {
	res := make([]any, n)
	for i := range res {
		_, res[i], _ = bn.RandomG2(rand.Reader)
	}

	return res
}
