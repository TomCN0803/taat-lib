package taat

import (
	"crypto/rand"
	"testing"

	"github.com/TomCN0803/taat-lib/pkg/groth"
	bn "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

func TestCredentialDelegation(t *testing.T) {
	t.Parallel()

	const msize = 10
	gsp, err := groth.Setup(msize+1, msize+1)
	require.NoError(t, err)
	sp := &Parameters{Groth: gsp}

	rootSK, rootPK := NewUserKeyPair(0)
	rootCred := NewRootCredential(rootPK)

	preCred, preSK := rootCred, rootSK
	for i := 1; i < 4; i++ {
		usk, upk := NewUserKeyPair(i)
		attrs := randNAttrs(msize)
		cred, err := preCred.Delegate(sp, preSK, upk, attrs)
		require.NoError(t, err)
		err = cred.Verify(sp, i, usk, rootPK)
		require.NoError(t, err)
		preCred = cred
	}
}

func randNAttrs(n int) []*Attribute {
	res := make([]*Attribute, n)
	for i := range res {
		k, _ := rand.Int(rand.Reader, bn.Order)
		res[i] = &Attribute{
			new(bn.G1).ScalarBaseMult(k),
			new(bn.G2).ScalarBaseMult(k),
		}
	}

	return res
}
