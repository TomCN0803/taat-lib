package taat

import (
	"crypto/rand"
	"log"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/TomCN0803/taat-lib/pkg/groth"
	bn "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

func TestCredProof(t *testing.T) {
	t.Parallel()

	const level = 3
	creds := make([]*Credential, level+1)
	usks := make([]*big.Int, level+1)
	upks := make([]*PK, level+1)
	nymSKs := make([]*big.Int, level+1)
	nymPKs := make([]*PK, level+1)
	attrs := make([][]*Attribute, level+1)
	attrSets := make([]AttrSet, level+1)
	usks[0], upks[0] = NewUserKeyPair(0)
	creds[0] = NewRootCredential(upks[0])
	nonce := make([]byte, 256)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	const msize = 3
	gsp, err := groth.Setup(msize+1, msize+1)
	require.NoError(t, err)
	_, h1, _ := bn.RandomG1(rand.Reader)
	_, h2, _ := bn.RandomG2(rand.Reader)
	sp := &Parameters{
		H1:       h1,
		H2:       h2,
		MaxAttrs: msize,
		Groth:    gsp,
		RootUPK:  upks[0],
	}

	proofs := make([]*CredProof, level+1)
	for i := 1; i <= level; i++ {
		usks[i], upks[i] = NewUserKeyPair(i)
		if i%2 == 0 {
			nymSKs[i], nymPKs[i], err = NewNymKeyPair(usks[i], sp.H1)
			require.NoError(t, err)
		} else {
			nymSKs[i], nymPKs[i], err = NewNymKeyPair(usks[i], sp.H2)
			require.NoError(t, err)
		}
		attrs[i] = randNAttrs(sp.MaxAttrs)
		attrSets[i] = randAttrSet(attrs, i, sp.MaxAttrs)
		creds[i], err = creds[i-1].Delegate(sp, usks[i-1], upks[i], attrs[i])
		require.NoError(t, err)
		if i == 3 {
			log.Println("********************************************")
			log.Println("********************************************")
			log.Println("********************************************")
			proofs[i], err = NewCredProof(sp, creds[i], usks[i], nymSKs[i], attrSets[i], nonce)
			require.NoError(t, err)
			log.Println("=============================")
			err = proofs[i].Verify(sp, attrSets[i], nymPKs[i], nonce)
			require.NoError(t, err)
		}
	}
}

func randAttrSet(attrs [][]*Attribute, level, maxAttrs int) AttrSet {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	n := rng.Intn(level * maxAttrs)
	as := make(AttrSet, 0, n)
	for i := 0; i < n; i++ {
		lvl := rng.Intn(level) + 1
		j := rng.Intn(maxAttrs)
		as = append(as, &AttrSetElem{lvl, j, attrs[lvl][j]})
	}
	return as
}
