package taat

import (
	"crypto/rand"
	"testing"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	bn "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

func TestNymPKSerialize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		inG1 bool
	}{
		{
			"in G1",
			true,
		},
		{
			"in G2",
			false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var npk *PK
			if tc.inG1 {
				_, a, err := bn.RandomG1(rand.Reader)
				require.NoError(t, err)
				npk = &PK{true, a}
			} else {
				_, a, err := bn.RandomG2(rand.Reader)
				require.NoError(t, err)
				npk = &PK{false, a}
			}
			npk2 := new(PK)
			err := npk2.Unmarshal(npk.Marshal())
			require.NoError(t, err)
			require.Equal(t, npk.inG1, npk2.inG1)
			if tc.inG1 {
				require.True(t, utils.Equals(npk.pk.(*bn.G1), npk2.pk.(*bn.G1)))
			} else {
				require.True(t, utils.Equals(npk.pk.(*bn.G2), npk2.pk.(*bn.G2)))
			}
		})
	}
}

func TestUskProof(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		inG1 bool
		err  error
	}{
		{
			"happy path in G1",
			true,
			nil,
		},
		{
			"happy path in G2",
			false,
			nil,
		},
		{
			"incorrect proof in G1",
			true,
			ErrIncorrectUSKProof,
		},
		{
			"incorrect proof in G2",
			false,
			ErrIncorrectUSKProof,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nonce := make([]byte, 128)
			_, err := rand.Read(nonce)
			require.NoError(t, err)
			usk, err := rand.Int(rand.Reader, bn.Order)
			require.NoError(t, err)
			upk := new(PK)
			if tc.inG1 {
				upk.inG1 = true
				upk.pk = utils.NewG1(usk)
			} else {
				upk.inG1 = false
				upk.pk = utils.NewG2(usk)
			}

			proof, err := NewUSKProof(usk, upk, nonce)
			require.NoError(t, err)

			if tc.err != nil {
				proof.p, err = rand.Int(rand.Reader, bn.Order)
			}
			err = proof.Verify(upk, nonce)
			if tc.err != nil {
				require.ErrorIs(t, err, ErrIncorrectUSKProof)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
