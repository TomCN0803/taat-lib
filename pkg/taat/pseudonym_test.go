package taat

import (
	"crypto/rand"
	"math/big"
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
			var npk *NymPK
			if tc.inG1 {
				_, a, err := bn.RandomG1(rand.Reader)
				require.NoError(t, err)
				npk = &NymPK{true, a}
			} else {
				_, a, err := bn.RandomG2(rand.Reader)
				require.NoError(t, err)
				npk = &NymPK{false, a}
			}
			npk2 := new(NymPK)
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

func TestPseudonymSignature(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		inG1   bool
		verErr error
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
			"illegal h in G1",
			true,
			ErrWrongHType,
		},
		{
			"inconsistent h and nymPK in G1",
			true,
			ErrInconsistentHAndNymPK,
		},
		{
			"inconsistent h and nymPK in G2",
			false,
			ErrInconsistentHAndNymPK,
		},
		{
			"incorrect nymSig in G1",
			true,
			ErrIncorrectNymSig,
		},
		{
			"incorrect nymSig in G2",
			false,
			ErrIncorrectNymSig,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			usk, err := rand.Int(rand.Reader, bn.Order)
			require.NoError(t, err)
			var h any
			var nymSK *big.Int
			var nymPK *NymPK
			if tc.inG1 {
				_, h, _ = bn.RandomG1(rand.Reader)
			} else {
				_, h, _ = bn.RandomG2(rand.Reader)
			}
			nymSK, nymPK, err = NewNymKeyPair(usk, h)
			require.NoError(t, err)
			require.NotNil(t, nymSK)
			require.NotNil(t, nymPK)
			require.Equal(t, tc.inG1, nymPK.inG1)

			// 生成随机的128B大小消息msg
			msg := make([]byte, 128)
			_, err = rand.Read(msg)
			require.NoError(t, err)

			nymSig, err := NewNymSignature(usk, nymSK, nymPK, h, msg)
			require.NoError(t, err)
			switch tc.verErr {
			case ErrWrongHType:
				h = "illegal h"
			case ErrInconsistentHAndNymPK:
				nymPK.inG1 = !nymPK.inG1
			case ErrIncorrectNymSig:
				nymSig.pUSK, err = rand.Int(rand.Reader, bn.Order)
				require.NoError(t, err)
			}
			err = nymSig.Verify(nymPK, h, msg)
			if tc.verErr != nil {
				require.ErrorIs(t, err, tc.verErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewNymKeyPairWrongHType(t *testing.T) {
	t.Parallel()
	h := "illegal h"
	usk, err := rand.Int(rand.Reader, bn.Order)
	require.NoError(t, err)
	nymSK, nymPK, err := NewNymKeyPair(usk, h)
	require.ErrorIs(t, err, ErrWrongHType)
	require.Nil(t, nymSK)
	require.Nil(t, nymPK)
}
