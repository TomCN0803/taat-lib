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
