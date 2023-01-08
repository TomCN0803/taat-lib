package grouputils

import (
	"math/big"
	"testing"

	"github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

func TestEquals(t *testing.T) {
	testCases := []struct {
		name string
		a, b serializable
		ans  bool
	}{
		{
			"both a and b are in G1 and a == b",
			NewG1(big.NewInt(128)),
			NewG1(big.NewInt(128)),
			true,
		},
		{
			"both a and b are in G1 and a != b",
			NewG1(big.NewInt(128)),
			NewG1(big.NewInt(64)),
			false,
		},
		{
			"both a and b are in G2 and a == b",
			NewG2(big.NewInt(128)),
			NewG2(big.NewInt(128)),
			true,
		},
		{
			"both a and b are in G2 and a != b",
			NewG2(big.NewInt(128)),
			NewG2(big.NewInt(64)),
			false,
		},
		{
			"a in G1 and b in G2",
			NewG1(big.NewInt(128)),
			NewG2(big.NewInt(128)),
			false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.ans, Equals(tc.a, tc.b))
		})
	}
}

func TestScalarMult(t *testing.T) {
	t.Parallel()

	g1elem := new(bn256.G1).ScalarBaseMult(big.NewInt(128))
	g2elem := new(bn256.G2).ScalarBaseMult(big.NewInt(128))
	k := big.NewInt(10)

	testCases := []struct {
		name string
		a    any
		k    *big.Int
		ans  serializable
		err  error
	}{
		{
			"a in G1",
			g1elem,
			k,
			new(bn256.G1).ScalarMult(g1elem, k),
			nil,
		},
		{
			"a in G2",
			g2elem,
			k,
			new(bn256.G2).ScalarMult(g2elem, k),
			nil,
		},
		{
			"a neither in G1 nor G2",
			"invalid type",
			k,
			nil,
			ErrIllegalGroupType,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := ScalarMult(tc.a, tc.k)
			if tc.ans != nil {
				require.NoError(t, err)
				v, ok := res.(serializable)
				require.True(t, ok)
				require.True(t, Equals(v, tc.ans))
			} else {
				require.Nil(t, res)
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestScalarBaseMult(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		inG1 bool
		k    *big.Int
		ans  serializable
	}{
		{
			"in G1",
			true,
			big.NewInt(128),
			NewG1(big.NewInt(128)),
		},
		{
			"in G2",
			false,
			big.NewInt(128),
			NewG2(big.NewInt(128)),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.True(t, Equals(tc.ans, ScalarBaseMult(tc.inG1, tc.k).(serializable)))
		})
	}
}

func TestAdd(t *testing.T) {
	t.Parallel()

	g1a, g1b := new(bn256.G1).ScalarBaseMult(big.NewInt(128)), new(bn256.G1).ScalarBaseMult(big.NewInt(64))
	g2a, g2b := new(bn256.G2).ScalarBaseMult(big.NewInt(128)), new(bn256.G2).ScalarBaseMult(big.NewInt(64))
	g1ab := new(bn256.G1).Add(g1a, g1b)
	g2ab := new(bn256.G2).Add(g2a, g2b)

	testCases := []struct {
		name string
		a, b any
		ans  serializable
		err  error
	}{
		{
			"both a and b are in G1",
			g1a,
			g1b,
			g1ab,
			nil,
		},
		{
			"both a and b are in G2",
			g2a,
			g2b,
			g2ab,
			nil,
		},
		{
			"a in G1 and b in G2",
			g1a,
			g2b,
			nil,
			ErrInconsistentGroupType,
		},
		{
			"a or b neither in G1 nor G2",
			"invalid a",
			"invalid b",
			nil,
			ErrIllegalGroupType,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := Add(tc.a, tc.b)
			if tc.ans != nil {
				require.NoError(t, err)
				v, ok := res.(serializable)
				require.True(t, ok)
				require.True(t, Equals(v, tc.ans))
			} else {
				require.Nil(t, res)
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestPair(t *testing.T) {
	t.Parallel()

	g1 := NewG1(big.NewInt(128))
	g2 := NewG2(big.NewInt(128))

	testCases := []struct {
		name string
		a, b any
		ans  serializable
		err  error
	}{
		{
			"a in G1, b in G2",
			NewG1(big.NewInt(128)),
			NewG2(big.NewInt(128)),
			bn256.Pair(g1, g2),
			nil,
		},
		{
			"a in G2, b in G1",
			NewG2(big.NewInt(128)),
			NewG1(big.NewInt(128)),
			bn256.Pair(g1, g2),
			nil,
		},
		{
			"both a and b are in G1",
			g1,
			g1,
			nil,
			ErrSameGroupInPairing,
		},

		{
			"both a and b are in G2",
			g2,
			g2,
			nil,
			ErrSameGroupInPairing,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := Pair(tc.a, tc.b)
			if tc.ans != nil {
				require.NoError(t, err)
				require.True(t, Equals(res, tc.ans))
			} else {
				require.Nil(t, res)
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}
