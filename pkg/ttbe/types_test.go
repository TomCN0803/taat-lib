package ttbe

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	bn "golang.org/x/crypto/bn256"
)

func TestCttbeSerialize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		cttbe *Cttbe
		err   error
	}{
		{
			"Cttbe in G1",
			mockRandomCttbe(true),
			nil,
		},
		{
			"Cttbe in G2",
			mockRandomCttbe(false),
			nil,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := tc.cttbe.Marshal()
			c := new(Cttbe)
			err := c.Unmarshal(b)
			require.NoError(t, err)
			require.True(t, c.Equals(tc.cttbe))
		})
	}
}

func mockRandomCttbe(inG1 bool) *Cttbe {
	if inG1 {
		es := randomKG1Elems(6)
		return &Cttbe{
			InG1: true,
			C1:   es[0],
			C2:   es[1],
			C3:   es[2],
			C4:   es[3],
			C5:   es[4],
			C6:   es[5],
		}
	} else {
		es := randomKG2Elems(6)
		return &Cttbe{
			InG1: false,
			C1:   es[0],
			C2:   es[1],
			C3:   es[2],
			C4:   es[3],
			C5:   es[4],
			C6:   es[5],
		}
	}
}

func randomKG1Elems(k int) []*bn.G1 {
	res := make([]*bn.G1, 0, k)
	for i := 0; i < k; i++ {
		_, e, _ := bn.RandomG1(rand.Reader)
		res = append(res, e)
	}

	return res
}

func randomKG2Elems(k int) []*bn.G2 {
	res := make([]*bn.G2, 0, k)
	for i := 0; i < k; i++ {
		_, e, _ := bn.RandomG2(rand.Reader)
		res = append(res, e)
	}

	return res
}
