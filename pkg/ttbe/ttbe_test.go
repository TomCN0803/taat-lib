package ttbe

import (
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"testing"
	"time"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	"github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

func TestSetup(t *testing.T) {
	t.Parallel()
	params, err := Setup(10, 5)
	require.NoError(t, err)
	require.NotNil(t, params)
}

func TestTTBEHappyPath(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		inG1        bool
		numAuditors int
		threshold   int
		numClues    int
	}{
		{
			"test case msg in G1",
			true,
			5,
			3,
			3,
		},
		{
			"test case msg in G2",
			false,
			5,
			3,
			3,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// setup TTBE
			params, err := Setup(uint64(tc.numAuditors), uint64(tc.threshold))
			require.NoError(t, err)
			require.NotNil(t, params)
			require.Len(t, params.TSKs, tc.numAuditors)
			require.Len(t, params.TVKs, tc.numAuditors)

			// generate a random message
			var msg any
			if tc.inG1 {
				_, msg, err = bn256.RandomG1(rand.Reader)
			} else {
				_, msg, err = bn256.RandomG2(rand.Reader)
			}
			require.NoError(t, err)
			require.NotNil(t, msg)

			// generate a random tag
			tag, err := rand.Int(rand.Reader, bn256.Order)
			require.NoError(t, err)

			// encrypt the message
			cttbe, _, _, err := Encrypt(params.TPK, tag, msg)
			require.NoError(t, err)
			require.NotNil(t, cttbe)

			// verify ciphertext
			require.True(t, IsValidEnc(params.TPK, tag, cttbe))

			// generate audit clues, and corresponding tvks
			audIdxs, err := randIntsNoRepeat(tc.numAuditors, tc.numClues)
			require.NoError(t, err)
			require.Len(t, audIdxs, tc.numClues)
			auditClues := make([]*AudClue, tc.numClues)
			tvks := make([]*TVK, tc.numClues)
			for i, ai := range audIdxs {
				auditClues[i], err = ShareAudClue(params.TPK, tag, cttbe, params.TSKs[ai])
				require.NoError(t, err)
				tvks[i] = params.TVKs[ai]
				examineShareAudClueCorrectness(t, params.TSKs[ai], auditClues[i], cttbe)
				require.True(t, IsValidAudClue(params.TPK, tag, cttbe, tvks[i], auditClues[i]))
			}

			// combine and get the plaintext result
			res, err := Combine(params.TPK, tag, cttbe, tvks, auditClues)
			require.NoError(t, err)
			require.NotNil(t, res)
			if tc.inG1 {
				require.True(t, utils.Equals(msg.(*bn256.G1), res.(*bn256.G1)))
			} else {
				require.True(t, utils.Equals(msg.(*bn256.G2), res.(*bn256.G2)))
			}
		})
	}
}

func examineShareAudClueCorrectness(t *testing.T, tsk *TSK, clue *AudClue, cttbe *Cttbe) {
	require.NotNil(t, clue)
	require.Equal(t, cttbe.InG1, clue.inG1)
	if clue.inG1 {
		ac1, ok := clue.ac1.(*bn256.G1)
		require.True(t, ok)
		ac2, ok := clue.ac2.(*bn256.G1)
		require.True(t, ok)
		c1, ok := cttbe.C1.(*bn256.G1)
		require.True(t, ok)
		c2, ok := cttbe.C2.(*bn256.G1)
		require.True(t, ok)

		require.True(t, utils.Equals(ac1, new(bn256.G1).ScalarMult(c1, tsk.u)))
		require.True(t, utils.Equals(ac2, new(bn256.G1).ScalarMult(c2, tsk.v)))
	} else {
		ac1, ok := clue.ac1.(*bn256.G2)
		require.True(t, ok)
		ac2, ok := clue.ac2.(*bn256.G2)
		require.True(t, ok)
		c1, ok := cttbe.C1.(*bn256.G2)
		require.True(t, ok)
		c2, ok := cttbe.C2.(*bn256.G2)
		require.True(t, ok)

		require.True(t, utils.Equals(ac1, new(bn256.G2).ScalarMult(c1, tsk.u)))
		require.True(t, utils.Equals(ac2, new(bn256.G2).ScalarMult(c2, tsk.v)))
	}
}

// randIntsNoRepeat 从[0,n)生成k个不重复的随机数
func randIntsNoRepeat(n, k int) ([]int, error) {
	if k > n {
		return nil, errors.New("k is larger than n")
	}

	mrand.Seed(time.Now().UnixNano())
	m := make(map[int]struct{})
	for len(m) < k {
		m[mrand.Intn(n)] = struct{}{}
	}

	res := make([]int, 0, k)
	for v := range m {
		res = append(res, v)
	}

	return res, nil
}
