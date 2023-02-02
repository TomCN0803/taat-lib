package groth

import (
	"crypto/rand"
	"testing"

	bn "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

func TestNewMessage(t *testing.T) {
	t.Parallel()
	_, g1a, _ := bn.RandomG1(rand.Reader)
	_, g1b, _ := bn.RandomG1(rand.Reader)
	_, g1c, _ := bn.RandomG1(rand.Reader)
	_, g2a, _ := bn.RandomG2(rand.Reader)
	_, g2b, _ := bn.RandomG2(rand.Reader)
	_, g2c, _ := bn.RandomG2(rand.Reader)
	testCases := []struct {
		name string
		ms   []any
		err  error
	}{
		{
			"happy path of G1",
			[]any{g1a, g1b},
			nil,
		},
		{
			"happy path of G2",
			[]any{g2a, g2b},
			nil,
		},
		{
			"empty ms",
			[]any{},
			ErrEmptyMsg,
		},
		{
			"illegal message type",
			[]any{"illegal"},
			ErrIllegalMsgType,
		},
		{
			"inconsistent message type",
			[]any{g1c, g2c},
			ErrInconsistentMsgType,
		},
	}

	for i, tc := range testCases {
		i, tc := i, tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg, err := NewMessage(tc.ms)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.Nil(t, msg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, msg)
				require.Equal(t, i == 0, msg.InG1)
			}
		})
	}
}
