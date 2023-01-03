package ttbe

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bn256"
)

func TestSetup(t *testing.T) {
	t.Parallel()
	params, err := Setup(10, 5)
	require.NoError(t, err)
	require.NotNil(t, params)
}

func TestSetupWithInitHPair(t *testing.T) {
	t.Parallel()
	_, h1, _ := bn256.RandomG1(rand.Reader)
	_, h2, _ := bn256.RandomG2(rand.Reader)
	SetHPair(h1, h2)

	params, err := Setup(10, 5)
	require.NoError(t, err)
	require.NotNil(t, params)
	require.Equal(t, h1, params.TPK.H1)
	require.Equal(t, h2, params.TPK.H2)
}
