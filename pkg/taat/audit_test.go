package taat

import (
	"crypto/rand"
	"math/big"
	"testing"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	"github.com/TomCN0803/taat-lib/pkg/ttbe"
	bn "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

func TestAudit(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		inG1     bool
		params   *audParams
		proveErr error
		verErr   error
	}{
		{
			"happy path in G1",
			true,
			newAudParams(true),
			nil,
			nil,
		},
		{
			"happy path in G2",
			false,
			newAudParams(false),
			nil,
			nil,
		},
		{
			"prove fail",
			true,
			newAudParams(true),
			ErrCttbeAndPKsNotInSameGroup,
			nil,
		},
		{
			"verify fail - not in same group",
			true,
			newAudParams(true),
			nil,
			ErrCttbeAndPKsNotInSameGroup,
		},
		{
			"verify fail - incorrect audit proof in G1",
			true,
			newAudParams(true),
			nil,
			ErrIncorrectAuditProof,
		},
		{
			"verify fail - incorrect audit proof in G2",
			false,
			newAudParams(false),
			nil,
			ErrIncorrectAuditProof,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.proveErr == ErrCttbeAndPKsNotInSameGroup {
				tc.params.cttbe.InG1 = !tc.params.cttbe.InG1
			}
			proof, err := NewAuditProof(
				tc.params.tpk,
				tc.params.cttbe,
				tc.params.r1,
				tc.params.r2,
				tc.params.usk,
				tc.params.nymSK,
				tc.params.nymPK,
				tc.params.h,
			)
			if tc.proveErr != nil {
				require.ErrorIs(t, err, tc.proveErr)
				require.Nil(t, proof)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, proof)

			if tc.verErr == ErrCttbeAndPKsNotInSameGroup {
				tc.params.nymPK.inG1 = !tc.params.cttbe.InG1
			} else if tc.verErr == ErrIncorrectAuditProof {
				proof.p3, _ = rand.Int(rand.Reader, bn.Order)
			}
			err = proof.Verify(
				tc.params.cttbe,
				tc.params.tpk,
				tc.params.nymPK,
				tc.params.h,
			)
			if tc.verErr != nil {
				require.ErrorIs(t, err, tc.verErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type audParams struct {
	tpk        *ttbe.TPK
	cttbe      *ttbe.Cttbe
	r1, r2     *big.Int
	usk, nymSK *big.Int
	nymPK      *NymPK
	h          any
}

func newAudParams(inG1 bool) *audParams {
	r1, _ := rand.Int(rand.Reader, bn.Order)
	r2, _ := rand.Int(rand.Reader, bn.Order)
	usk, _ := rand.Int(rand.Reader, bn.Order)
	nymSK, _ := rand.Int(rand.Reader, bn.Order)
	r := utils.AddMod(r1, r2)

	params := &audParams{
		r1:    r1,
		r2:    r2,
		usk:   usk,
		nymSK: nymSK,
	}

	_, u1, _ := bn.RandomG1(rand.Reader)
	_, u2, _ := bn.RandomG2(rand.Reader)
	params.tpk = &ttbe.TPK{U1: u1, U2: u2}

	var h any
	var nymPK *NymPK
	var cttbe *ttbe.Cttbe
	rint, _ := rand.Int(rand.Reader, bn.Order)
	if inG1 {
		_, h, _ = bn.RandomG1(rand.Reader)
		upk := new(bn.G1).ScalarBaseMult(usk)
		nymPK = &NymPK{
			inG1: true,
			pk:   new(bn.G1).Add(upk, new(bn.G1).ScalarMult(h.(*bn.G1), nymSK)),
		}
		cttbe = &ttbe.Cttbe{
			InG1: true,
			C1:   utils.NewG1(rint),
			C2:   utils.NewG1(rint),
			C3:   new(bn.G1).Add(upk, new(bn.G1).ScalarMult(params.tpk.U1, r)),
			C4:   utils.NewG1(rint),
			C5:   utils.NewG1(rint),
			C6:   new(bn.G1).ScalarBaseMult(r),
		}
	} else {
		_, h, _ = bn.RandomG2(rand.Reader)
		upk := new(bn.G2).ScalarBaseMult(usk)
		nymPK = &NymPK{
			inG1: false,
			pk:   new(bn.G2).Add(upk, new(bn.G2).ScalarMult(h.(*bn.G2), nymSK)),
		}
		cttbe = &ttbe.Cttbe{
			InG1: false,
			C1:   utils.NewG2(rint),
			C2:   utils.NewG2(rint),
			C3:   new(bn.G2).Add(upk, new(bn.G2).ScalarMult(params.tpk.U2, r)),
			C4:   utils.NewG2(rint),
			C5:   utils.NewG2(rint),
			C6:   new(bn.G2).ScalarBaseMult(r),
		}
	}

	params.h = h
	params.nymPK = nymPK
	params.cttbe = cttbe

	return params
}
