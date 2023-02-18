package taat

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/TomCN0803/taat-lib/pkg/groth"
	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	bn "github.com/cloudflare/bn256"
	"github.com/jinzhu/copier"
)

var (
	ErrWrongGroupNymPK    = errors.New("wrong group of NymPK")
	ErrIncorrectCredProof = errors.New("incorrect credential proof")
)

// CredProof 关于 Credential 的证明
type CredProof struct {
	comm    *big.Int
	resSigs []*resSig
	resAttr [][]any
	resUPK  []any
	resUSK  *big.Int
	resNym  *big.Int
}

type resSig struct {
	rPrime any
	resS   any
	resT   []any
}

// NewCredProof 产生新的 CredProof
func NewCredProof(
	sp *Parameters, cred *Credential, usk, nymSK *big.Int, attrSet AttrSet, nonce []byte,
) (*CredProof, error) {
	const prefix = "failed to generate credential proof"
	level := len(cred.prevCreds)
	rhoSigmas := make([]*big.Int, level+1)
	randSigs := make([]*groth.Signature, level+1)
	rhoSs := make([]*big.Int, level+1)
	rhoTSs := make([][]*big.Int, level+1)
	rhoUPKs := make([]*big.Int, level+1)
	rhoAttrs := make([][]*big.Int, level+1)

	for i := 1; i <= level; i++ {
		c, err := cred.AtLevel(i)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix, err)
		}

		rho, err := rand.Int(rand.Reader, bn.Order)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix, err)
		}
		rhoSigmas[i] = rho

		sig := new(groth.Signature)
		err = copier.Copy(sig, c.sig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix, err)
		}
		sig.Randomize(rho)
		randSigs[i] = sig

		rhoSs[i], err = rand.Int(rand.Reader, bn.Order)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix, err)
		}
		rhoUPKs[i], err = rand.Int(rand.Reader, bn.Order)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix, err)
		}
		rhoTSs[i] = make([]*big.Int, len(c.attrs)+1)
		rhoAttrs[i] = make([]*big.Int, len(c.attrs))
		for j := range rhoTSs[i] {
			if j < len(c.attrs) {
				rhoAttrs[i][j], err = rand.Int(rand.Reader, bn.Order)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", prefix, err)
				}
			}
			rhoTSs[i][j], err = rand.Int(rand.Reader, bn.Order)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", prefix, err)
			}
		}
	}

	ec := newEComputer(level, level+1, sp.MaxAttrs+2)
	ec.run()
	for i := 1; i <= level; i++ {
		c, err := cred.AtLevel(i)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix, err)
		}

		g1, g2 := g1g2AtLevel(i)
		g1neg, _ := utils.Neg(g1)
		g2neg, _ := utils.Neg(g2)

		eas1 := []*eArg{newEArg(g1, c.sig.R(), utils.MulMod(rhoSigmas[i], rhoSs[i]))}
		eas2 := []*eArg{
			newEArg(g1, c.sig.R(), utils.MulMod(rhoSigmas[i], rhoTSs[i][0])),
			newEArg(g1, g2neg, rhoUPKs[i]),
		}
		if i != 1 {
			eas1 = append(eas1, newEArg(g1neg, g2, rhoUPKs[i-1]))
			eas2 = append(eas2, newEArg(yiAtLevel(sp, 0, i), g2, rhoUPKs[i-1]))
		}
		ec.enqueue(eas1, i, 0)
		ec.enqueue(eas2, i, 1)

		for j, rhoA := range rhoAttrs[i] {
			eas := []*eArg{newEArg(g1, c.sig.R(), utils.MulMod(rhoSigmas[i], rhoTSs[i][j+1]))}
			if i != 1 {
				eas = append(eas, newEArg(yiAtLevel(sp, j+1, i), g2, rhoUPKs[i-1]))
			}
			if attrSet.Get(i, j) == nil {
				eas = append(eas, newEArg(g1, g2neg, rhoA))
			}
			ec.enqueue(eas, i, j+2)
		}
	}
	cijs := ec.result()

	var cnym serializable
	rhoNym, err := rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", prefix, err)
	}
	if level%2 == 0 {
		cnym = utils.ProductOfExpG1(utils.G1Generator(), rhoUPKs[level], sp.H1, rhoNym)
	} else {
		cnym = utils.ProductOfExpG2(utils.G2Generator(), rhoUPKs[level], sp.H2, rhoNym)
	}

	rPrimes := make([]any, 0, len(randSigs))
	for _, sig := range randSigs {
		rPrimes = append(rPrimes, sig.R())
	}
	comm := new(big.Int).SetBytes(hashCredComm(sp.RootUPK, rPrimes, cijs, cnym, attrSet, nonce))

	resSigs := make([]*resSig, level+1)
	resUPK := make([]any, level+1)
	resAttr := make([][]any, level+1)
	for i := 1; i <= level; i++ {
		var g any
		if i%2 == 1 {
			g = utils.G1Generator()
		} else {
			g = utils.G2Generator()
		}

		c, err := cred.AtLevel(i)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix, err)
		}

		resSigs[i].resS = pexp(g, rhoSs[i], randSigs[i].S(), comm)
		resSigs[i].rPrime = rPrimes[i]
		if i != level {
			resUPK[i] = pexp(g, rhoUPKs[i], c.upk, comm)
		}

		resSigs[i].resT = make([]any, len(rhoTSs[i]))
		resAttr[i] = make([]any, len(rhoAttrs[i]))
		for j, rho := range rhoTSs[i] {
			resSigs[i].resT[j] = pexp(g, rho, randSigs[i].Ts()[j], comm)
			if j < len(rhoAttrs[i]) && attrSet.Get(i, j) == nil {
				resAttr[i][j] = pexp(g, rhoAttrs[i][j], c.attrs[j], comm)
			}
		}
	}

	resUSK := utils.AddMod(rhoUPKs[len(rhoUPKs)-1], utils.MulMod(comm, usk))
	resNym := utils.AddMod(rhoNym, utils.MulMod(comm, nymSK))

	return &CredProof{comm, resSigs, resAttr, resUPK, resUSK, resNym}, nil
}

// Verify verifies a CredProof.
func (cp *CredProof) Verify(sp *Parameters, attrSet AttrSet, nymPK *PK, nonce []byte) error {
	const prefix = "failed to verify credential proof"
	level := len(cp.resSigs)
	one := big.NewInt(1)
	cneg := utils.AddInv(cp.comm, bn.Order)

	ec := newEComputer(level, level+1, sp.MaxAttrs+2)
	ec.run()
	for i := 1; i <= level; i++ {
		g1, g2 := g1g2AtLevel(i)
		g1neg, _ := utils.Neg(g1)
		g2neg, _ := utils.Neg(g2)

		rsig := cp.resSigs[i]
		y0 := yiAtLevel(sp, 0, i)
		eas1 := []*eArg{
			newEArg(rsig.resS, rsig.rPrime, one),
			newEArg(y0, g2, cneg),
		}
		eas2 := []*eArg{newEArg(rsig.resT[0], rsig.rPrime, one)}
		if i == 1 {
			eas1 = append(eas1, newEArg(g1, sp.RootUPK, cneg))
			eas2 = append(eas2, newEArg(y0, sp.RootUPK, cneg))
		} else {
			eas1 = append(eas1, newEArg(g1neg, cp.resUPK[i], one))
			eas2 = append(eas2, newEArg(y0, cp.resUPK[i-1], one))
		}
		if i == level {
			eas2 = append(eas2, newEArg(g1, g2neg, cp.resUSK))
		} else {
			eas2 = append(eas2, newEArg(cp.resUPK[i], g2neg, one))
		}
		ec.enqueue(eas1, i, 0)
		ec.enqueue(eas2, i, 1)

		for j := range cp.resAttr[i] {
			eas := []*eArg{newEArg(rsig.resT[j+1], rsig.rPrime, one)}
			yj := yiAtLevel(sp, j+1, i)
			if i == 1 {
				eas = append(eas, newEArg(yj, sp.RootUPK, cneg))
			} else {
				eas = append(eas, newEArg(yj, cp.resUPK[i-1], one))
			}
			if attr := attrSet.Get(i, j); attr == nil {
				eas = append(eas, newEArg(cp.resAttr[i][j], g2neg, one))
			} else {
				eas = append(eas, newEArg(attr.Value(), g2, cneg))
			}
			ec.enqueue(eas, i, j+2)
		}
	}
	cijs := ec.result()

	var cnym serializable
	if level%2 == 0 {
		if !nymPK.inG1 {
			return fmt.Errorf("%s: %w", prefix, ErrWrongGroupNymPK)
		}
		cnym = utils.ProductOfExpG1(
			utils.ProductOfExpG1(utils.G1Generator(), cp.resUSK, sp.H1, cp.resNym),
			one,
			nymPK.pk.(*bn.G1),
			cneg,
		)
	} else {
		if nymPK.inG1 {
			return fmt.Errorf("%s: %w", prefix, ErrWrongGroupNymPK)
		}
		cnym = utils.ProductOfExpG2(
			utils.ProductOfExpG2(utils.G2Generator(), cp.resUSK, sp.H2, cp.resNym),
			one,
			nymPK.pk.(*bn.G2),
			cneg,
		)
	}

	rPrimes := make([]any, len(cp.resSigs))
	for i, rsig := range cp.resSigs {
		rPrimes[i] = rsig.rPrime
	}
	comm := hashCredComm(sp.RootUPK, rPrimes, cijs, cnym, attrSet, nonce)

	if !bytes.Equal(cp.comm.Bytes(), comm) {
		return fmt.Errorf("%s: %w", prefix, ErrIncorrectCredProof)
	}

	return nil
}

func hashCredComm(rootUPK *PK, rPrimes []any, cijs [][]*bn.GT, cnym serializable, attrSet AttrSet, m []byte) []byte {
	h := sha256.New()
	h.Write(rootUPK.Marshal())
	for _, v := range rPrimes {
		h.Write(v.(serializable).Marshal())
	}
	for _, c := range compactCijs(cijs) {
		h.Write(c.Marshal())
	}
	h.Write(cnym.Marshal())
	h.Write(attrSet.Marshal())
	h.Write(m)

	return h.Sum(nil)
}

func compactCijs(cijs [][]*bn.GT) []*bn.GT {
	res := make([]*bn.GT, 0)
	for _, row := range cijs {
		for _, c := range row {
			if c == nil {
				break
			}
			res = append(res, c)
		}
	}
	return res
}

func yiAtLevel(sp *Parameters, i, level int) (y any) {
	if level%2 == 1 {
		y = sp.Groth.Y1s[i]
	} else {
		y = sp.Groth.Y2s[i]
	}
	return
}

func g1g2AtLevel(i int) (g1 any, g2 any) {
	if i%2 == 1 {
		g1 = utils.G1Generator()
		g2 = utils.G2Generator()
	} else {
		g1 = utils.G2Generator()
		g2 = utils.G1Generator()
	}
	return
}

func pexp(g any, a *big.Int, h any, b *big.Int) any {
	if gv, ok := g.(*bn.G1); ok {
		return utils.ProductOfExpG1(gv, a, h.(*bn.G1), b)
	} else {
		return utils.ProductOfExpG2(g.(*bn.G2), a, h.(*bn.G2), b)
	}
}
