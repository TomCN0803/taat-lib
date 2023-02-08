package groth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	bn "github.com/cloudflare/bn256"
)

var (
	ErrArgOverflow        = errors.New("wrong argument length supplied")
	ErrInconsistentArgLen = errors.New("inconsistent argument length")
	ErrFailedERSPredicate = errors.New("failed for e(r, s) predicate")
	ErrFailedMsgPredicate = errors.New("failed for message predicate")
)

// Signature Groth签名
type Signature struct {
	STG1 bool // indicates whether s and ts are in G1
	r    any
	s    any
	ts   []any
}

// Parameters Groth公共参数
type Parameters struct {
	Y1s []*bn.G1
	Y2s []*bn.G2
}

// PK Groth签名公钥，pk1 == g1^sk，pk2 == g2^sk
type PK struct {
	pk1 *bn.G1
	pk2 *bn.G2
}

// Setup 初始化在Groth签名
func Setup(max1, max2 int) *Parameters {
	y1s := make([]*bn.G1, max1)
	for i := range y1s {
		_, y1s[i], _ = bn.RandomG1(rand.Reader)
	}
	y2s := make([]*bn.G2, max2)
	for i := range y2s {
		_, y2s[i], _ = bn.RandomG2(rand.Reader)
	}

	return &Parameters{y1s, y2s}
}

// GenKeyPair 产生Groth公私钥对
func GenKeyPair() (sk *big.Int, pk *PK) {
	sk, _ = rand.Int(rand.Reader, bn.Order)
	pk = &PK{
		pk1: new(bn.G1).ScalarBaseMult(sk),
		pk2: new(bn.G2).ScalarBaseMult(sk),
	}

	return
}

// NewSignature 产生Groth签名
func NewSignature(sp *Parameters, sk *big.Int, m *Message) *Signature {
	rho, _ := rand.Int(rand.Reader, bn.Order)
	rhoInv := new(big.Int).ModInverse(rho, bn.Order)

	sig := &Signature{
		STG1: m.InG1,
		ts:   make([]any, len(m.ms)),
	}
	if m.InG1 {
		sig.r = new(bn.G2).ScalarBaseMult(rho)
		s := new(bn.G1).Add(sp.Y1s[0], new(bn.G1).ScalarBaseMult(sk))
		sig.s = s.ScalarMult(s, rhoInv)
		for i := range sig.ts {
			t := new(bn.G1).Add(m.ms[i].(*bn.G1), new(bn.G1).ScalarMult(sp.Y1s[i], sk))
			sig.ts[i] = t.ScalarMult(t, rhoInv)
		}
	} else {
		sig.r = new(bn.G1).ScalarBaseMult(rho)
		s := new(bn.G2).Add(sp.Y2s[0], new(bn.G2).ScalarBaseMult(sk))
		sig.s = s.ScalarMult(s, rhoInv)
		for i := range sig.ts {
			t := new(bn.G2).Add(m.ms[i].(*bn.G2), new(bn.G2).ScalarMult(sp.Y2s[i], sk))
			sig.ts[i] = t.ScalarMult(t, rhoInv)
		}
	}

	return sig
}

// Verify 验证groth签名
func (sig *Signature) Verify(sp *Parameters, pk *PK, m *Message) error {
	const prefix = "failed to verify groth signature"
	ny1, ny2 := len(sp.Y1s), len(sp.Y2s)
	if sig.STG1 && (len(m.ms) > ny1 || len(sig.ts) > ny1) {
		return fmt.Errorf("%s: %w, at most %d", prefix, ErrArgOverflow, ny1)
	}
	if !sig.STG1 && (len(m.ms) > ny2 || len(sig.ts) > ny2) {
		return fmt.Errorf("%s: %w, at most %d", prefix, ErrArgOverflow, ny2)
	}
	if len(m.ms) != len(sig.ts) {
		return fmt.Errorf(
			"%s: %w, m(%d) must be equal to ts(%d)",
			prefix,
			ErrInconsistentArgLen,
			len(m.ms),
			len(sig.ts),
		)
	}

	var err error
	o := sync.Once{}
	wg := sync.WaitGroup{}
	efn := func(i int, g1a, g1b, g1c *bn.G1, g2a, g2b, g2c *bn.G2) {
		defer wg.Done()
		elhs := bn.Pair(g1a, g2a)
		erhs := new(bn.GT).Add(bn.Miller(g1b, g2b), bn.Miller(g1c, g2c)).Finalize()
		if !utils.Equals(elhs, erhs) {
			o.Do(func() {
				if i < len(m.ms) {
					err = fmt.Errorf("%s: %w, at index %d", prefix, ErrFailedMsgPredicate, i)
				} else {
					err = fmt.Errorf("%s: %w", prefix, ErrFailedERSPredicate)
				}
			})
		}
	}

	g1 := new(bn.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn.G2).ScalarBaseMult(big.NewInt(1))
	for i := 0; i < len(m.ms)+1; i++ {
		var g1a, g1b, g1c *bn.G1
		var g2a, g2b, g2c *bn.G2
		if i < len(m.ms) {
			if sig.STG1 {
				g1a, g1b, g1c = sig.ts[i].(*bn.G1), sp.Y1s[i], m.ms[i].(*bn.G1)
				g2a, g2b, g2c = sig.r.(*bn.G2), pk.pk2, g2
			} else {
				g1a, g1b, g1c = sig.r.(*bn.G1), pk.pk1, g1
				g2a, g2b, g2c = sig.ts[i].(*bn.G2), sp.Y2s[i], m.ms[i].(*bn.G2)
			}
		} else {
			if sig.STG1 {
				g1a, g1b, g1c = sig.s.(*bn.G1), sp.Y1s[0], g1
				g2a, g2b, g2c = sig.r.(*bn.G2), g2, pk.pk2
			} else {
				g1a, g1b, g1c = sig.r.(*bn.G1), g1, pk.pk1
				g2a, g2b, g2c = sig.s.(*bn.G2), sp.Y2s[0], g2
			}
		}

		wg.Add(1)
		go efn(i, g1a, g1b, g1c, g2a, g2b, g2c)
	}

	return err
}

// Randomize randomizes sig with rho if rho is provided or a random big int.
func (sig *Signature) Randomize(rho *big.Int) {
	if rho == nil {
		rho, _ = rand.Int(rand.Reader, bn.Order)
	}
	rhoInv := new(big.Int).ModInverse(rho, bn.Order)
	if sig.STG1 {
		r := sig.r.(*bn.G2)
		r.ScalarMult(r, rho)
		s := sig.s.(*bn.G1)
		s.ScalarMult(s, rhoInv)
		for i := range sig.ts {
			ti := sig.ts[i].(*bn.G1)
			ti.ScalarMult(ti, rhoInv)
		}
	} else {
		r := sig.r.(*bn.G1)
		r.ScalarMult(r, rho)
		s := sig.s.(*bn.G2)
		s.ScalarMult(s, rhoInv)
		for i := range sig.ts {
			ti := sig.ts[i].(*bn.G2)
			ti.ScalarMult(ti, rhoInv)
		}
	}
}
