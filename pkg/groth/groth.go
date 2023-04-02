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
	ErrIllegalMaxMessageNum = errors.New("illegal max message number, must greater than 0")
	ErrArgOverflow          = errors.New("wrong argument length supplied")
	ErrInconsistentArgLen   = errors.New("inconsistent argument length")
	ErrFailedERSPredicate   = errors.New("failed for e(r, s) predicate")
	ErrFailedMsgPredicate   = errors.New("failed for message predicate")
)

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

// G1 返回在g1的pk
func (pk *PK) G1() *bn.G1 {
	return pk.pk1
}

// G2 返回在g2的pk
func (pk *PK) G2() *bn.G2 {
	return pk.pk2
}

// NewGrothPK 生成新的groth公钥
func NewGrothPK(pk1 *bn.G1, pk2 *bn.G2) *PK {
	return &PK{pk1, pk2}
}

// Setup 初始化Groth签名
func Setup(max1, max2 int) (*Parameters, error) {
	if max1 <= 0 || max2 <= 0 {
		return nil, fmt.Errorf("failed to set up groth: %w", ErrIllegalMaxMessageNum)
	}
	y1s := make([]*bn.G1, max1)
	for i := range y1s {
		_, y1s[i], _ = bn.RandomG1(rand.Reader)
	}
	y2s := make([]*bn.G2, max2)
	for i := range y2s {
		_, y2s[i], _ = bn.RandomG2(rand.Reader)
	}

	return &Parameters{y1s, y2s}, nil
}

// GenKeyPair 产生Groth公私钥对
// 如果提供了私钥即isk不为空，则使用isk为私钥，否则随机生成私钥
func GenKeyPair(isk *big.Int) (sk *big.Int, pk *PK) {
	sk = isk
	if sk == nil {
		sk, _ = rand.Int(rand.Reader, bn.Order)
	}
	pk = &PK{
		pk1: new(bn.G1).ScalarBaseMult(sk),
		pk2: new(bn.G2).ScalarBaseMult(sk),
	}

	return
}

// Signature Groth签名
type Signature struct {
	STG1 bool // indicates whether s and ts are in G1
	r    any
	s    any
	ts   []any
}

func (sig *Signature) R() any {
	return sig.r
}

func (sig *Signature) S() any {
	return sig.s
}

func (sig *Signature) Ts() []any {
	return sig.ts
}

func (sig *Signature) Copy() *Signature {
	res := &Signature{STG1: sig.STG1}
	res.r, _ = utils.Copy(sig.r)
	res.s, _ = utils.Copy(sig.s)
	res.ts = make([]any, len(sig.ts))
	for i := range res.ts {
		res.ts[i], _ = utils.Copy(sig.ts[i])
	}

	return res
}

// NewSignature 产生Groth签名
func NewSignature(sp *Parameters, sk *big.Int, m *Message) (*Signature, error) {
	ny1, ny2 := len(sp.Y1s), len(sp.Y2s)
	ny := -1
	if m.InG1 && m.Len() > ny1 {
		ny = ny1
	} else if !m.InG1 && m.Len() > ny2 {
		ny = ny2
	}
	if ny != -1 {
		return nil, fmt.Errorf(
			"failed to generate new groth signature: %w, message length at most %d, got %d instead",
			ErrArgOverflow,
			ny,
			m.Len(),
		)
	}

	rho, _ := rand.Int(rand.Reader, bn.Order)
	rhoInv := new(big.Int).ModInverse(rho, bn.Order)

	sig := &Signature{
		STG1: m.InG1,
		ts:   make([]any, m.Len()),
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

	return sig, nil
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

	wg.Wait()

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
