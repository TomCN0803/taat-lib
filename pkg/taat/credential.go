package taat

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/TomCN0803/taat-lib/pkg/groth"
	bn "github.com/cloudflare/bn256"
)

var (
	ErrWrongUPKType       = errors.New("wrong upk type")
	ErrWrongCredNum       = errors.New("wrong number of credentials")
	ErrInconsistentRootPK = errors.New("inconsistent root public key")
	ErrWrongUPK           = errors.New("wrong upk for this usk")
)

// Credential 用户的证书，L-level的用户证书包括：
//  1. 自身的（L层）sig（groth签名）、attrs（属性）与pk（公钥）
//  2. L层以下的（i...L-1层）的 Credential（prevCreds）
type Credential struct {
	sig       *groth.Signature // TODO: change to []byte
	attrs     []*Attribute
	upk       *PK
	prevCreds []*Credential
}

// NewRootCredential 根据根授权组织的公钥rootPK产生一个根 Credential，L=0
func NewRootCredential(rootPK *PK) *Credential {
	return &Credential{
		upk: rootPK,
	}
}

// Delegate 使用L-1层的私钥、L层的groth公钥与L层的属性attrs给L层生成一个新的 Credential，即延长了证书链
func (c *Credential) Delegate(sp *Parameters, sk *big.Int, upk *PK, attrs []*Attribute) (*Credential, error) {
	// level indicates L
	level := len(c.prevCreds) + 1
	m, err := c.newGrothMessage(level, upk, attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to delegate to level-%d user: %w", level, err)
	}
	sig, err := groth.NewSignature(sp.Groth, sk, m)
	if err != nil {
		return nil, fmt.Errorf("failed to delegate to level-%d user: %w", level, err)
	}

	return &Credential{
		sig:       sig,
		attrs:     attrs,
		upk:       upk,
		prevCreds: append(c.prevCreds, c),
	}, nil
}

// Verify 验证 Credential 的有效性，需要满足：
//  1. 证书链中证书数量与level对应
//  2. 根授权组织的公钥正确，以确保证书授权链来自信任的根
//  3. 本层证书中的upk是与usk对应的
//  4. 证书链中每层的证书都是有效的
func (c *Credential) Verify(sp *Parameters, level int, usk *big.Int, rootPK *PK) error {
	const prefix = "failed to verify credential"
	if level != len(c.prevCreds) {
		return fmt.Errorf("%s: %w, expected %d, got %d", prefix, ErrWrongCredNum, level, len(c.prevCreds))
	}

	if !rootPK.Equals(c.prevCreds[0].upk) {
		return fmt.Errorf("%s: %w", prefix, ErrInconsistentRootPK)
	}

	if !c.upk.Verify(usk) {
		return fmt.Errorf("%s: %w", prefix, ErrWrongUPK)
	}

	for i := level; i > 0; i-- {
		var curr, prev *Credential
		if i == level {
			curr = c
		} else {
			curr = c.prevCreds[i]
		}
		prev = c.prevCreds[i-1]

		var (
			ppk1 *bn.G1
			ppk2 *bn.G2
		)
		if prev.upk.inG1 {
			ppk1 = prev.upk.pk.(*bn.G1)
		} else {
			ppk2 = prev.upk.pk.(*bn.G2)
		}

		gm, err := c.newGrothMessage(i, curr.upk, curr.attrs)
		if err != nil {
			return fmt.Errorf("%s at level-%d: %w", prefix, i, err)
		}
		err = curr.sig.Verify(sp.Groth, groth.NewGrothPK(ppk1, ppk2), gm)
		if err != nil {
			return fmt.Errorf("%s at level-%d: %w", prefix, i, err)
		}
	}

	return nil
}

func (c *Credential) newGrothMessage(level int, upk *PK, attrs []*Attribute) (*groth.Message, error) {
	pkG1 := level%2 == 0
	if upk.inG1 != pkG1 {
		g := "G1"
		if !pkG1 {
			g = "G2"
		}
		return nil, fmt.Errorf("%w, upk must be in %s", ErrWrongUPKType, g)
	}

	ms := make([]any, len(attrs)+1)
	ms[0] = upk.pk
	for i := 1; i < len(ms); i++ {
		if pkG1 {
			ms[i] = attrs[i-1].attr1
		} else {
			ms[i] = attrs[i-1].attr2
		}
	}

	return groth.NewMessage(ms)
}
