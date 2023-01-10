package grouputils

import (
	"bytes"
	"errors"
	"math/big"

	bn "github.com/cloudflare/bn256"
)

var (
	ErrIllegalGroupType      = errors.New("illegal group type, must be G1 or G2")
	ErrInconsistentGroupType = errors.New("inconsistent group type, must be all in G1 or all in G2")
	ErrSameGroupInPairing    = errors.New("require 'a' and 'b' come from different groups")
)

const (
	G1SizeByte = 64  // bn256.G1的大小
	G2SizeByte = 129 // bn256.G2的大小
)

// ScalarMult 求循环群元素a的k次幂
func ScalarMult(a any, k *big.Int) (res any, err error) {
	switch v := a.(type) {
	case *bn.G1:
		return new(bn.G1).ScalarMult(v, k), nil
	case *bn.G2:
		return new(bn.G2).ScalarMult(v, k), nil
	default:
		return nil, ErrIllegalGroupType
	}
}

// ScalarBaseMult 获取g^k，g是群生成元, inG1为true代表在G1否则在G2
func ScalarBaseMult(inG1 bool, k *big.Int) (res any) {
	if inG1 {
		return NewG1(k)
	} else {
		return NewG2(k)
	}
}

// Add 求循环群元素a+b
func Add(a, b any) (ab any, err error) {
	switch av := a.(type) {
	case *bn.G1:
		if bv, ok := b.(*bn.G1); ok {
			return new(bn.G1).Add(av, bv), nil
		} else {
			return nil, ErrInconsistentGroupType
		}
	case *bn.G2:
		if bv, ok := b.(*bn.G2); ok {
			return new(bn.G2).Add(av, bv), nil
		} else {
			return nil, ErrInconsistentGroupType
		}
	default:
		return nil, ErrIllegalGroupType
	}
}

// Pair 求e(a, b)，或者e(b, a)
func Pair(a, b any) (*bn.GT, error) {
	switch av := a.(type) {
	case *bn.G1:
		if bv, ok := b.(*bn.G2); ok {
			return bn.Pair(av, bv), nil
		} else {
			return nil, ErrSameGroupInPairing
		}
	case *bn.G2:
		if bv, ok := b.(*bn.G1); ok {
			return bn.Pair(bv, av), nil
		} else {
			return nil, ErrSameGroupInPairing
		}
	default:
		return nil, ErrIllegalGroupType
	}
}

// Neg 求-a
func Neg(a any) (aNeg any, err error) {
	switch v := a.(type) {
	case *bn.G1:
		return new(bn.G1).Neg(v), nil
	case *bn.G2:
		return new(bn.G2).Neg(v), nil
	default:
		return nil, ErrIllegalGroupType
	}
}

// NewG1 get g1^k from G1
func NewG1(k *big.Int) *bn.G1 {
	return new(bn.G1).ScalarBaseMult(k)
}

// NewG2 get g2^k from G2
func NewG2(k *big.Int) *bn.G2 {
	return new(bn.G2).ScalarBaseMult(k)
}

type serializable interface {
	Marshal() []byte
}

// Equals checks if a == b
func Equals(a, b serializable) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}

// AddMod gets (a + b) mod bn256.Order
func AddMod(a, b *big.Int) *big.Int {
	ab := new(big.Int).Add(a, b)
	return ab.Mod(ab, bn.Order)
}

// MulMod gets (a * b) mod bn256.Order
func MulMod(a, b *big.Int) *big.Int {
	ab := new(big.Int).Mul(a, b)
	return ab.Mod(ab, bn.Order)
}

// G1Generator generates the generator of G1.
func G1Generator() *bn.G1 {
	return new(bn.G1).ScalarBaseMult(big.NewInt(1))
}

// G2Generator generates the generator of G2.
func G2Generator() *bn.G2 {
	return new(bn.G2).ScalarBaseMult(big.NewInt(1))
}

// ProductOfExpG1 computes (g^a)*(h^b) in G1 and returns it.
func ProductOfExpG1(g *bn.G1, a *big.Int, h *bn.G1, b *big.Int) *bn.G1 {
	return new(bn.G1).Add(new(bn.G1).ScalarMult(g, a), new(bn.G1).ScalarMult(h, b))
}

// ProductOfExpG2 computes (g^a)*(h^b) in G2 and returns it.
func ProductOfExpG2(g *bn.G2, a *big.Int, h *bn.G2, b *big.Int) *bn.G2 {
	return new(bn.G2).Add(new(bn.G2).ScalarMult(g, a), new(bn.G2).ScalarMult(h, b))
}

// AddInv gets the additive inverse of x mod q
func AddInv(x, q *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Neg(x), q)
}
