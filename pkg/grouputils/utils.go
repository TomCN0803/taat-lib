package grouputils

import (
	"errors"
	"math/big"

	bn "golang.org/x/crypto/bn256"
)

var (
	ErrIllegalGroupType      = errors.New("illegal group type, must be G1 or G2")
	ErrInconsistentGroupType = errors.New("inconsistent group type, must be both G1 or both G2")
	ErrSameGroupInPairing    = errors.New("require 'a' and 'b' come from different groups")
)

// ScalarMult 求循环群元素a的k次幂
func ScalarMult(a any, k *big.Int) (any, error) {
	switch v := a.(type) {
	case *bn.G1:
		return new(bn.G1).ScalarMult(v, k), nil
	case *bn.G2:
		return new(bn.G2).ScalarMult(v, k), nil
	default:
		return nil, ErrIllegalGroupType
	}
}

// GAdd 求循环群元素a+b
func GAdd(a, b any) (any, error) {
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

// InvMod finds the inverse of a mod p
func InvMod(a, p *big.Int) *big.Int {
	return new(big.Int).Exp(a, new(big.Int).Sub(p, big.NewInt(2)), p)
}
