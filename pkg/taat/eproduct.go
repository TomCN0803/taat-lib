package taat

import (
	"math/big"

	bn "github.com/cloudflare/bn256"
)

type eArg struct {
	a *bn.G1
	b *bn.G2
	c *big.Int
}

func newEArg(g1, g2 any, c *big.Int) *eArg {
	ea := new(eArg)
	if v, ok := g1.(*bn.G1); ok {
		ea.a = v
		ea.b = g2.(*bn.G2)
	} else {
		ea.a = g2.(*bn.G1)
		ea.b = g1.(*bn.G2)
	}
	ea.c = c

	return ea
}

type eProdFn func(pairs []*eArg) *bn.GT

func eProduct(args []*eArg, fn eProdFn) *bn.GT {
	pairs := make([]*eArg, 0, len(args))
	for _, arg := range args {
		if arg == nil {
			continue
		}

		n := &eArg{
			a: new(bn.G1).Set(arg.a),
			b: new(bn.G2).Set(arg.b),
		}
		if arg.c != nil {
			n.a.ScalarMult(n.a, arg.c)
		}

		pairs = append(pairs, n)
	}

	return fn(pairs)
}

func eProdOptMiller(pairs []*eArg) *bn.GT {
	res := new(bn.GT).ScalarBaseMult(big.NewInt(0))
	for _, pair := range pairs {
		res.Add(res, bn.Miller(pair.a, pair.b))
	}

	return res.Finalize()
}

func eProdOptMillerLoopUnroll(pairs []*eArg) *bn.GT {
	res := new(bn.GT).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(pairs); i += 2 {
		var e *bn.GT
		if i == len(pairs)-1 {
			e = bn.Miller(pairs[i].a, pairs[i].b)
		} else {
			e = new(bn.GT).Add(
				bn.Miller(pairs[i].a, pairs[i].b),
				bn.Miller(pairs[i+1].a, pairs[i+1].b),
			)
		}
		res.Add(res, e)
	}

	return res.Finalize()
}

func eProdNoOpt(pairs []*eArg) *bn.GT {
	res := new(bn.GT).ScalarBaseMult(big.NewInt(0))
	for _, arg := range pairs {
		bk := bn.Pair(arg.a, arg.b)
		if arg.c != nil {
			bk.ScalarMult(bk, arg.c)
		}
		res.Add(res, bk)
	}
	return res
}
