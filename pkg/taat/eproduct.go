package taat

import (
	"math/big"

	bn "github.com/cloudflare/bn256"
)

type eArgs struct {
	a *bn.G1
	b *bn.G2
	c *big.Int
}

type eProdComputer func(pairs []*eArgs) *bn.GT

func eProduct(args []*eArgs, fn eProdComputer) *bn.GT {
	pairs := make([]*eArgs, 0, len(args))
	for _, arg := range args {
		if arg == nil {
			continue
		}

		n := &eArgs{
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

func eProdOptMiller(pairs []*eArgs) *bn.GT {
	res := new(bn.GT).ScalarBaseMult(big.NewInt(0))
	for _, pair := range pairs {
		res.Add(res, bn.Miller(pair.a, pair.b))
	}

	return res.Finalize()
}

func eProdOptMillerLoopUnroll(pairs []*eArgs) *bn.GT {
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
