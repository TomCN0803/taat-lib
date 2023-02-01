package taat

import bn "github.com/cloudflare/bn256"

type eComputerSync struct {
	nworker int
	res     [][]*bn.GT
}

func newEComputerSync(nworker, rows, cols int) *eComputerSync {
	res := make([][]*bn.GT, rows)
	for i := range res {
		res[i] = make([]*bn.GT, cols)
	}
	return &eComputerSync{
		nworker: nworker,
		res:     res,
	}
}

func (ec *eComputerSync) run() {
}

func (ec *eComputerSync) enqueue(args []*eArg, i, j int) {
	ec.res[i][j] = eProduct(args, eProdOptMillerLoopUnroll)
}

func (ec *eComputerSync) result() [][]*bn.GT {
	return ec.res
}
