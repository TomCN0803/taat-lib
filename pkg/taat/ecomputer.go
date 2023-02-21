package taat

import (
	bn "github.com/cloudflare/bn256"
)

type eComputer struct {
	nworker int

	inc  chan *eComArg
	resc chan *eProdRes
	resq chan struct{}
	done chan struct{}

	res [][]*bn.GT
}

type eComArg struct {
	args []*eArg
	i, j int
}

type eProdRes struct {
	res  *bn.GT
	i, j int
}

func newEComputer(nworker, rows, cols int) *eComputer {
	res := make([][]*bn.GT, rows)
	for i := range res {
		res[i] = make([]*bn.GT, cols)
	}

	return &eComputer{
		nworker: nworker,
		inc:     make(chan *eComArg, nworker),
		resc:    make(chan *eProdRes, nworker),
		resq:    make(chan struct{}),
		done:    make(chan struct{}),
		res:     res,
	}
}

func (ec *eComputer) run() {
	for i := 0; i < ec.nworker; i++ {
		go func() {
			for eca := range ec.inc {
				r := eProduct(eca.args, eProdOptMillerLoopUnroll)
				ec.resc <- &eProdRes{r, eca.i, eca.j}
			}
			ec.resq <- struct{}{}
		}()
	}

	go func() {
		for i := 0; i < ec.nworker; i++ {
			<-ec.resq
		}
		close(ec.resc)
	}()

	go func() {
		for r := range ec.resc {
			//res, _ := utils.Copy(r.res)
			//log.Println(r.i, r.j, res.(*bn.GT).Marshal())
			ec.res[r.i][r.j] = r.res
		}
		ec.done <- struct{}{}
	}()
}

func (ec *eComputer) enqueue(args []*eArg, i, j int) {
	ec.inc <- &eComArg{args, i, j}
}

func (ec *eComputer) result() [][]*bn.GT {
	close(ec.inc)
	<-ec.done
	return ec.res
}
