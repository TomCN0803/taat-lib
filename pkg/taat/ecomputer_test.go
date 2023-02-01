package taat

import (
	"testing"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	bn "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

const size = 10

func TestEComputer(t *testing.T) {
	t.Parallel()
	argMat := randArgMat(size, size, size)

	ecSync := newEComputerSync(size, size, size)
	ecSync.run()
	for i, row := range argMat {
		for j, args := range row {
			ecSync.enqueue(args, i, j)
		}
	}
	resSync := ecSync.result()

	ecPara := newEComputer(size, size, size)
	ecPara.run()
	for i, row := range argMat {
		for j, args := range row {
			ecPara.enqueue(args, i, j)
		}
	}
	resPara := ecPara.result()

	require.True(t, equals(resSync, resPara))
}

func BenchmarkEComputer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		argMat := randArgMat(size, size, size)
		b.StartTimer()
		ecPara := newEComputer(size, size, size)
		ecPara.run()
		for i, row := range argMat {
			for j, args := range row {
				ecPara.enqueue(args, i, j)
			}
		}
		_ = ecPara.result()
	}
}

func BenchmarkEComputerSync(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		argMat := randArgMat(size, size, size)
		b.StartTimer()
		ecSync := newEComputerSync(size, size, size)
		ecSync.run()
		for i, row := range argMat {
			for j, args := range row {
				ecSync.enqueue(args, i, j)
			}
		}
		_ = ecSync.result()
	}
}

func randArgMat(rows, cols, nargs int) [][][]*eArg {
	argMat := make([][][]*eArg, rows)
	for i := range argMat {
		argMat[i] = make([][]*eArg, cols)
		for j := range argMat[i] {
			argMat[i][j] = randEArgs(nargs)
		}
	}

	return argMat
}

func equals(a, b [][]*bn.GT) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if !utils.Equals(a[i][j], b[i][j]) {
				return false
			}
		}
	}

	return true
}
