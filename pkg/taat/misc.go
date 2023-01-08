package taat

import (
	"crypto/rand"
	"math/big"

	"github.com/cloudflare/bn256"
)

func genKRandomBigInts(k int) ([]*big.Int, error) {
	res := make([]*big.Int, 0, k)
	for i := 0; i < k; i++ {
		v, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
	}

	return res, nil
}
