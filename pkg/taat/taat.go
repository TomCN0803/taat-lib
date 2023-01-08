package taat

import bn "golang.org/x/crypto/bn256"

// Parameters TAAT公共参数
type Parameters struct {
	H1 *bn.G1
	H2 *bn.G2
}
