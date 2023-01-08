package taat

import bn "github.com/cloudflare/bn256"

// Parameters TAAT公共参数
type Parameters struct {
	H1 *bn.G1
	H2 *bn.G2
}
