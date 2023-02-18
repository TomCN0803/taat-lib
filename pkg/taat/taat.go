package taat

import (
	"github.com/TomCN0803/taat-lib/pkg/groth"
	"github.com/TomCN0803/taat-lib/pkg/ttbe"
	bn "github.com/cloudflare/bn256"
)

// Parameters TAAT公共参数
type Parameters struct {
	H1 *bn.G1
	H2 *bn.G2

	MaxAttrs int // 最大 Attribute 数量

	TPK     *ttbe.TPK         // TTBE公钥
	Groth   *groth.Parameters // Groth签名公共参数
	RootUPK *PK               // 根Authority的公钥
}
