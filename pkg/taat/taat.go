package taat

import (
	"github.com/TomCN0803/taat-lib/pkg/groth"
	"github.com/TomCN0803/taat-lib/pkg/ttbe"
)

// Parameters TAAT公共参数
type Parameters struct {
	TTBE  *ttbe.Parameters
	Groth *groth.Parameters
}
