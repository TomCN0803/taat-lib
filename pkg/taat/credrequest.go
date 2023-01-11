package taat

import (
	"fmt"
	"math/big"
)

// CredRequest 包含了服务端的nonce，用户公钥upk以及关于持有私钥usk的证明
type CredRequest struct {
	nonce    []byte
	upk      *PK // g^usk
	uskProof *UskProof
}

// NewCredRequest 创建一个 CredRequest
func NewCredRequest(usk *big.Int, upk *PK, nonce []byte) (*CredRequest, error) {
	proof, err := NewUSKProof(usk, upk, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential request: %w", err)
	}

	return &CredRequest{
		nonce:    nonce,
		upk:      upk,
		uskProof: proof,
	}, nil
}

// Check 检查当前的 CredRequest 是否合法有效
func (r *CredRequest) Check() error {
	if err := r.uskProof.Verify(r.upk, r.nonce); err != nil {
		return fmt.Errorf("credential request check failed: %w", err)
	} else {
		return nil
	}
}
