package taat

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	bn "github.com/cloudflare/bn256"
)

var (
	ErrIllegalInG1Byte   = errors.New("illegal inG1 byte, 0 for inG1 == false, 1 for inG1 == true")
	ErrIncorrectUSKProof = errors.New("incorrect usk proof")
)

// PK 公钥，nymPK或upk都可以用该结构体表示
type PK struct {
	inG1 bool
	pk   serializable
}

// Marshal marshals PK
func (np *PK) Marshal() []byte {
	var res []byte
	if np.inG1 {
		res = make([]byte, 0, utils.G1SizeByte+1)
		res = append(res, 1)
	} else {
		res = make([]byte, 0, utils.G2SizeByte+1)
		res = append(res, 0)
	}
	res = append(res, np.pk.Marshal()...)

	return res
}

func (np *PK) Unmarshal(buff []byte) error {
	if buff[0] == 1 {
		np.inG1 = true
	} else if buff[0] == 0 {
		np.inG1 = false
	} else {
		return fmt.Errorf("failed to unmarshal buff: %w", ErrIllegalInG1Byte)
	}

	if np.inG1 {
		np.pk = new(bn.G1)
		_, err := np.pk.(*bn.G1).Unmarshal(buff[1 : 1+utils.G1SizeByte])
		if err != nil {
			return fmt.Errorf("failed to unmarshal buff: %w", err)
		}
	} else {
		np.pk = new(bn.G2)
		_, err := np.pk.(*bn.G2).Unmarshal(buff[1 : 1+utils.G2SizeByte])
		if err != nil {
			return fmt.Errorf("failed to unmarshal buff: %w", err)
		}
	}

	return nil
}

type UskProof struct {
	c *big.Int
	p *big.Int
}

// NewUSKProof 创建新的 UskProof，用于证明：
//   - upk由usk产生
//   - 用户持有usk
func NewUSKProof(usk *big.Int, upk *PK, nonce []byte) (*UskProof, error) {
	r, err := rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate usk proof: %w", err)
	}

	var com serializable
	if upk.inG1 {
		com = new(bn.G1).ScalarBaseMult(r)
	} else {
		com = new(bn.G2).ScalarBaseMult(r)
	}

	proof := new(UskProof)
	proof.c = new(big.Int).SetBytes(uskProveHash(com, upk, nonce))
	proof.p = utils.AddMod(r, utils.MulMod(proof.c, usk))

	return proof, nil
}

func (up *UskProof) Verify(upk *PK, nonce []byte) error {
	var com serializable
	cInv := utils.AddInv(up.c, bn.Order)
	if upk.inG1 {
		com = utils.ProductOfExpG1(utils.G1Generator(), up.p, upk.pk.(*bn.G1), cInv)
	} else {
		com = utils.ProductOfExpG2(utils.G2Generator(), up.p, upk.pk.(*bn.G2), cInv)
	}

	if !bytes.Equal(up.c.Bytes(), uskProveHash(com, upk, nonce)) {
		return ErrIncorrectUSKProof
	}

	return nil
}

// uskProveHash returns HASH(com, upk, nonce)
func uskProveHash(com serializable, upk *PK, nonce []byte) []byte {
	h := sha256.New()
	h.Write(com.Marshal())
	h.Write(upk.Marshal())
	h.Write(nonce)

	return h.Sum(nil)
}
