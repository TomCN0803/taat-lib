package taat

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/TomCN0803/taat-lib/pkg/groth"
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

// NewUserKeyPair 根据授权层级level来生成用户公私钥对
func NewUserKeyPair(level int) (sk *big.Int, upk *PK) {
	sk, gpk := groth.GenKeyPair(nil)
	upk = new(PK)
	upk.inG1 = level%2 == 0
	if upk.inG1 {
		upk.pk = gpk.G1()
	} else {
		upk.pk = gpk.G2()
	}
	return sk, upk
}

// Verify 验证pk是否由sk生成
func (pk *PK) Verify(sk *big.Int) bool {
	pk2 := &PK{inG1: pk.inG1}
	_, gpk := groth.GenKeyPair(sk)
	if pk.inG1 {
		pk2.pk = gpk.G1()
	} else {
		pk2.pk = gpk.G2()
	}

	return pk.Equals(pk2)
}

// Marshal marshals PK
func (pk *PK) Marshal() []byte {
	var res []byte
	var pk2 serializable
	if pk.inG1 {
		res = make([]byte, 0, utils.G1SizeByte+1)
		res = append(res, 1)
		pk2 = new(bn.G1).Set(pk.pk.(*bn.G1))
	} else {
		res = make([]byte, 0, utils.G2SizeByte+1)
		res = append(res, 0)
		pk2 = new(bn.G2).Set(pk.pk.(*bn.G2))
	}
	res = append(res, pk2.Marshal()...)

	return res
}

func (pk *PK) Unmarshal(buff []byte) error {
	if buff[0] == 1 {
		pk.inG1 = true
	} else if buff[0] == 0 {
		pk.inG1 = false
	} else {
		return fmt.Errorf("failed to unmarshal buff: %w", ErrIllegalInG1Byte)
	}

	if pk.inG1 {
		pk.pk = new(bn.G1)
		_, err := pk.pk.(*bn.G1).Unmarshal(buff[1 : 1+utils.G1SizeByte])
		if err != nil {
			return fmt.Errorf("failed to unmarshal buff: %w", err)
		}
	} else {
		pk.pk = new(bn.G2)
		_, err := pk.pk.(*bn.G2).Unmarshal(buff[1 : 1+utils.G2SizeByte])
		if err != nil {
			return fmt.Errorf("failed to unmarshal buff: %w", err)
		}
	}

	return nil
}

// Equals checks if pk == pk2
func (pk *PK) Equals(pk2 *PK) bool {
	return bytes.Equal(pk.Marshal(), pk2.Marshal())
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
