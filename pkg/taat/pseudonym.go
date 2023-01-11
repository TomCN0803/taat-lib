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
	ErrWrongHType            = errors.New("wrong h type, must be in G1 or in G2")
	ErrInconsistentHAndNymPK = errors.New("h and nymPK must be both in G1 or in G2")
	ErrIncorrectNymSig       = errors.New("incorrect pseudonym signature")
)

// NewNymKeyPair 根据usk产生匿名公私钥对(nymSK, nymPK)
func NewNymKeyPair(usk *big.Int, h any) (nymSK *big.Int, nymPK *PK, err error) {
	nymSK, err = rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new pseudonym key pair: %w", err)
	}

	nymPK = new(PK)
	switch hv := h.(type) {
	case *bn.G1:
		nymPK.inG1 = true
		nymPK.pk = utils.ProductOfExpG1(utils.G1Generator(), usk, hv, nymSK)
	case *bn.G2:
		nymPK.pk = utils.ProductOfExpG2(utils.G2Generator(), usk, hv, nymSK)
	default:
		return nil, nil, fmt.Errorf("failed to generate new pseudonym key pair: %w", ErrWrongHType)
	}

	return nymSK, nymPK, nil
}

// NymSignature 假名公钥私钥对产生的签名
type NymSignature struct {
	c      *big.Int
	pUSK   *big.Int
	pNymSK *big.Int
}

// NewNymSignature 产生关于msg的假名签名nymSignature，用于证明：
//  1. 用户持有usk
//  2. 用户签名所使用的假名私钥nymSK是由usk生成
func NewNymSignature(usk, nymSK *big.Int, nymPK *PK, h any, msg []byte) (*NymSignature, error) {
	r1, _ := rand.Int(rand.Reader, bn.Order)
	r2, _ := rand.Int(rand.Reader, bn.Order)
	var com interface{ Marshal() []byte }
	switch hv := h.(type) {
	case *bn.G1:
		com = utils.ProductOfExpG1(utils.G1Generator(), r1, hv, r2)
	case *bn.G2:
		com = utils.ProductOfExpG2(utils.G2Generator(), r1, hv, r2)
	default:
		return nil, fmt.Errorf("\"failed to generate new pseudonym signature\": %w", ErrWrongHType)
	}

	c := new(big.Int).SetBytes(nymSigProveHash(com, nymPK, msg))
	ns := &NymSignature{c: c}
	ns.pUSK = utils.AddMod(r1, utils.MulMod(c, usk))
	ns.pNymSK = utils.AddMod(r2, utils.MulMod(c, nymSK))

	return ns, nil
}

// Verify 验证nymSignature的合法性
func (ns *NymSignature) Verify(nymPK *PK, h any, msg []byte) error {
	cInv := utils.AddInv(ns.c, bn.Order)
	var com serializable
	switch hv := h.(type) {
	case *bn.G1:
		if !nymPK.inG1 {
			return fmt.Errorf("failed to verify pseudonym signature: %w", ErrInconsistentHAndNymPK)
		}
		com = utils.ProductOfExpG1(utils.G1Generator(), ns.pUSK, hv, ns.pNymSK)
		com = new(bn.G1).Add(com.(*bn.G1), new(bn.G1).ScalarMult(nymPK.pk.(*bn.G1), cInv))
	case *bn.G2:
		if nymPK.inG1 {
			return fmt.Errorf("failed to verify pseudonym signature: %w", ErrInconsistentHAndNymPK)
		}
		com = utils.ProductOfExpG2(utils.G2Generator(), ns.pUSK, hv, ns.pNymSK)
		com = new(bn.G2).Add(com.(*bn.G2), new(bn.G2).ScalarMult(nymPK.pk.(*bn.G2), cInv))
	default:
		return fmt.Errorf("failed to verify pseudonym signature: %w", ErrWrongHType)
	}

	if !bytes.Equal(ns.c.Bytes(), nymSigProveHash(com, nymPK, msg)) {
		return fmt.Errorf("failed to verify pseudonym signature: %w", ErrIncorrectNymSig)
	}

	return nil
}

// nymSigProveHash returns HASH(com, nymPK, msg).
func nymSigProveHash(com serializable, nymPK *PK, msg []byte) []byte {
	h := sha256.New()
	h.Write(com.Marshal())
	h.Write(nymPK.Marshal())
	h.Write(msg)

	return h.Sum(nil)
}
