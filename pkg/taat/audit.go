package taat

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	"github.com/TomCN0803/taat-lib/pkg/ttbe"
	bn "github.com/cloudflare/bn256"
)

// AuditProof 审计证明，
type AuditProof struct {
	c, p1, p2, p3 *big.Int
}

var (
	ErrCttbeAndPKsNotInSameGroup = errors.New("cttbe, nymPK and h must in same group, either G1 or G2")
	ErrIncorrectAuditProof       = errors.New("incorrect audit proof")
)

// NewAuditProof 产生审计证明，用于证明：
//  1. cttbe所加密的是usk所对应的公钥，即cttbe加密的是属于该用户自己的公钥
//  2. cttbe.C5 == upk*(tpk.U)^(r1+r2)
//  3. nymSK由usk产生，进而有nymPK由于upk产生
func NewAuditProof(
	tpk *ttbe.TPK, cttbe *ttbe.Cttbe, r1, r2 *big.Int,
	usk, nymSK *big.Int, nymPK *PK, h any,
) (*AuditProof, error) {
	// nymPK、h、cttbe必须在同一个群中，G1或者G2
	if !inSameGroup(cttbe, nymPK, h) {
		return nil, fmt.Errorf("failed to generate new audit proof: %w", ErrCttbeAndPKsNotInSameGroup)
	}

	r := utils.AddMod(r1, r2)
	rhos, err := genKRandomBigInts(3)
	if err != nil {
		return nil, err
	}

	// 生成com1～com3
	com1 := utils.ScalarBaseMult(cttbe.InG1, rhos[0])
	if cttbe.InG1 {
		vc1 := com1.(*bn.G1)
		vc1.Add(vc1, new(bn.G1).ScalarMult(tpk.U1, rhos[1]))
	} else {
		vc1 := com1.(*bn.G2)
		vc1.Add(vc1, new(bn.G2).ScalarMult(tpk.U2, rhos[1]))
	}
	com2 := utils.ScalarBaseMult(cttbe.InG1, rhos[1])
	com3, _ := utils.ScalarMult(h, rhos[2])
	com3, _ = utils.Add(com3, utils.ScalarBaseMult(cttbe.InG1, rhos[0]))

	proof := new(AuditProof)

	// 生成Hash(com1, com2, com3, nymPK, cttbe)，并转换成*big.Int
	c := new(big.Int).SetBytes(auditProveHash(com1, com2, com3, nymPK, cttbe))
	proof.c = c

	proof.p1 = utils.AddMod(rhos[0], utils.MulMod(c, usk))
	proof.p2 = utils.AddMod(rhos[1], utils.MulMod(c, r))
	proof.p3 = utils.AddMod(rhos[2], utils.MulMod(c, nymSK))

	return proof, nil
}

// Verify 验证AuditProof是否有效
func (ap *AuditProof) Verify(cttbe *ttbe.Cttbe, tpk *ttbe.TPK, nymPK *PK, h any) error {
	if !inSameGroup(cttbe, nymPK, h) {
		return fmt.Errorf("failed to verify audit proof: %w", ErrCttbeAndPKsNotInSameGroup)
	}

	com1 := utils.ScalarBaseMult(cttbe.InG1, ap.p1)
	com2 := utils.ScalarBaseMult(cttbe.InG1, ap.p2)
	com3 := utils.ScalarBaseMult(cttbe.InG1, ap.p1)

	if cttbe.InG1 {
		vc1 := com1.(*bn.G1)
		vc1.Add(vc1, new(bn.G1).ScalarMult(tpk.U1, ap.p2))
	} else {
		vc1 := com1.(*bn.G2)
		vc1.Add(vc1, new(bn.G2).ScalarMult(tpk.U2, ap.p2))
	}

	cInv := new(big.Int).Mod(new(big.Int).Neg(ap.c), bn.Order)
	e1c, _ := utils.ScalarMult(cttbe.C3, cInv)
	com1, _ = utils.Add(com1, e1c)
	e2c, _ := utils.ScalarMult(cttbe.C6, cInv)
	com2, _ = utils.Add(com2, e2c)
	hp3, _ := utils.ScalarMult(h, ap.p3)
	com3, _ = utils.Add(com3, hp3)
	npkc, _ := utils.ScalarMult(nymPK.pk, cInv)
	com3, _ = utils.Add(com3, npkc)

	if !bytes.Equal(auditProveHash(com1, com2, com3, nymPK, cttbe), ap.c.Bytes()) {
		return fmt.Errorf("failed to verify audit proof: %w", ErrIncorrectAuditProof)
	}

	return nil
}

// inSameGroup 检查nymPK、h、cttbe是否在同一个群中，G1或者G2
func inSameGroup(cttbe *ttbe.Cttbe, nymPK *PK, h any) bool {
	if cttbe.InG1 {
		if _, ok := h.(*bn.G1); !ok || !nymPK.inG1 {
			return false
		}
	} else {
		if _, ok := h.(*bn.G2); !ok || nymPK.inG1 {
			return false
		}
	}

	return true
}

// auditProveHash 生成Hash(com1, com2, com3, nymPK, cttbe)
func auditProveHash(com1, com2, com3 any, nymPK *PK, cttbe *ttbe.Cttbe) (sum []byte) {
	h := sha256.New()
	if cttbe.InG1 {
		h.Write(com1.(*bn.G1).Marshal())
		h.Write(com2.(*bn.G1).Marshal())
		h.Write(com3.(*bn.G1).Marshal())
		h.Write(nymPK.pk.(*bn.G1).Marshal())
	} else {
		h.Write(com1.(*bn.G2).Marshal())
		h.Write(com2.(*bn.G2).Marshal())
		h.Write(com3.(*bn.G2).Marshal())
		h.Write(nymPK.pk.(*bn.G2).Marshal())
	}
	h.Write(cttbe.Marshal())

	return h.Sum(nil)
}
