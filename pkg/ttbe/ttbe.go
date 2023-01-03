package ttbe

import (
	"crypto/rand"
	"errors"
	"math/big"
	"reflect"

	utils "github.com/TomCN0803/taat/pkg/grouputils"
	"github.com/TomCN0803/taat/pkg/shamir"
	bn "golang.org/x/crypto/bn256"
)

var ErrInvalidCttbe = errors.New("invalid TTBE cipher text")

var hPair struct {
	h1 *bn.G1
	h2 *bn.G2
}

func SetHPair(h1 *bn.G1, h2 *bn.G2) {
	hPair.h1 = h1
	hPair.h2 = h2
}

// TPK TTBE公钥
type TPK struct {
	H1, U1, V1, W1, Z1 *bn.G1
	H2, U2, V2, W2, Z2 *bn.G2
}

// TSK TTBE私钥
type TSK struct {
	index uint64
	u, v  *big.Int
}

// TVK TTBE验证证密钥
type TVK struct {
	index  uint64
	U1, V1 *bn.G1
	U2, V2 *bn.G2
}

// Cttbe TTBE密文
type Cttbe struct {
	first              bool // true if in G1 and false in G2
	c1, c2, c3, c4, c5 any
}

// AudClue 审计线索，即auditing clue
type AudClue struct {
	index    uint64
	ac1, ac2 any
}

// Parameters TTBE初始化参数
type Parameters struct {
	TPK  *TPK
	TSKs []TSK
	TVKs []TVK
}

// Setup 初始化TTBE参数，n为审计者的数量，t为门限阈值
// 如果hPair被初始化了则使用hPair的值作为H1、H2的值
func Setup(n, t uint64) (*Parameters, error) {
	var err error
	tsks := make([]TSK, 0, n)
	tvks := make([]TVK, 0, n)

	var h *big.Int
	if hPair.h1 == nil || hPair.h2 == nil {
		h, err = rand.Int(rand.Reader, bn.Order)
		if err != nil {
			return nil, err
		}
	}

	w, err := rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, err
	}
	z, err := rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, err
	}

	// u is the shamir secret of u_1 ... u_n
	// v is the shamir secret of v_1 ... v_n
	// tsk is the shamir secret of tsk_1=(u_1, v_1) ... tsk_n=(u_n, v_n)
	u, err := rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, err
	}
	v, err := rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, err
	}
	polyU := shamir.GenRandPoly(t, u, bn.Order)
	polyV := shamir.GenRandPoly(t, v, bn.Order)
	us := shamir.GenShares(polyU, n, bn.Order)
	vs := shamir.GenShares(polyV, n, bn.Order)

	var h1 *bn.G1
	var h2 *bn.G2
	if h != nil {
		h1, h2 = new(bn.G1).ScalarBaseMult(h), new(bn.G2).ScalarBaseMult(h)
	} else {
		h1, h2 = hPair.h1, hPair.h2
	}

	u1, u2 := new(bn.G1).ScalarMult(h1, u), new(bn.G2).ScalarMult(h2, u)
	vInv := utils.InvMod(v, bn.Order) // get the inverse of v i.e. vInv
	v1, v2 := new(bn.G1).ScalarMult(u1, vInv), new(bn.G2).ScalarMult(u2, vInv)
	w1, w2 := new(bn.G1).ScalarMult(h1, w), new(bn.G2).ScalarMult(h2, w)
	z1, z2 := new(bn.G1).ScalarMult(v1, z), new(bn.G2).ScalarMult(v2, z)

	for i := uint64(0); i < n; i++ {
		usi, vsi := us[i], vs[i]
		tsks = append(tsks, TSK{i + 1, usi.Y(), vsi.Y()})
		tvkU1i := new(bn.G1).ScalarMult(h1, usi.Y())
		tvkV1i := new(bn.G1).ScalarMult(h1, vsi.Y())
		tvkU2i := new(bn.G2).ScalarMult(h2, usi.Y())
		tvkV2i := new(bn.G2).ScalarMult(h2, vsi.Y())
		tvks = append(tvks, TVK{i + 1, tvkU1i, tvkV1i, tvkU2i, tvkV2i})
	}

	return &Parameters{
		&TPK{h1, u1, v1, w1, z1, h2, u2, v2, w2, z2},
		tsks,
		tvks,
	}, nil
}

// Encrypt 产生TTBE密文
func Encrypt(tpk *TPK, tag *big.Int, m any) (*Cttbe, error) {
	r1, err := rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, err
	}
	r2, err := rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, err
	}

	var h, v, u, w, z any
	var first bool
	switch m.(type) {
	case *bn.G1:
		first = true
		h, v, u, w, z = tpk.H1, tpk.V1, tpk.U1, tpk.W1, tpk.Z1
	case *bn.G2:
		h, v, u, w, z = tpk.H2, tpk.V2, tpk.U2, tpk.W2, tpk.Z2
	default:
		return nil, utils.ErrIllegalGroupType
	}

	c1, _ := utils.ScalarMult(h, r1)
	c2, _ := utils.ScalarMult(v, r2)
	c3, _ := utils.ScalarMult(u, new(big.Int).Add(r1, r2))
	c3, _ = utils.GAdd(c3, m)
	c4, _ := utils.ScalarMult(u, tag)
	c4, _ = utils.GAdd(c4, w)
	c4, _ = utils.ScalarMult(c4, r1)
	c5, _ := utils.ScalarMult(u, tag)
	c5, _ = utils.GAdd(c5, z)
	c5, _ = utils.ScalarMult(c5, r2)

	return &Cttbe{first, c1, c2, c3, c4, c5}, nil
}

// IsValidEnc 验证密文cttbe是否在给定tpk和tag下有效
func IsValidEnc(tpk *TPK, tag *big.Int, cttbe *Cttbe) bool {
	var u, v, w, h, z any
	if !cttbe.first {
		u, v, w, h, z = tpk.U1, tpk.V1, tpk.W1, tpk.H1, tpk.Z1
	} else {
		u, v, w, h, z = tpk.U2, tpk.V2, tpk.W2, tpk.H2, tpk.Z2
	}

	uw, _ := utils.ScalarMult(u, tag)
	uw, _ = utils.GAdd(uw, w)
	p1, _ := utils.Pair(cttbe.c1, uw)

	uz, _ := utils.ScalarMult(u, tag)
	uz, _ = utils.GAdd(uz, z)
	p2, _ := utils.Pair(cttbe.c2, uz)

	p4, _ := utils.Pair(cttbe.c4, h)
	p5, _ := utils.Pair(cttbe.c5, v)

	return reflect.DeepEqual(p1, p4) && reflect.DeepEqual(p2, p5)
}

// ShareDec return an auditing clue.
func ShareDec(tpk *TPK, tsk *TSK, tag *big.Int, cttbe *Cttbe) (*AudClue, error) {
	if !IsValidEnc(tpk, tag, cttbe) {
		return nil, ErrInvalidCttbe
	}

	ac1, err := utils.ScalarMult(cttbe.c1, tsk.u)
	if err != nil {
		return nil, err
	}
	ac2, err := utils.ScalarMult(cttbe.c2, tsk.v)
	if err != nil {
		return nil, err
	}

	return &AudClue{tsk.index, ac1, ac2}, nil
}
