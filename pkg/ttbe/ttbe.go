package ttbe

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	"github.com/TomCN0803/taat-lib/pkg/shamir"
	bn "golang.org/x/crypto/bn256"
)

var (
	ErrInvalidCttbe                = errors.New("invalid TTBE cipher text")
	ErrUnequalLenOfTVKsAndAudClues = errors.New("unequal length of tvks and audClues")
	ErrEmptyTVKsOrAudClues         = errors.New("tvks or audClues must not be empty")
)

var hPair struct {
	h1 *bn.G1
	h2 *bn.G2
}

func SetHPair(h1 *bn.G1, h2 *bn.G2) {
	hPair.h1 = h1
	hPair.h2 = h2
}

// Setup 初始化TTBE参数，n为审计者的数量，t为门限阈值
// 如果hPair被初始化了则使用hPair的值作为H1、H2的值
func Setup(n, t uint64) (*Parameters, error) {
	var err error
	tsks := make([]*TSK, 0, n)
	tvks := make([]*TVK, 0, n)

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
		tsks = append(tsks, &TSK{i + 1, usi.Y(), vsi.Y()})
		tvkU1i := new(bn.G1).ScalarMult(h1, usi.Y())
		tvkV1i := new(bn.G1).ScalarMult(v1, vsi.Y())
		tvkU2i := new(bn.G2).ScalarMult(h2, usi.Y())
		tvkV2i := new(bn.G2).ScalarMult(v2, vsi.Y())
		tvks = append(tvks, &TVK{i + 1, tvkU1i, tvkV1i, tvkU2i, tvkV2i})
	}

	return &Parameters{
		&TPK{h1, u1, v1, w1, z1, h2, u2, v2, w2, z2},
		tsks,
		tvks,
	}, nil
}

// Encrypt 产生TTBE密文
func Encrypt(tpk *TPK, tag *big.Int, m any) (cttbe *Cttbe, r1 *big.Int, r2 *big.Int, err error) {
	r1, err = rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, nil, nil, err
	}
	r2, err = rand.Int(rand.Reader, bn.Order)
	if err != nil {
		return nil, nil, nil, err
	}

	var h, v, u, w, z any
	var inG1 bool
	switch m.(type) {
	case *bn.G1:
		inG1 = true
		h, v, u, w, z = tpk.H1, tpk.V1, tpk.U1, tpk.W1, tpk.Z1
	case *bn.G2:
		h, v, u, w, z = tpk.H2, tpk.V2, tpk.U2, tpk.W2, tpk.Z2
	default:
		return nil, nil, nil, utils.ErrIllegalGroupType
	}

	r := new(big.Int).Add(r1, r2)
	c1, _ := utils.ScalarMult(h, r1)
	c2, _ := utils.ScalarMult(v, r2)
	c3, _ := utils.ScalarMult(u, r)
	c3, _ = utils.Add(c3, m)
	c4, _ := utils.ScalarMult(u, tag)
	c4, _ = utils.Add(c4, w)
	c4, _ = utils.ScalarMult(c4, r1)
	c5, _ := utils.ScalarMult(u, tag)
	c5, _ = utils.Add(c5, z)
	c5, _ = utils.ScalarMult(c5, r2)
	c6 := utils.ScalarBaseMult(inG1, r)

	return &Cttbe{inG1, c1, c2, c3, c4, c5, c6}, r1, r2, nil
}

// Combine 根据线索恢复出cttbe对应的明文
// tvks和clues数组要保持一致的对应顺序,且数量必须大于等于解密阈值t，否则会出错
func Combine(tpk *TPK, tag *big.Int, cttbe *Cttbe, tvks []*TVK, clues []*AudClue) (result any, err error) {
	if len(tvks) == 0 || len(clues) == 0 {
		return nil, ErrEmptyTVKsOrAudClues
	}
	if len(tvks) != len(clues) {
		return nil, ErrUnequalLenOfTVKsAndAudClues
	}
	if !IsValidEnc(tpk, tag, cttbe) {
		return nil, ErrInvalidCttbe
	}

	indices := make([]*big.Int, len(clues))
	for i, clue := range clues {
		indices[i] = big.NewInt(int64(clue.id))
	}

	var den any
	if cttbe.InG1 {
		den = new(bn.G1).Identity()
	} else {
		den = new(bn.G2).Identity()
	}
	for i, ac := range clues {
		if !IsValidAudClue(tpk, tag, cttbe, tvks[i], ac) {
			return nil, fmt.Errorf("invalid audit clue of id %d", ac.id)
		}
		idx := big.NewInt(int64(ac.id))
		coeff := shamir.LagCoeff(idx, indices, bn.Order)
		c1, _ := utils.ScalarMult(ac.ac1, coeff)
		c2, _ := utils.ScalarMult(ac.ac2, coeff)
		d, _ := utils.Add(c1, c2)
		den, _ = utils.Add(den, d)
	}
	den, _ = utils.Neg(den)

	return utils.Add(cttbe.C3, den)
}

// IsValidEnc 验证密文cttbe是否在给定tpk和tag下有效
func IsValidEnc(tpk *TPK, tag *big.Int, cttbe *Cttbe) bool {
	var u, v, w, h, z any
	if !cttbe.InG1 {
		u, v, w, h, z = tpk.U1, tpk.V1, tpk.W1, tpk.H1, tpk.Z1
	} else {
		u, v, w, h, z = tpk.U2, tpk.V2, tpk.W2, tpk.H2, tpk.Z2
	}

	uw, _ := utils.ScalarMult(u, tag)
	uw, _ = utils.Add(uw, w)
	p1, _ := utils.Pair(cttbe.C1, uw)

	uz, _ := utils.ScalarMult(u, tag)
	uz, _ = utils.Add(uz, z)
	p2, _ := utils.Pair(cttbe.C2, uz)

	p4, _ := utils.Pair(cttbe.C4, h)
	p5, _ := utils.Pair(cttbe.C5, v)

	return bytes.Equal(p1.Marshal(), p4.Marshal()) && bytes.Equal(p2.Marshal(), p5.Marshal())
}

// ShareAudClue return an auditing clue.
func ShareAudClue(tpk *TPK, tag *big.Int, cttbe *Cttbe, tsk *TSK) (*AudClue, error) {
	if !IsValidEnc(tpk, tag, cttbe) {
		return nil, ErrInvalidCttbe
	}

	ac1, err := utils.ScalarMult(cttbe.C1, tsk.u)
	if err != nil {
		return nil, err
	}
	ac2, err := utils.ScalarMult(cttbe.C2, tsk.v)
	if err != nil {
		return nil, err
	}

	return &AudClue{tsk.id, cttbe.InG1, ac1, ac2}, nil
}

// IsValidAudClue 验证AudClue是否在给定tpk和tag下有效
func IsValidAudClue(tpk *TPK, tag *big.Int, cttbe *Cttbe, tvk *TVK, clue *AudClue) bool {
	// clue和cttbe需要在同一个群中
	if !IsValidEnc(tpk, tag, cttbe) || clue.inG1 != cttbe.InG1 {
		return false
	}

	var ui, vi any
	var h, v any
	if cttbe.InG1 {
		ui, vi = tvk.u2, tvk.v2
		h, v = tpk.H2, tpk.V2
	} else {
		ui, vi = tvk.u1, tvk.v1
		h, v = tpk.H1, tpk.V1
	}

	pi1, _ := utils.Pair(clue.ac1, h)
	p1, _ := utils.Pair(cttbe.C1, ui)
	pi2, _ := utils.Pair(clue.ac2, v)
	p2, _ := utils.Pair(cttbe.C2, vi)

	return bytes.Equal(pi1.Marshal(), p1.Marshal()) && bytes.Equal(pi2.Marshal(), p2.Marshal())
}
