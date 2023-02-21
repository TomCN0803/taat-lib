package taat

import (
	"encoding/binary"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	bn "github.com/cloudflare/bn256"
)

// Attribute 是 Credential 证书的属性
type Attribute struct {
	attr1 *bn.G1
	attr2 *bn.G2
}

func (a *Attribute) G1() *bn.G1 {
	return a.attr1
}

func (a *Attribute) G2() *bn.G2 {
	return a.attr2
}

// AttrSetElem 用于表示在第i层的第j个属性attr
type AttrSetElem struct {
	i, j  int
	value *Attribute
}

func (ase *AttrSetElem) Value() *Attribute {
	return ase.value
}

func (ase *AttrSetElem) Marshal() []byte {
	res := make([]byte, 0)
	res = binary.LittleEndian.AppendUint64(res, uint64(ase.i))
	res = binary.LittleEndian.AppendUint64(res, uint64(ase.j))
	a1, _ := utils.Copy(ase.value.attr1)
	res = append(res, a1.(*bn.G1).Marshal()...)
	a2, _ := utils.Copy(ase.value.attr2)
	res = append(res, a2.(*bn.G2).Marshal()...)

	return res
}

type AttrSet []*AttrSetElem

func (as AttrSet) Len() int {
	return len(as)
}

func (as AttrSet) Less(i, j int) bool {
	return as[i].i < as[j].i || as[i].j < as[j].j
}

func (as AttrSet) Swap(i, j int) {
	as[i], as[j] = as[j], as[i]
}

func (as AttrSet) Get(i, j int) *AttrSetElem {
	for _, elem := range as {
		if elem.i == i && elem.j == j {
			return elem
		}
	}
	return nil
}

func (as AttrSet) Marshal() []byte {
	var res []byte
	for _, a := range as {
		res = append(res, a.Marshal()...)
	}

	return res
}
