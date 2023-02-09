package taat

import bn "github.com/cloudflare/bn256"

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
