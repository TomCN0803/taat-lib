package taat

// NymPK 假名的公钥
type NymPK struct {
	inG1 bool
	pk   any // (g^usk)*(h^nymSK)
}
