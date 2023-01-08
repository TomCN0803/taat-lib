package ttbe

import (
	"errors"
	"fmt"
	"math/big"

	utils "github.com/TomCN0803/taat-lib/pkg/grouputils"
	bn "golang.org/x/crypto/bn256"
)

var (
	ErrIllegalInG1Byte = errors.New("illegal InG1 byte, 0 for InG1 == false, 1 for InG1 == true")
	ErrMalFormedG1Elem = errors.New("malformed G1 element")
	ErrMalFormedG2Elem = errors.New("malformed G2 element")
)

// TPK TTBE公钥
type TPK struct {
	H1, U1, V1, W1, Z1 *bn.G1
	H2, U2, V2, W2, Z2 *bn.G2
}

// TSK TTBE私钥
type TSK struct {
	id   uint64
	u, v *big.Int
}

// TVK TTBE验证证密钥
type TVK struct {
	id     uint64
	u1, v1 *bn.G1
	u2, v2 *bn.G2
}

// Cttbe TTBE密文
type Cttbe struct {
	InG1                   bool // true if in G1 and false in G2
	C1, C2, C3, C4, C5, C6 any
}

func (c *Cttbe) Marshal() []byte {
	var res []byte
	if c.InG1 {
		res = make([]byte, 0, 64*6+1)
		res = append(res, 1)
		res = append(res, c.C1.(*bn.G1).Marshal()...)
		res = append(res, c.C2.(*bn.G1).Marshal()...)
		res = append(res, c.C3.(*bn.G1).Marshal()...)
		res = append(res, c.C4.(*bn.G1).Marshal()...)
		res = append(res, c.C5.(*bn.G1).Marshal()...)
		res = append(res, c.C6.(*bn.G1).Marshal()...)
	} else {
		res = make([]byte, 0, 128*6+1)
		res = append(res, 0)
		res = append(res, c.C1.(*bn.G2).Marshal()...)
		res = append(res, c.C2.(*bn.G2).Marshal()...)
		res = append(res, c.C3.(*bn.G2).Marshal()...)
		res = append(res, c.C4.(*bn.G2).Marshal()...)
		res = append(res, c.C5.(*bn.G2).Marshal()...)
		res = append(res, c.C6.(*bn.G2).Marshal()...)
	}

	return res
}

// Unmarshal reads from byte slice buff, converts it to *Cttbe and sets c to the converting result.
func (c *Cttbe) Unmarshal(buff []byte) error {
	if buff[0] == 1 {
		c.InG1 = true
	} else if buff[0] == 0 {
		c.InG1 = false
	} else {
		return fmt.Errorf("failed to unmarshal buff: %w", ErrIllegalInG1Byte)
	}

	if c.InG1 {
		var ok bool
		c.C1, ok = new(bn.G1).Unmarshal(buff[1:65])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG1Elem)
		}
		c.C2, ok = new(bn.G1).Unmarshal(buff[65:129])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG1Elem)
		}
		c.C3, ok = new(bn.G1).Unmarshal(buff[129:193])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG1Elem)
		}
		c.C4, ok = new(bn.G1).Unmarshal(buff[193:257])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG1Elem)
		}
		c.C5, ok = new(bn.G1).Unmarshal(buff[257:321])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG1Elem)
		}
		c.C6, ok = new(bn.G1).Unmarshal(buff[321:])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG1Elem)
		}
	} else {
		var ok bool
		c.C1, ok = new(bn.G2).Unmarshal(buff[1:129])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG2Elem)
		}
		c.C2, ok = new(bn.G2).Unmarshal(buff[129:257])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG2Elem)
		}
		c.C3, ok = new(bn.G2).Unmarshal(buff[257:385])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG2Elem)
		}
		c.C4, ok = new(bn.G2).Unmarshal(buff[385:513])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG2Elem)
		}
		c.C5, ok = new(bn.G2).Unmarshal(buff[513:641])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG2Elem)
		}
		c.C6, ok = new(bn.G2).Unmarshal(buff[641:])
		if !ok {
			return fmt.Errorf("failed to unmarshal buff: %w", ErrMalFormedG2Elem)
		}
	}

	return nil
}

// Equals check if c == cttbe.
// c == cttbe if
//   - c.InG1 == cttbe.InG1
//   - c.C1~c.C6 == cttbe.C1~cttbe.C6
func (c *Cttbe) Equals(cttbe *Cttbe) bool {
	if c.InG1 != cttbe.InG1 {
		return false
	}

	if c.InG1 {
		return utils.Equals(c.C1.(*bn.G1), cttbe.C1.(*bn.G1)) &&
			utils.Equals(c.C2.(*bn.G1), cttbe.C2.(*bn.G1)) &&
			utils.Equals(c.C3.(*bn.G1), cttbe.C3.(*bn.G1)) &&
			utils.Equals(c.C4.(*bn.G1), cttbe.C4.(*bn.G1)) &&
			utils.Equals(c.C5.(*bn.G1), cttbe.C5.(*bn.G1)) &&
			utils.Equals(c.C6.(*bn.G1), cttbe.C6.(*bn.G1))
	} else {
		return utils.Equals(c.C1.(*bn.G2), cttbe.C1.(*bn.G2)) &&
			utils.Equals(c.C2.(*bn.G2), cttbe.C2.(*bn.G2)) &&
			utils.Equals(c.C3.(*bn.G2), cttbe.C3.(*bn.G2)) &&
			utils.Equals(c.C4.(*bn.G2), cttbe.C4.(*bn.G2)) &&
			utils.Equals(c.C5.(*bn.G2), cttbe.C5.(*bn.G2)) &&
			utils.Equals(c.C6.(*bn.G2), cttbe.C6.(*bn.G2))
	}
}

// AudClue 审计线索，即auditing clue
type AudClue struct {
	id       uint64
	inG1     bool // true if in G1 and false in G2
	ac1, ac2 any
}

// Parameters TTBE初始化参数
type Parameters struct {
	TPK  *TPK
	TSKs []*TSK
	TVKs []*TVK
}
