package groth

import (
	"errors"
	"fmt"

	bn "github.com/cloudflare/bn256"
)

var (
	ErrEmptyMsg            = errors.New("empty input message")
	ErrIllegalMsgType      = errors.New("illegal message type")
	ErrInconsistentMsgType = errors.New("inconsistent message type")
)

// Message Groth签名消息封装
type Message struct {
	InG1 bool
	ms   []any
}

// NewMessage 创建新的Groth签名消息
// ms不能为空，且ms中的元素必须同时为 *bn.G1 或者同时为 *bn.G2
func NewMessage(ms []any) (*Message, error) {
	const prefix = "failed to generate new groth message"
	if len(ms) == 0 {
		return nil, fmt.Errorf("%s: %w", prefix, ErrEmptyMsg)
	}

	var InG1 bool
	for i, m := range ms {
		_, ok1 := m.(*bn.G1)
		_, ok2 := m.(*bn.G2)
		if !ok1 && !ok2 {
			return nil, fmt.Errorf("%s: %w, at index %d", prefix, ErrIllegalMsgType, i)
		}
		if i == 0 {
			if ok1 {
				InG1 = true
			}
			continue
		}
		if InG1 != ok1 {
			return nil, fmt.Errorf("%s: %w, at index %d", prefix, ErrInconsistentMsgType, i)
		}
	}

	return &Message{InG1, ms}, nil
}

func (m *Message) Len() int {
	return len(m.ms)
}
