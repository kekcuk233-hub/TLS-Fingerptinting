package tlsdata

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

var errShort = errors.New("ClientHello обрезан или имеет неверную длину")

// reader — курсор по срезу с «залипающей» ошибкой: после первого выхода за границы
// все последующие чтения возвращают нули, а ошибку проверяем один раз в конце.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n > len(r.b) {
		r.err = errShort
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() int {
	if b := r.take(1); b != nil {
		return int(b[0])
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func joinU16(v []uint16) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(int(x))
	}
	return strings.Join(s, "-")
}
