package tlsext

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
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

// JA3 принимает тело handshake-сообщения ClientHello (после 4-байтного
// заголовка handshake) и возвращает исходную строку JA3 и её MD5.
func JA3(data []byte) (raw, hash string, err error) {
	r := &reader{b: data}

	version := r.u16() // legacy_version
	r.take(32)         // random
	r.take(r.u8())     // session_id
	//fmt.Printf("version: %v\n", version)

	// cipher_suites: длина (2 байта) + значения по 2 байта
	cs := r.take(int(r.u16()))
	r.take(r.u8()) // compression_methods

	var exts []byte
	if len(r.b) > 0 { // у очень старых клиентов расширений нет
		exts = r.take(int(r.u16()))
	}
	if r.err != nil {
		return "", "", r.err
	}
	if len(cs)%2 != 0 {
		return "", "", errShort
	}

	var ciphers []uint16
	for i := 0; i < len(cs); i += 2 {
		if c := binary.BigEndian.Uint16(cs[i:]); !IsGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	//fmt.Println("ciphers done")

	var extensions, curves, formats []uint16
	er := &reader{b: exts}
	for len(er.b) > 0 {
		typ := er.u16()
		body := er.take(int(er.u16()))
		if er.err != nil {
			return "", "", er.err
		}

		if !IsGREASE(typ) {
			extensions = append(extensions, typ)
		}

		switch typ {
		case 10: // supported_groups: длина списка (2 байта) + группы по 2 байта
			if len(body) < 2 {
				return "", "", errShort
			}
			list := body[2:]
			if int(binary.BigEndian.Uint16(body)) != len(list) || len(list)%2 != 0 {
				return "", "", errShort
			}
			for i := 0; i < len(list); i += 2 {
				if g := binary.BigEndian.Uint16(list[i:]); !IsGREASE(g) {
					curves = append(curves, g)
				}
			}
		case 11: // ec_point_formats: длина списка (1 байт) + форматы по 1 байту
			if len(body) < 1 || int(body[0]) != len(body)-1 {
				return "", "", errShort
			}
			for _, f := range body[1:] {
				formats = append(formats, uint16(f))
			}
		}
	}

	raw = strings.Join([]string{
		strconv.Itoa(int(version)),
		joinU16(ciphers),
		joinU16(extensions),
		joinU16(curves),
		joinU16(formats),
	}, ",")

	sum := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

// JA4 принимает тело handshake-сообщения ClientHello (после 4-байтного
// заголовка handshake) и возвращает исходную строку JA4_r и преобразованную JA4.
// Пока работает только с TCP
func JA4(data []byte) (ja4_r string, ja4 string, err error) {
	r := &reader{b: data}

	// t для TCP
	protocol := 't'

	version := r.u16() // legacy_version
	r.take(32)         // random
	r.take(r.u8())     // session_id

	println("version: ", version)

	//ciphers
	cs := r.take(int(r.u16()))

	r.take(r.u8()) //compression methods

	var exts []byte
	if len(r.b) > 0 { // у очень старых клиентов расширений нет
		exts = r.take(int(r.u16()))
	}
	if r.err != nil {
		return "", "", r.err
	}
	if len(cs)%2 != 0 {
		return "", "", errShort
	}

	//a part
	//Самый наибольший из supported versions | Если нет, то client version
	biggest_supported_version := uint16(0)
	SNI := "i"
	e_amount := 0
	er := &reader{b: exts}
	for len(er.b) > 0 {
		typ := er.u16()
		body := r.take(int(er.u16()))

		if er.err != nil {
			return "", "", er.err
		}

		if typ == 0 {
			SNI = "d"
		}

		if typ == 10 {
			if len(body) < 2 {
				return "", "", errShort
			}
			list := body[2:]
			if int(binary.BigEndian.Uint16(body)) != len(list) || len(list)%2 != 0 {
				return "", "", errShort
			}
			for i := 0; i < len(list); i += 2 {
				if g := binary.BigEndian.Uint16(list[i:]); !IsGREASE(g) {
					if biggest_supported_version < g {
						biggest_supported_version = g
					}
				}
			}
		}
		e_amount++
	}
	println("BigSP: ", biggest_supported_version)

	//Число шифров
	c_amount := 0
	for i := 0; i < len(cs); i += 2 {
		if c := binary.BigEndian.Uint16(cs[i:]); !IsGREASE(c) {
			c_amount++
		}
	}

	a_part := string(protocol)+string(biggest_supported_version)+SNI+string(c_amount) + string(e_amount)

	return a_part, a_part, nil
}
