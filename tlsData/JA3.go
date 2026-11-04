package tlsdata

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

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
