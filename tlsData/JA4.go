package tlsdata

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// Выдает версию в 10 формате
func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

// Какие символы содержатся в названии протокола.
// По спецификации RFC 7301, ALPN содержит ASCII-символы.
func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// Получение значения alpn - первый и последний символ первого протокола
// 2 длина массива -> 1 длина протокола -> 2 протокол
func getALPN(body []byte) string {
	if len(body) < 2 || (int(binary.BigEndian.Uint16(body)) != len(body)-2) {
		return "00"
	}

	list := body[2:]
	if len(list) == 0 {
		return "00"
	}

	n := int(list[0])
	if n > len(list)-1 {
		return "00"
	}

	first, last := list[1], list[n]

	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}

	h := hex.EncodeToString(list[1 : 1+n])
	return string([]byte{h[0], h[n]})
}

func sha256_12(data string) string {
	if data == "" {
		return "000000000000"
	}

	hash := sha256.Sum256([]byte(data))

	return hex.EncodeToString(hash[:])[:12]
}

func hexString(v []uint16) string {
	s := make([]string, 0, len(v))
	for _, x := range v {
		s = append(s, fmt.Sprintf("%04x", x))
	}
	return strings.Join(s, ",")
}

// JA4 принимает тело handshake-сообщения ClientHello (после 4-байтного заголовка
// handshake) и возвращает отпечаток JA4: Hash — "a_хеш(b)_хеш(c)", Raw — то же
// со списками вместо хешей.
func JA4(ch *clientHello) (Fingerprint, error) {
	return ja4('t', ch)
}

// ja4 принимает символ протокола ('t', 'q', 'd'): для TCP, QUIC и DTLS
// Пока только с TCP
func ja4(proto byte, ch *clientHello) (Fingerprint, error) {
	//Получаем все шифры, убираем GREASE и сортируем
	ciphers := withoutGrease(ch.ciphers) // Обязательно делаем копию
	slices.Sort(ciphers)

	// Все необходимые переменные для работы с расширениями
	var (
		extCount int      // Количество расширений с SNI и ALPN
		extForC  []uint16 // Все типы расширений без SNI и ALPN
		signAlg  []uint16 // Алгоритмы подписи в исходном порядке
		maxVer   uint16
		sni      = byte('i')
		alpn     = "00"
		err      error
	)

	for _, ext := range ch.extensions {
		if IsGREASE(ext.tp) {
			continue
		}

		extCount++
		if ext.tp != 0x0000 && ext.tp != 0x0010 {
			extForC = append(extForC, ext.tp)
		}

		switch ext.tp {
		case 0x0000:
			sni = 'd'

		case 0x0010:
			alpn = getALPN(ext.b)

		case 0x002b:
			supVer, err := listOf(ext.b, 1, 2)
			if err != nil {
				return Fingerprint{}, err
			}
			supVer = withoutGrease(supVer)
			for _, x := range supVer {
				maxVer = max(maxVer, x)
			}

		case 0x000d:
			if signAlg, err = listOf(ext.b, 2, 2); err != nil {
				return Fingerprint{}, err
			}
		}

	}

	slices.Sort(extForC)
	signAlg = withoutGrease(signAlg)

	// Если нет supported_groups берем из ClientHello
	version := ch.version
	if maxVer != 0 {
		version = maxVer
	}

	a := fmt.Sprintf("%c%s%c%02d%02d%s",
		proto, ja4Version(version), sni, min(len(ciphers), 99), min(extCount, 99), alpn)

	b := hexString(ciphers)

	c := hexString(extForC)
	if c != "" && len(signAlg) > 0 { // "_" только если есть алгоритмы подписи
		c += "_" + hexString(signAlg)
	}

	return Fingerprint{
		Hash: a + "_" + sha256_12(b) + "_" + sha256_12(c),
		Raw:  a + "_" + b + "_" + c,
	}, nil
}
