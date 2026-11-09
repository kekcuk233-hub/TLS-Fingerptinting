package tlsdata

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// Функция для слияния десятичных данных в нужную форму
// Дясятичные значения через "-"
func joinDec(data []uint16) string {
	s := make([]string, 0, len(data))
	for _, d := range data {
		s = append(s, strconv.Itoa(int(d)))
	}
	return strings.Join(s, "-")
}

// JA3 принимает тело handshake-сообщения ClientHello (после 4-байтного
// заголовка handshake) и возвращает исходную строку JA3 и её MD5.
func JA3(ch *clientHello) (Fingerprint, error) {
	var (
		exts    []uint16
		curves  []uint16
		formats []uint16
		err     error
	)

	for _, e := range ch.extensions {
		if IsGREASE(e.tp) {
			continue
		}
		exts = append(exts, e.tp) // порядок как в пакете, без сортировки

		switch e.tp {
		case 0x000a: // supported_groups: 2 байта длины + группы по 2 байта
			if curves, err = listOf(e.b, 2, 2); err != nil {
				return Fingerprint{}, err
			}
		case 0x000b: // ec_point_formats: 1 байт длины + форматы по 1 байту
			if formats, err = listOf(e.b, 1, 1); err != nil {
				return Fingerprint{}, err
			}
		}
	}

	raw := strings.Join([]string{
		strconv.Itoa(int(ch.version)),
		joinDec(withoutGrease(ch.ciphers)),
		joinDec(exts),
		joinDec(withoutGrease(curves)),
		joinDec(formats),
	}, ",")

	sum := md5.Sum([]byte(raw))
	return Fingerprint{
		Hash: hex.EncodeToString(sum[:]),
		Raw:  raw,
	}, nil
}

