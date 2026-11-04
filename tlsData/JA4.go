package tlsdata

import (
	"encoding/binary"
	"fmt"
	"strconv"
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

//

// Получение JA4. Возращает ja4, ja4_raw, error
func JA4(data []byte) (string, string, error) {
	ch, err := parseClientHello(data)
	if err != nil {
		return "", "", err
	}

	amount_of_ciphers := len(ch.ciphers)
	amount_of_extensions := len(ch.extensions)

	max_supported_group := uint16(0)
	sni := "i"
	var alpn string
	for _, ext := range ch.extensions {
		if ext.tp == 0 {
			sni = "d"
		}

		if ext.tp == 16 {
			size := uint16(ext.b[2]) // Пропускаем общий размер и выбираем размер первого
			alpn = string(ext.b[3]) + strconv.Itoa(int(ext.b[size]))
		}

		if ext.tp == 43 { // 43 - supported versions
			for i := 1; i < len(ext.b); i += 2 { // i = 1, чтобы пропустить размер
				current_version := binary.BigEndian.Uint16(ext.b[i:])
				if current_version > max_supported_group && !IsGREASE(current_version) {
					max_supported_group = current_version
				}
			}
		}
	}

	fmt.Println(amount_of_ciphers)
	fmt.Println(amount_of_extensions)

	a_part := "t" +
		ja4Version(max_supported_group) +
		sni + strconv.Itoa(amount_of_ciphers) +
		strconv.Itoa(amount_of_extensions) +
		alpn

	return a_part, "", nil
}
