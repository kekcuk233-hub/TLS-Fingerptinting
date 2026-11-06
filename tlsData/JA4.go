package tlsdata

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
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

func sha256_12(data string) string {
	hash := sha256.Sum256([]byte(data))
	result := hex.EncodeToString(hash[:])

	return result[:12]
}

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

	//Соединить все для части а
	a_part := "t" +
		ja4Version(max_supported_group) +
		sni + strconv.Itoa(amount_of_ciphers) +
		strconv.Itoa(amount_of_extensions) +
		alpn

	//Часть b - sha256 от отсортированных шифров через запятую
	sorted_ciphers := ch.ciphers
	slices.Sort(sorted_ciphers)
	var b_part strings.Builder
	for i, c := range sorted_ciphers {
		if i < amount_of_ciphers-1 {
			fmt.Fprintf(&b_part, "%04x,", c)
		} else {
			fmt.Fprintf(&b_part, "%04x", c) // В конце без ","
		}
	}

	// С Часть
	var c_ext []uint16
	var sign_alg strings.Builder
	for _, ext := range ch.extensions {
		if ext.tp != 00 && ext.tp != 16 {
			c_ext = append(c_ext, ext.tp)
		}
		// add signature algorithms
		if ext.tp == 13 {
			for i := 2; i < len(ext.b); i += 2 {
				if d := binary.BigEndian.Uint16(ext.b[i:]); !IsGREASE(d) {
					if i < len(ext.b)-2 {
						fmt.Fprintf(&sign_alg, "%04x,", d)
					} else {
						fmt.Fprintf(&sign_alg, "%04x", d)
					}

				}

			}
		}
	}

	var ext_str strings.Builder
	slices.Sort(c_ext)
	for i, ext := range c_ext {
		if i < len(c_ext)-1 {
			fmt.Fprintf(&ext_str, "%04x,", ext)
		} else {
			fmt.Fprintf(&ext_str, "%04x_", ext)
		}
		fmt.Println("ext: ", ext)
	}

	c_part := ext_str.String() + sign_alg.String()

	return (a_part + "_" + sha256_12(b_part.String()) + "_" + sha256_12(c_part)), "", nil
}
