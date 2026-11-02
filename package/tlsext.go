// Package tlsext содержит таблицу «номер → имя» для реестра IANA
// "TLS ExtensionType Values".
//
// Источник: https://www.iana.org/assignments/tls-extensiontype-values/
// (реестр tls-extensiontype-values-1, состояние на 2026-10-08).
package tlsext

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ExtensionType — значение поля extension_type (uint16) из TLS ClientHello/ServerHello.
type ExtensionType uint16

// extensionNames — таблица переходов: номер расширения → имя по реестру IANA.
// Диапазоны (Unassigned, Private Use, GREASE) обрабатываются в функции Name.
var extensionNames = map[ExtensionType]string{
	0:  "server_name",
	1:  "max_fragment_length",
	2:  "client_certificate_url",
	3:  "trusted_ca_keys",
	4:  "truncated_hmac",
	5:  "status_request",
	6:  "user_mapping",
	7:  "client_authz",
	8:  "server_authz",
	9:  "cert_type",
	10: "supported_groups", // ранее elliptic_curves
	11: "ec_point_formats",
	12: "srp",
	13: "signature_algorithms",
	14: "use_srtp",
	15: "heartbeat",
	16: "application_layer_protocol_negotiation",
	17: "status_request_v2",
	18: "signed_certificate_timestamp",
	19: "client_certificate_type",
	20: "server_certificate_type",
	21: "padding",
	22: "encrypt_then_mac",
	23: "extended_main_secret", // ранее extended_master_secret
	24: "token_binding",
	25: "cached_info",
	26: "tls_lts",
	27: "compress_certificate",
	28: "record_size_limit",
	29: "pwd_protect",
	30: "pwd_clear",
	31: "password_salt",
	32: "ticket_pinning",
	33: "tls_cert_with_extern_psk",
	34: "delegated_credential",
	35: "session_ticket", // ранее SessionTicket TLS
	36: "TLMSP",
	37: "TLMSP_proxying",
	38: "TLMSP_delegate",
	39: "supported_ekt_ciphers",
	40: "Reserved",
	41: "pre_shared_key",
	42: "early_data",
	43: "supported_versions",
	44: "cookie",
	45: "psk_key_exchange_modes",
	46: "Reserved",
	47: "certificate_authorities",
	48: "oid_filters",
	49: "post_handshake_auth",
	50: "signature_algorithms_cert",
	51: "key_share",
	52: "transparency_info",
	53: "connection_id (deprecated)",
	54: "connection_id",
	55: "external_id_hash",
	56: "external_session_id",
	57: "quic_transport_parameters",
	58: "ticket_request",
	59: "dnssec_chain",
	60: "sequence_number_encryption_algorithms",
	61: "rrc",
	62: "tls_flags",

	64768: "ech_outer_extensions",
	65037: "encrypted_client_hello",
	65281: "renegotiation_info",
}

// Name возвращает имя расширения по его номеру.
// Для значений, которых нет в реестре, возвращает описание диапазона
// (GREASE, Private Use) или "Unassigned(N)".String()
func Name(v uint16) string {
	if name, ok := extensionNames[ExtensionType(v)]; ok {
		return name
	}
	switch {
	case IsGREASE(v):
		return "Reserved (GREASE)" // RFC 8701: 0x0A0A, 0x1A1A, ..., 0xFAFA
	case v >= 65280: // 65280, 65282–65535 (65281 уже в таблице)
		return "Reserved for Private Use"
	default:
		return fmt.Sprintf("Unassigned(%d)", v)
	}
}

// String позволяет использовать ExtensionType в fmt/log напрямую.
func (e ExtensionType) String() string { return Name(uint16(e)) }

// isGREASE проверяет шаблон 0xNANA, где N — любая тетрада (RFC 8701).
func IsGREASE(v uint16) bool {
	return v&0x0F0F == 0x0A0A && v>>8 == v&0xFF
}

// ---------------------------------------------------------------------------
// Справочники значений (реестры IANA)
// ---------------------------------------------------------------------------

// namedGroups — реестр "TLS Supported Groups" (расширения 10 supported_groups и 51 key_share).
var namedGroups = map[uint16]string{
	1: "sect163k1", 2: "sect163r1", 3: "sect163r2", 4: "sect193r1", 5: "sect193r2",
	6: "sect233k1", 7: "sect233r1", 8: "sect239k1", 9: "sect283k1", 10: "sect283r1",
	11: "sect409k1", 12: "sect409r1", 13: "sect571k1", 14: "sect571r1",
	15: "secp160k1", 16: "secp160r1", 17: "secp160r2", 18: "secp192k1", 19: "secp192r1",
	20: "secp224k1", 21: "secp224r1", 22: "secp256k1",
	23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
	26: "brainpoolP256r1", 27: "brainpoolP384r1", 28: "brainpoolP512r1",
	29: "x25519", 30: "x448",
	31: "brainpoolP256r1tls13", 32: "brainpoolP384r1tls13", 33: "brainpoolP512r1tls13",
	34: "GC256A", 35: "GC256B", 36: "GC256C", 37: "GC256D",
	38: "GC512A", 39: "GC512B", 40: "GC512C", 41: "curveSM2",
	256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
	512: "MLKEM512", 513: "MLKEM768", 514: "MLKEM1024",
	4587:  "SecP256r1MLKEM768",
	4588:  "X25519MLKEM768",
	4589:  "SecP384r1MLKEM1024",
	25497: "X25519Kyber768Draft00",    // устаревший пред-стандартный гибрид
	25498: "SecP256r1Kyber768Draft00", // устаревший пред-стандартный гибрид
	65281: "arbitrary_explicit_prime_curves (deprecated)",
	65282: "arbitrary_explicit_char2_curves (deprecated)",
}

// signatureSchemes — реестр "TLS SignatureScheme" (расширения 13 и 50).
var signatureSchemes = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0203: "ecdsa_sha1",
	0x0301: "rsa_sha224",
	0x0302: "dsa_sha224",
	0x0303: "ecdsa_sha224",
	0x0401: "rsa_pkcs1_sha256",
	0x0402: "dsa_sha256",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0420: "rsa_pkcs1_sha256_legacy",
	0x0501: "rsa_pkcs1_sha384",
	0x0502: "dsa_sha384",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0520: "rsa_pkcs1_sha384_legacy",
	0x0601: "rsa_pkcs1_sha512",
	0x0602: "dsa_sha512",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0620: "rsa_pkcs1_sha512_legacy",
	0x0704: "eccsi_sha256",
	0x0705: "iso_ibs1",
	0x0706: "iso_ibs2",
	0x0707: "iso_chinese_ibs",
	0x0708: "sm2sig_sm3",
	0x0709: "gostr34102012_256a",
	0x070A: "gostr34102012_256b",
	0x070B: "gostr34102012_256c",
	0x070C: "gostr34102012_256d",
	0x070D: "gostr34102012_512a",
	0x070E: "gostr34102012_512b",
	0x070F: "gostr34102012_512c",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080A: "rsa_pss_pss_sha384",
	0x080B: "rsa_pss_pss_sha512",
	0x081A: "ecdsa_brainpoolP256r1tls13_sha256",
	0x081B: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081C: "ecdsa_brainpoolP512r1tls13_sha512",
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",
}

// ecPointFormats — реестр "TLS EC Point Formats" (расширение 11).
var ecPointFormats = map[uint16]string{
	0: "uncompressed",
	1: "ansiX962_compressed_prime",
	2: "ansiX962_compressed_char2",
}

// pskModes — реестр "TLS PskKeyExchangeMode" (расширение 45).
var pskModes = map[uint16]string{
	0: "psk_ke",
	1: "psk_dhe_ke",
}

// protocolVersions — версии протокола (расширение 43 supported_versions).
var protocolVersions = map[uint16]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
	0xFEFF: "DTLS 1.0",
	0xFEFD: "DTLS 1.2",
	0xFEFC: "DTLS 1.3",
}

// ---------------------------------------------------------------------------
// Общие вспомогательные функции
// ---------------------------------------------------------------------------

// item форматирует одно значение: "x25519(0x001d)" или "GREASE(0x2a2a)".
func item(v uint16, names map[uint16]string, width int) string {
	format := "%s(0x%04x)"
	if width == 1 {
		format = "%s(0x%02x)"
	}
	if n, ok := names[v]; ok {
		return fmt.Sprintf(format, n, v)
	}
	if width == 2 && IsGREASE(v) {
		return fmt.Sprintf(format, "GREASE", v)
	}
	return fmt.Sprintf(format, "unknown", v)
}

// Данная функция возвращает имя serverName
func getServerName(data []byte) (string, error) {
	size := int(binary.BigEndian.Uint16(data[0:]))
	if size != len(data)-2 {
		return "", fmt.Errorf("Длина списка %d не совпадает с реальной %d", size, len(data))
	}
	server_name_type := string(data[2])

	off := 3
	server_name_size := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	server_name := fmt.Sprintf("%s", data[off:off+server_name_size])

	return fmt.Sprintf("Тип имени сервера: %s | Имя сервера: %s", server_name_type, server_name), nil

}

// parseList разбирает структуру "длина списка (prefixLen байт) + элементы по itemLen байт".
// prefixLen: 1 или 2, itemLen: 1 или 2.
func parseList(data []byte, prefixLen, itemLen int, names map[uint16]string) (string, error) {
	if len(data) < prefixLen {
		return "", fmt.Errorf("слишком короткие данные: %d байт, нужен префикс длины %d", len(data), prefixLen)
	}

	listLen := int(data[0])
	if prefixLen == 2 {
		listLen = int(data[0])<<8 | int(data[1])
	}

	body := data[prefixLen:]
	if listLen != len(body) {
		return "", fmt.Errorf("длина списка %d не совпадает с реальной %d", listLen, len(body))
	}
	if listLen%itemLen != 0 {
		return "", fmt.Errorf("длина списка %d не кратна размеру элемента %d", listLen, itemLen)
	}

	parts := make([]string, 0, listLen/itemLen)
	for i := 0; i < len(body); i += itemLen {
		var v uint16
		if itemLen == 1 {
			v = uint16(body[i])
		} else {
			v = uint16(body[i])<<8 | uint16(body[i+1])
		}
		parts = append(parts, item(v, names, itemLen))
	}
	return "[" + strings.Join(parts, ", ") + "]", nil
}

func hexFallback(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

// ---------------------------------------------------------------------------
// Парсеры отдельных расширений
// ---------------------------------------------------------------------------

// Parser разбирает тело расширения (поле extension_data) в читаемую строку.
type Parser func(data []byte) (string, error)

func parseServerName(d []byte) (string, error)      { return getServerName(d) }
func parseSupportedGroups(d []byte) (string, error) { return parseList(d, 2, 2, namedGroups) }
func parseSignatureAlgs(d []byte) (string, error)   { return parseList(d, 2, 2, signatureSchemes) }
func parseECPointFormats(d []byte) (string, error)  { return parseList(d, 1, 1, ecPointFormats) }
func parsePSKModes(d []byte) (string, error)        { return parseList(d, 1, 1, pskModes) }

// parseSupportedVersions: в ClientHello это список (1 байт длины + версии по 2 байта),
// в ServerHello — ровно одна версия (2 байта без префикса).
func parseSupportedVersions(d []byte) (string, error) {
	if len(d) == 2 {
		v := uint16(d[0])<<8 | uint16(d[1])
		return "selected " + item(v, protocolVersions, 2), nil
	}
	return parseList(d, 1, 2, protocolVersions)
}

// parsers — таблица «тип расширения → парсер». Для типов, которых здесь нет,
// Decode вернёт hex. Чтобы поддержать новое расширение, добавь сюда строку.
var parsers = map[ExtensionType]Parser{
	0:  parseServerName,
	10: parseSupportedGroups,
	11: parseECPointFormats,
	13: parseSignatureAlgs,
	43: parseSupportedVersions,
	45: parsePSKModes,
	50: parseSignatureAlgs, // signature_algorithms_cert — тот же формат
}

// Decode возвращает расшифрованное тело расширения типа t.
// Если парсера нет, возвращает hex; если данные некорректны — hex и описание ошибки.
func Decode(t uint16, data []byte) string {
	p, ok := parsers[ExtensionType(t)]
	if !ok {
		return hexFallback(data)
	}

	s, err := p(data)
	if err != nil {
		return fmt.Sprintf("%s (ошибка разбора: %v)", hexFallback(data), err)
	}
	return s
}
