package tlsdata

// Fingerprint — результат вычисления отпечатка (JA3 или JA4).
type Fingerprint struct {
	Hash string // итоговый отпечаток: у JA3 — MD5, у JA4 — a_хеш(b)_хеш(c)
	Raw  string // исходная строка до хеширования
}
