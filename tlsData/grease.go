package tlsdata

// Проверяет шаблон 0xNANA, где N — любая тетрада (RFC 8701):
// 0x0A0A, 0x1A1A, ..., 0xFAFA. Оба байта должны совпадать.
func IsGrease(v uint16) bool {
	return v&0x0F0F == 0x0A0A && v>>8 == v&0xFF
}

// Возвращает новый срез без GREASE
func withoutGrease(data []uint16) []uint16 {
	arr := make([]uint16, 0, len(data))
	for _, x := range data {
		if !IsGREASE(x) {
			arr = append(arr, x)
		}
	}
	return arr
}
