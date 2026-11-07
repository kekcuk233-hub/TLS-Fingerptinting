package tlsdata

import "encoding/binary"

type extension struct {
	tp uint16
	b  []byte
}

// Хранит в себе все данные clientHello
// в исходном значении и с GREASE
type clientHello struct {
	version    uint16
	ciphers    []uint16
	extensions []extension
}

// Собираем данные для ClientHello
func parseClientHello(data []byte) (*clientHello, error) {
	r := &reader{b: data}
	h := &clientHello{}

	h.version = r.u16() //version
	r.take(32)          //skip random
	r.take(r.u8())      //skip session

	cs := r.take(int(r.u16())) //get ciphers
	r.take(r.u8())             //skip compression methods

	var exts []byte
	if len(r.b) > 0 { //У старых клиентов нет расширений
		exts = r.take(int(r.u16()))
	}

	if r.err != nil {
		return nil, r.err
	}

	if len(cs)%2 != 0 {
		return nil, errShort
	}

	//Добавляем шифры
	for i := 0; i < len(cs); i += 2 {
		h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(cs[i:]))
	}

	//Добавляем расширения
	er := &reader{b: exts}
	for len(er.b) > 0 {
		tp := er.u16()
		body := er.take(int(er.u16()))

		if er.err != nil {
			return nil, er.err
		}

		h.extensions = append(h.extensions, extension{tp, body})
	}

	return h, nil
}

// Функиция разбирает длину списка + элементы по size байт
// prefix - размер длины (1 или 2)
// size - размер данных (1 или 2)
func listOf(body []byte, prefix, size int) ([]uint16, error) {
	if len(body) < prefix {
		return nil, errShort
	}

	n := int(body[0])
	if prefix == 2 {
		n = int(binary.BigEndian.Uint16(body))
	}

	list := body[prefix:]
	if n != len(list) || n%2 != 0 {
		return nil, errShort
	}

	arr := make([]uint16, 0, n/size)
	for i := 0; i < n; i += 2 {
		if size == 1 {
			arr = append(arr, uint16(list[i]))
		} else {
			arr = append(arr, binary.BigEndian.Uint16(list[i:]))
		}
	}

	return arr, nil
}
