package tlsdata

import (
	"encoding/binary"
	"fmt"
)

type extension struct {
	tp uint16
	b  []byte
}

// Хранит в себе все данные clientHello
// ciphers без Grease
// extensions с Grease
type clientHello struct {
	version    uint16
	ciphers    []uint16    // Без Grease
	extensions []extension // С Grease
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
		if c := binary.BigEndian.Uint16(cs[i:]); !IsGREASE(c) {
			h.ciphers = append(h.ciphers, c)
		}
	}

	//Добавляем расширения
	er := &reader{b: exts}
	for len(er.b) > 0 {
		tp := er.u16()
		body := er.take(int(er.u16()))
		fmt.Printf("%#x\n", body)

		if er.err != nil {
			return nil, er.err
		}

		h.extensions = append(h.extensions, extension{tp, body})
	}

	return h, nil
}
