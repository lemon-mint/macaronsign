package macaronsign

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

func (s Signer) signData(data []byte) []byte {
	sig := s.gensig(data)
	return []byte(urlsafe.EncodeToString(data) + "." + urlsafe.EncodeToString(sig))
}

//ErrBadSignature : This error occurs when the signature values do not match.
var ErrBadSignature error = errors.New("bad signature")

func (s Signer) verifyData(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("encoding error")
	}
	dataWithSig := string(data)
	parts := strings.Split(dataWithSig, ".")
	if len(parts) != 2 {
		return nil, errors.New("encoding error")
	}
	DataPart, err := urlsafe.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	Sigpart, err := urlsafe.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	//if subtle.ConstantTimeCompare(s.gensig(DataPart), Sigpart) != 1 {
	//	return DataPart, ErrBadSignature
	//}
	if !bytes.Equal(s.gensig(DataPart), Sigpart) {
		return DataPart, ErrBadSignature
	}
	return DataPart, nil
}

//SignAndEncrypt : Signs the input data and returns the encrypted result
func (s Signer) SignAndEncrypt(data []byte) string {
	nonce := make([]byte, 16)
	io.ReadFull(rand.Reader, nonce)
	encrypted := s.encrypt(s.signData(s.pack(data)), nonce)
	return urlsafe.EncodeToString(encrypted) + "." + urlsafe.EncodeToString(nonce)
}
