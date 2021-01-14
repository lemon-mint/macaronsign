package macaronsign

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

const signerVersion int = 0

var urlsafe = base64.RawURLEncoding

func (s Signer) pack(data []byte) []byte {
	salt := make([]byte, 16)
	Head, _ := json.Marshal(header{
		Version: signerVersion,
		Exp:     s.EXP + time.Now().UTC().Unix(),
		Salt:    urlsafe.EncodeToString(salt),
	})
	sHead := urlsafe.EncodeToString(Head)
	Body, _ := json.Marshal(payload{
		Body:    urlsafe.EncodeToString(data),
		BodyLen: len(data),
	})
	sBody := urlsafe.EncodeToString(Body)
	return []byte(sHead + "$" + sBody)
}

//ErrExpired : Token has expired
var ErrExpired error = errors.New("expired token")

func (s Signer) unpack(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("encoding error")
	}
	sData := string(data)
	parts := strings.Split(sData, "$")
	if len(parts) != 2 {
		return nil, errors.New("encoding error")
	}
	HeadPart, err := urlsafe.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	Bodypart, err := urlsafe.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	body := new(payload)
	head := new(header)
	err = json.Unmarshal(HeadPart, head)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(Bodypart, body)
	if err != nil {
		return nil, err
	}
	if head.Exp < time.Now().UTC().Unix() {
		bodyByte, err := urlsafe.DecodeString(body.Body)
		if err != nil {
			return nil, ErrExpired
		}
		return bodyByte, ErrExpired
	}
	bodyByte, err := urlsafe.DecodeString(body.Body)
	if err != nil {
		return nil, err
	}
	if len(bodyByte) != body.BodyLen {
		return bodyByte, errors.New("Wrong Body length")
	}
	return bodyByte, nil
}
