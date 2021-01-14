package macaronsign

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

const signerVersion int = 0

func (s Signer) pack(data []byte) []byte {
	Head, _ := json.Marshal(header{
		Version: signerVersion,
		Exp:     s.EXP + time.Now().UTC().Unix(),
	})
	sHead := base64.RawURLEncoding.EncodeToString(Head)
	Body, _ := json.Marshal(payload{
		Body:    base64.RawURLEncoding.EncodeToString(data),
		BodyLen: len(data),
	})
	sBody := base64.RawURLEncoding.EncodeToString(Body)
	return []byte(sHead + "$" + sBody)
}
