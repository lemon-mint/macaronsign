package macaronsign

import "golang.org/x/crypto/sha3"

//Signer : Signature generator
type Signer struct {
	EXP     int64
	encKey  [32]byte
	signKey [32]byte
	encV    int
	signV   int
}

type header struct {
	Version int   `json:"version"`
	Exp     int64 `json:"exp"`
}

type payload struct {
	Body    string `json:"body"`
	BodyLen int    `json:"len"`
}

//NewSigner : make new signer object
func NewSigner(Expiry int64, key []byte, EncVersion int, SignVersion int) Signer {
	digest := sha3.Sum512(key)
	digest = sha3.Sum512(digest[:])
	digest = sha3.Sum512(digest[:])
	digest = sha3.Sum512(digest[:])
	digest = sha3.Sum512(digest[:])
	var encK, signK [32]byte
	copy(encK[:], digest[:32])
	copy(signK[:], digest[32:])
	return Signer{
		EXP:     Expiry,
		encKey:  encK,
		signKey: signK,
		encV:    EncVersion,
		signV:   SignVersion,
	}
}
