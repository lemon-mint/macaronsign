package macaronsign

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
)

func (s Signer) encrypt(data []byte, nonce []byte) (encrypted []byte) {
	if s.encV == 1 {
		b, _ := aes.NewCipher(s.encKey[:])
		c, _ := cipher.NewGCM(b)
		return c.Seal(nil, nonce[:12], data, nil)
	}
	return
}

func (s Signer) decrypt(data []byte, nonce []byte) (decrypted []byte, err error) {
	if s.encV == 1 {
		b, _ := aes.NewCipher(s.encKey[:])
		c, _ := cipher.NewGCM(b)
		return c.Open(nil, nonce[:12], data, nil)
	}
	return
}

func (s Signer) gensig(data []byte) (sig []byte) {
	if s.signV == 1 {
		hash := sha512.Sum512(data)
		mac := hmac.New(sha512.New384, s.signKey[:])
		mac.Write(hash[:])
		sig = mac.Sum(nil)
	}
	return
}
