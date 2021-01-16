package macaronsign

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/lemon-mint/LEA/golea"
)

func (s Signer) encrypt(data []byte, nonce []byte) (encrypted []byte) {
	if s.encV == 0 {
		return data
	} else if s.encV == 1 {
		b, _ := aes.NewCipher(s.encKey[:])
		c, _ := cipher.NewGCM(b)
		return c.Seal(nil, nonce[:12], data, nil)
	} else if s.encV == 2 {
		b, _ := golea.NewCipher(s.encKey[:])
		c, _ := cipher.NewGCM(b)
		return c.Seal(nil, nonce[:12], data, nil)
	} else if s.encV == 3 {
		cipher, _ := chacha20poly1305.NewX(s.encKey[:])
		return cipher.Seal(nil, nonce[:cipher.NonceSize()], data, nil)
	}
	return
}

func (s Signer) decrypt(data []byte, nonce []byte) (decrypted []byte, err error) {
	if s.encV == 0 {
		return data, nil
	} else if s.encV == 1 {
		b, _ := aes.NewCipher(s.encKey[:])
		c, _ := cipher.NewGCM(b)
		return c.Open(nil, nonce[:12], data, nil)
	} else if s.encV == 2 {
		b, _ := golea.NewCipher(s.encKey[:])
		c, _ := cipher.NewGCM(b)
		return c.Open(nil, nonce[:c.NonceSize()], data, nil)
	} else if s.encV == 3 {
		cipher, _ := chacha20poly1305.NewX(s.encKey[:])
		return cipher.Open(nil, nonce[:cipher.NonceSize()], data, nil)
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
	if s.signV == 2 {
		hash := sha512.Sum512(data)
		mac := hmac.New(sha512.New, s.signKey[:])
		mac.Write(hash[:])
		sig = mac.Sum(nil)
	}
	return
}
