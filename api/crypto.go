package api

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/sha512"
)

func zero(in []byte) {
	for i := range in {
		in[i] ^= in[i]
	}
}

const (
	scryN   = 32768
	scryR   = 8
	scryP   = 1
	scryLen = 224
)

func scryptPassphrase(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, scryN, scryR, scryP, scryLen)
}

func hmacSHA512(k, in []byte) []byte {
	h := hmac.New(sha512.New, k)
	h.Write(in)
	return h.Sum(nil)
}
