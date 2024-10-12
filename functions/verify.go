package functions

import (
	"crypto/ecdh"
	"encoding/base64"
	"net/url"
)

func VerifyURL(_url string) bool {
	_, err := url.ParseRequestURI(_url)
	return err == nil
}

func VerifyP256dh(_p256dh string) bool {
	decodedP256DH, err := base64.RawURLEncoding.DecodeString(_p256dh)
	if err != nil {
		return false
	}

	if len(decodedP256DH) != 65 || decodedP256DH[0] != 0x04 {
		return false
	}

	_, err = ecdh.P256().NewPublicKey(decodedP256DH)
	return err == nil
}

func VerifyAuth(_auth string) bool {
	decodedAuth, err := base64.RawURLEncoding.DecodeString(_auth)
	if err != nil {
		return false
	}
	return len(decodedAuth) == 16
}
