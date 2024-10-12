package functions

import (
	"crypto/ecdh"
	"encoding/base64"
	"net/url"
	"time"
)

var Now = time.Now()

func UpdateNow() {
	Now = time.Now()
}

func VerifyURL(_url string) bool {
	_, err := url.ParseRequestURI(_url)
	return err == nil
}

func VerifyP256dh(_p256dh string) bool {
	decodedP256DH, err := base64.URLEncoding.DecodeString(_p256dh)
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
	decodedAuth, err := base64.URLEncoding.DecodeString(_auth)
	if err != nil {
		return false
	}
	if len(decodedAuth) != 16 {
		return false
	}
	return true
}

func ConcatBuffer(byteData ...[]byte) []byte {
	tmpBuffer := []byte{}
	for _, buf := range byteData {
		tmpBuffer = append(tmpBuffer, buf...)
	}
	return tmpBuffer
}

func VariableWrapper[T any](anyValue T) T {
	return anyValue
}

func VariablePtrWrapper[T any](anyValue T) *T {
	return &anyValue
}
