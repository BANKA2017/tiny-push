package functions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
)

type JWT struct {
	Content string
	Expire  int64
}

// ImportKey imports a JWK as an ECDSA private key.
func ImportKey(_privateKey string) (*ecdsa.PrivateKey, error) {
	dBytes, err := base64.RawURLEncoding.DecodeString(_privateKey)
	if err != nil {
		return nil, err
	}

	curve := elliptic.P256()

	d := new(big.Int).SetBytes(dBytes)

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     nil,
			Y:     nil,
		},
		D: d,
	}

	privateKey.X, privateKey.Y = curve.ScalarBaseMult(d.Bytes())

	return privateKey, nil
}

// GetPrivateKey retrieves the private key from JWK.
func GetPrivateKey(privateKey *ecdsa.PrivateKey) string {
	return strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(privateKey.D.Bytes()), "=", "")
}

// GetPublicKey retrieves or caches the public key derived from JWK.
func GetPublicKey(privateKey *ecdsa.PrivateKey) string {
	pk, _ := privateKey.PublicKey.ECDH()
	return strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(pk.Bytes()), "=", "")
}

var GlobalJWT sync.Map

type GlobalJWTContent struct {
	Content string
	Expire  int64
}

// BuildJWT builds a JWT token using the provided VAPID object and audience.
func BuildJWT(privateKey *ecdsa.PrivateKey, aud string, sub string) (string, error) {
	now := Now
	if jwt, exists := GlobalJWT.Load(aud); exists {
		j := jwt.(GlobalJWTContent)
		if j.Content != "" && j.Expire > now.UnixMilli() {
			return j.Content, nil
		}
	}

	if aud == "" {
		return "", errors.New("missing audience")
	}

	// Create the Claims
	claims := jwt.StandardClaims{
		Subject: sub,
		// NotBefore: now.Unix(),
		// IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Audience:  aud,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	ss, err := token.SignedString(privateKey)
	if err == nil {
		GlobalJWT.Store(aud, GlobalJWTContent{
			Content: ss,
			Expire:  now.Add(time.Minute * 30).UnixMilli(),
		})
	}

	return ss, err
}

// Sign signs the payload with the provided JWK key using ECDSA.
func Sign(privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

func GenHMAC256(ciphertext, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ciphertext))
	hmac := mac.Sum(nil)
	return hmac
}

func GetAESGCMNonceAndCekAndContent(subscriptionPublicKey *ecdh.PublicKey, auth []byte, privateKey *ecdsa.PrivateKey, salt []byte) ([]byte, []byte, []byte) {
	subscriptionPublicKeyBuffer := subscriptionPublicKey.Bytes()
	ecdhPrivateKey, _ := privateKey.ECDH()
	ecdh_secret, _ := ecdhPrivateKey.ECDH(subscriptionPublicKey)
	publishPublicKeyBuffer := ConcatBuffer([]byte{4}, privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes())

	auth_secret := auth

	context := []byte("P-256\x00")
	context = append(context, []byte{0, 65}...)
	context = append(context, subscriptionPublicKeyBuffer...)
	context = append(context, []byte{0, 65}...)
	context = append(context, publishPublicKeyBuffer...)

	auth_info := []byte("Content-Encoding: auth\x00")
	PRK_combine := GenHMAC256(ecdh_secret, auth_secret)
	IKM := GenHMAC256(append(auth_info, 0x01), PRK_combine)

	PRK := GenHMAC256(IKM, salt)

	cek_info := []byte("Content-Encoding: aesgcm\x00")
	cek_info = append(cek_info, context...)
	cek := GenHMAC256(append(cek_info, 0x01), PRK)[0:16]

	nonce_info := []byte("Content-Encoding: nonce\x00")
	nonce_info = append(nonce_info, context...)
	nonce := GenHMAC256(append(nonce_info, 0x01), PRK)[0:12]

	return nonce, cek, context
}

func GetAES128GCMNonceAndCekAndContent(subscriptionPublicKey *ecdh.PublicKey, auth []byte, privateKey *ecdsa.PrivateKey, salt []byte) ([]byte, []byte, []byte) {
	subscriptionPublicKeyBuffer := subscriptionPublicKey.Bytes()

	ecdhPrivateKey, _ := privateKey.ECDH()
	ecdh_secret, _ := ecdhPrivateKey.ECDH(subscriptionPublicKey)
	publishPublicKeyBuffer := ConcatBuffer([]byte{4}, privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes())

	auth_secret := auth

	key_info := []byte("WebPush: info\x00")
	key_info = append(key_info, subscriptionPublicKeyBuffer...)
	key_info = append(key_info, publishPublicKeyBuffer...)

	PRK_key := GenHMAC256(ecdh_secret, auth_secret)
	IKM := GenHMAC256(append(key_info, 0x01), PRK_key)

	PRK := GenHMAC256(IKM, salt)

	cek_info := []byte("Content-Encoding: aes128gcm\x00")
	cek := GenHMAC256(append(cek_info, 0x01), PRK)[0:16]

	nonce_info := []byte("Content-Encoding: nonce\x00")
	nonce := GenHMAC256(append(nonce_info, 0x01), PRK)[0:12]

	return nonce, cek, key_info
}

func Encrypt(nonce, contentEncryptionKey, content []byte, encoding string) []byte {

	block, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	payload := []byte{}

	if encoding == "aes128gcm" {
		payload = append(payload, 0x02)
	} else {
		tmp := []byte("\x00\x00")
		payload = append(tmp, payload...)
	}

	ciphertext := aead.Seal(nonce, nonce, payload, nil)

	return ciphertext

}
