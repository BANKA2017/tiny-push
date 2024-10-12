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
	mac.Write(ciphertext)
	return mac.Sum(nil)
}

func GetAESGCMNonceAndCekAndContent(subscriptionPublicKey *ecdh.PublicKey, auth_secret []byte, eccKeyData *ecdh.PrivateKey, salt []byte) ([]byte, []byte, []byte) {
	subscriptionPublicKeyBuffer := subscriptionPublicKey.Bytes()
	ecdh_secret, _ := eccKeyData.ECDH(subscriptionPublicKey)
	publishPublicKeyBuffer := eccKeyData.PublicKey().Bytes()

	context := ConcatBuffer([]byte("P-256\x00"), []byte{0, 65}, subscriptionPublicKeyBuffer, []byte{0, 65}, publishPublicKeyBuffer)

	auth_info := []byte("Content-Encoding: auth\x00")

	PRK := HKDF(auth_secret, ecdh_secret, auth_info, 32)

	cek_info := append([]byte("Content-Encoding: aesgcm\x00"), context...)
	cek := HKDF(salt, PRK, cek_info, 16)

	nonce_info := append([]byte("Content-Encoding: nonce\x00"), context...)
	nonce := HKDF(salt, PRK, nonce_info, 12)

	return nonce, cek, context
}

func GetAES128GCMNonceAndCekAndContent(subscriptionPublicKey *ecdh.PublicKey, auth_secret []byte, eccKeyData *ecdh.PrivateKey, salt []byte) ([]byte, []byte, []byte) {
	subscriptionPublicKeyBuffer := subscriptionPublicKey.Bytes()

	ecdh_secret, _ := eccKeyData.ECDH(subscriptionPublicKey)
	publishPublicKeyBuffer := eccKeyData.PublicKey().Bytes()

	key_info := ConcatBuffer([]byte("WebPush: info\x00"), subscriptionPublicKeyBuffer, publishPublicKeyBuffer)

	PRK := HKDF(auth_secret, ecdh_secret, key_info, 32)

	cek_info := []byte("Content-Encoding: aes128gcm\x00")
	cek := HKDF(salt, PRK, cek_info, 16)

	nonce_info := []byte("Content-Encoding: nonce\x00")
	nonce := HKDF(salt, PRK, nonce_info, 12)

	return nonce, cek, key_info
}

func Encrypt(nonce, contentEncryptionKey, payload []byte, encoding string) []byte {
	block, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	if encoding == "aes128gcm" {
		payload = append(payload, 0x02)
	} else {
		payload = append([]byte("\x00\x00"), payload...)
	}

	ciphertext := aead.Seal(nil, nonce, payload, nil)

	return ciphertext
}

func HKDF(salt, ikm, info []byte, length int) []byte {
	key := GenHMAC256(ikm, salt)
	signature := GenHMAC256(ConcatBuffer(info, []byte{0x01}), key)
	return signature[0:length]
}
