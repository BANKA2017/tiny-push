package api

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/BANKA2017/tiny-push/functions"
	"github.com/BANKA2017/tiny-push/share"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func ApiPush(c echo.Context) error {
	now := functions.Now

	_uuid := c.Param("uuid")

	p256dh := c.FormValue("p256dh")
	endpoint := c.FormValue("endpoint")
	auth := c.FormValue("auth")
	message := c.FormValue("message")
	testMessage := c.FormValue("test") == "1"
	//isEncrypt := c.FormValue("encrypt") == "1"
	isAES128GCM := c.FormValue("encoding") == "aes128gcm"
	encoding := "aes128gcm"
	if !isAES128GCM {
		encoding = "aesgcm"
	}

	if message == "" && !testMessage {
		return c.JSON(http.StatusOK, ApiTemplate(403, "Empty message", false, "push"))
	}

	if uuid.Validate(_uuid) == nil {
		uuidData, err := functions.GetUUID(_uuid)
		if err != nil {
			return c.JSON(http.StatusOK, ApiTemplate(401, "Invalid UUID", false, "push"))
		}

		p256dh = uuidData.P256dh
		auth = uuidData.Auth
		endpoint = uuidData.Endpoint

		uuidData.LastUsed = int32(now.UnixMilli())
		uuidData.Count += 1
		err = functions.UpdateUUID(uuidData)
		if err != nil {
			log.Println(err)
		}
	}

	// TODO double check?
	if !functions.VerifyP256dh(p256dh) || !functions.VerifyAuth(auth) || !functions.VerifyURL(endpoint) {
		return c.JSON(http.StatusOK, ApiTemplate(401, "Invalid UUID/p256dh/auth/endpoint", false, "push"))
	}

	parsedURL, _ := url.ParseRequestURI(endpoint)
	aud := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	jwt, _ := functions.BuildJWT(share.ECCPrivateKey, aud, share.Vapid.Sub)

	decodedP256dh, _ := base64.RawURLEncoding.DecodeString(p256dh)
	p256dhPublicKey, _ := ecdh.P256().NewPublicKey(decodedP256dh)

	eccKeyData, _ := ecdh.P256().GenerateKey(rand.Reader)

	salt := make([]byte, 16)
	rand.Read(salt)

	var nonce []byte
	var cek []byte

	authBuffer, _ := base64.RawURLEncoding.DecodeString(auth)

	if isAES128GCM {
		nonce, cek, _ = functions.GetAES128GCMNonceAndCekAndContent(p256dhPublicKey, authBuffer, eccKeyData, salt)
	} else {
		nonce, cek, _ = functions.GetAESGCMNonceAndCekAndContent(p256dhPublicKey, authBuffer, eccKeyData, salt)
	}

	eccPublicKey := eccKeyData.PublicKey().Bytes()

	if message == "" {
		message = fmt.Sprintf("This is a test content🔔✅🎉😺\n%s (%d)", now.String(), now.UnixMilli())
	}

	signPayload := url.Values{}
	signPayload.Set("content", message)
	signPayload.Set("timestamp", strconv.Itoa(int(now.UnixMilli())))

	signBuffer, _ := functions.Sign(share.ECCPrivateKey, []byte(signPayload.Encode()))
	sign := base64.RawURLEncoding.EncodeToString(signBuffer)

	payloadObject := map[string]any{
		"content":   message,
		"sign":      sign,
		"timestamp": now.UnixMilli(),
		//"encrypt":   isEncrypt,
	}
	payloadJSON, _ := functions.JsonEncode(payloadObject)
	payload := functions.Encrypt(nonce, cek, payloadJSON, encoding)

	headers := make(map[string]string)
	headers["Content-Type"] = "application/octet-stream"
	headers["Content-Encoding"] = encoding
	headers["TTL"] = "60"

	if isAES128GCM {
		headers["Authorization"] = fmt.Sprintf("vapid t=%s,k=%s", jwt, functions.GetPublicKey(share.ECCPrivateKey))
		payload = functions.ConcatBuffer(salt, []byte("\x00\x00\x16\x00"), []byte{65}, eccPublicKey, payload)
		headers["Content-Length"] = strconv.Itoa(len(payload))
	} else {
		headers["Authorization"] = fmt.Sprintf("WebPush %s", jwt)
		headers["Crypto-Key"] = fmt.Sprintf("dh=%s;p256ecdsa=%s", strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(eccPublicKey), "=", ""), functions.GetPublicKey(share.ECCPrivateKey))
		headers["Encryption"] = fmt.Sprintf("salt=%s", strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(salt), "=", ""))
		headers["Content-Length"] = strconv.Itoa(len(payload))
	}

	resp, data, err := functions.Fetch(endpoint, "POST", payload, headers)
	if err != nil {
		return c.JSON(http.StatusOK, ApiTemplate(500, "Failed", false, "push"))
	}

	if _uuid != "" && slices.Contains([]int{404, 410}, resp.StatusCode) {
		// TODO ...
		functions.DeleteUUID(_uuid)
	}

	return c.JSON(http.StatusOK, ApiTemplate(resp.StatusCode, "OK", map[string]any{
		"status": resp.StatusCode,
		"text":   string(data),
	}, "push"))
}
