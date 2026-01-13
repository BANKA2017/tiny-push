package api

import (
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BANKA2017/tiny-push/functions"
	"github.com/BANKA2017/tiny-push/model"
	"github.com/BANKA2017/tiny-push/share"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

type PushHeader struct {
	Encryption    string `header:"Encryption"`
	CryptoKey     string `header:"Crypto-Key"`
	Encoding      string `header:"Content-Encoding"`
	TTL           int    `header:"TTL"` // seconds
	Authorization string `header:"Authorization"`
	ContentLength int    `header:"Content-Length"`
}

func ParsePushHeaderKV(text string) map[string]string {
	kvMap := make(map[string]string)

	for _, kv := range strings.Split(text, ";") {
		if len(kv) > 2 {
			tmpKV := strings.SplitN(kv, "=", 2)
			if len(tmpKV) == 2 && tmpKV[0] != "" {
				kvMap[strings.TrimSpace(tmpKV[0])] = strings.TrimSpace(tmpKV[1])
			}
		}
	}

	return kvMap
}

func EncodePushHeaderKV(_map map[string]string) string {
	kvArr := make([]string, 0)

	for k, v := range _map {
		kvArr = append(kvArr, k+"="+v)
	}
	return strings.Join(kvArr, ";")
}

var PushQueue = make(chan PushQueueItem, 1000)

func ApiV2Push(c echo.Context) error {
	pushHeader := new(PushHeader)
	if err := (&echo.DefaultBinder{}).BindHeaders(c, pushHeader); err != nil {
		log.Println(err)
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid request", false, "push_v2"))
	}

	token := c.Param("token")
	if !regexp.MustCompile(`^[\w+\-/]{10,100}$`).MatchString(token) {
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid token", false, "push_v2"))
	}

	channel := c.Param("channel")
	if channel != "" && !regexp.MustCompile(`^[\w+\-/]{1,100}$`).MatchString(channel) {
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid channel", false, "push_v2"))
	}

	// parse header

	// content length
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid request", false, "push_v2"))
	}
	if len(body) != pushHeader.ContentLength || len(body) > 4096 {
		return c.JSON(http.StatusRequestEntityTooLarge, ApiTemplate(413, "Invalid content length", false, "push_v2"))
	}

	cryptoKey := ParsePushHeaderKV(pushHeader.CryptoKey)
	encryption := ParsePushHeaderKV(pushHeader.Encryption)

	encoding := pushHeader.Encoding
	if !slices.Contains([]string{"aesgcm", "aes128gcm", "none"}, encoding) {
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Not supported", false, "push_v2"))
	}

	/// TODO ignore authorization now
	var jwt_ = ""
	if encoding == "aes128gcm" {
		splitedAuthorization := strings.Split(strings.TrimPrefix(pushHeader.Authorization, "vapid "), ",")
		authorizationMap := make(map[string]string, 2)
		for _, v := range splitedAuthorization {
			authorizationKV := strings.Split(v, "=")
			authorizationMap[authorizationKV[0]] = authorizationKV[1]
		}

		jwt_ = authorizationMap["t"]
		// publicKey := authorizationMap["k"]
	} else if encoding == "aesgcm" {
		jwt_ = strings.TrimPrefix(pushHeader.Authorization, "WebPush ")
	}

	_, err = jwt.ParseWithClaims(jwt_, jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		if !token.Valid {
			return nil, errors.New("invalid token")
		}

		return token, nil
	})

	// set ttl
	// one day
	ttl := min(max(0, pushHeader.TTL), share.V2MaximumTTL)

	// log.Println(t, err)

	var rawData string
	if encoding == "none" {
		rawData = string(body)
	} else {
		rawData = base64.RawURLEncoding.EncodeToString(body)
	}

	payload := &PushBody{
		MessageType: "notification",
		ChannelID:   channel,
		Version:     strconv.Itoa(int(time.Now().UnixMilli())),
		Headers: &struct {
			Encryption string `json:"encryption,omitempty"`
			CryptoKey  string `json:"crypto_key,omitempty"`
			Encoding   string `json:"encoding,omitempty"`
		}{
			Encryption: EncodePushHeaderKV(encryption),
			CryptoKey:  EncodePushHeaderKV(cryptoKey),
			Encoding:   encoding,
		},
		Data: rawData,
	}

	// TODO queue
	if cc := WsCore.WebsocketConnPool.Get("push_v2:" + token); cc != nil {
		wsConn := cc.Value()
		if wsConn.Conn != nil && wsConn.Ctx.Err() == nil {
			wsChannel, ok := wsConn.Store["push_channel"]

			if (!ok || wsChannel == "") || slices.Contains(strings.Split(wsChannel, ","), channel) {
				PushQueue <- PushQueueItem{
					Conn: wsConn,
					Body: payload,
				}
			}
		} else if ttl > 0 {
			return CacheMessage(c, payload, int64(ttl), token)
		} else {
			return c.JSON(http.StatusCreated, ApiTemplate(404, "Conn lost", false, "push_v2"))
		}

		// if err := cc.Value().WsConn.WriteMessage(websocket.TextMessage, jsonPayload); err != nil {
		// 	return c.JSON(http.StatusInternalServerError, ApiTemplate(500, "Failed", payload, "push"))
		// } else {
		return c.JSON(http.StatusCreated, ApiTemplate(201, "OK", true, "push_v2"))
		// }
	} else if ttl > 0 {
		return CacheMessage(c, payload, int64(ttl), token)
	}

	return c.JSON(http.StatusAccepted, ApiTemplate(200, "No conn", true, "push_v2"))
}

func CacheMessage(c echo.Context, payload *PushBody, ttl int64, token string) error {
	if !slices.Contains([]string{"aesgcm", "aes128gcm"}, payload.Headers.Encryption) {
		return c.JSON(http.StatusAccepted, ApiTemplate(400, "Plaintext message is not allow", false, "push_v2"))
	}
	message, err := functions.JsonEncode(payload)
	if err != nil {
		log.Println(err)
		return c.JSON(http.StatusAccepted, ApiTemplate(500, "Encode message failed", true, "push_v2"))
	}
	if err := functions.GormDB.W.Create(&model.V2MessageCache{
		Uaid:      token,
		Message:   string(message),
		ExpiredAt: time.Now().Unix() + int64(ttl),
	}).Error; err != nil {
		log.Println(err)
		return c.JSON(http.StatusAccepted, ApiTemplate(500, "Save message failed", true, "push_v2"))
	}

	return c.JSON(http.StatusAccepted, ApiTemplate(200, "Cached", true, "push_v2"))
}
