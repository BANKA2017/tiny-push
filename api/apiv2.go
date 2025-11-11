package api

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jellydator/ttlcache/v3"
	"github.com/labstack/echo/v4"
	"github.com/lesismal/nbio/nbhttp/websocket"
)

var (
	upgrader = newUpgrader()
)

func newUpgrader() *websocket.Upgrader {
	u := websocket.NewUpgrader()
	u.OnOpen(func(c *websocket.Conn) {
		// echo
		fmt.Println("OnOpen:", c.RemoteAddr().String())
	})
	u.OnMessage(func(c *websocket.Conn, messageType websocket.MessageType, data []byte) {
		// echo
		fmt.Println("OnMessage:", messageType, string(data))
		c.WriteMessage(messageType, data)
	})
	u.OnClose(func(c *websocket.Conn, err error) {
		fmt.Println("OnClose:", c.RemoteAddr().String(), err)
	})
	return u
}

type PushHeader struct {
	Encryption    string `header:"Encryption"`
	CryptoKey     string `header:"Crypto-Key"`
	Encoding      string `header:"Content-Encoding"`
	TTL           string `header:"TTL"` // TODO no used now...
	Authorization string `header:"Authorization"`
	ContentLength string `header:"Content-Length"`
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

// like autopush
type PushBody struct {
	MessageType string `json:"message_type"`
	ChannelID   string `json:"channel_id"`
	Version     string `json:"version"`
	Data        string `json:"data"`
	Headers     struct {
		Encryption string `json:"encryption,omitempty"`
		CryptoKey  string `json:"crypto_key,omitempty"`
		Encoding   string `json:"encoding,omitempty"`
	} `json:"headers"`
}

type PushQueueItem struct {
	Conn *websocket.Conn
	Body PushBody
}

var PushQueue = make(chan PushQueueItem, 1000)

func ApiV2Push(c echo.Context) error {
	pushHeader := new(PushHeader)
	if err := (&echo.DefaultBinder{}).BindHeaders(c, pushHeader); err != nil {
		log.Println(err)
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid request", false, "push_v2"))
	}

	token := c.Param("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid token1", false, "push_v2"))
	} else if len(token) > 100 {
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid token2", false, "push_v2"))
	} else if !regexp.MustCompile(`^[A-Za-z0-9+\-_/]+$`).MatchString(token) {
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid token3", false, "push_v2"))
	}

	// parse header

	// content length
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ApiTemplate(400, "Invalid request", false, "push_v2"))
	}
	if strconv.Itoa(int(len(body))) != pushHeader.ContentLength || len(body) > 4096 {
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
	_, err = jwt.ParseWithClaims(jwt_, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	}, jwt.WithIssuedAt(), jwt.WithExpirationRequired())
	// ttl := pushHeader.TTL

	var rawData string
	if encoding == "none" {
		rawData = string(body)
	} else {
		rawData = base64.RawURLEncoding.EncodeToString(body)
	}

	payload := PushBody{
		MessageType: "notification",
		ChannelID:   token,
		Version:     token,
		Headers: struct {
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
	if cc := WsConnCache.Get(token); cc != nil {
		PushQueue <- PushQueueItem{
			Conn: cc.Value().WsConn,
			Body: payload,
		}

		// if err := cc.Value().WsConn.WriteMessage(websocket.TextMessage, jsonPayload); err != nil {
		// 	return c.JSON(http.StatusInternalServerError, ApiTemplate(500, "Failed", payload, "push"))
		// } else {
		return c.JSON(http.StatusCreated, ApiTemplate(201, "OK", payload, "push"))
		// }
	} else {
		return c.JSON(http.StatusAccepted, ApiTemplate(200, "No conn", payload, "push"))
	}
}

type WsConnStruct struct {
	WsConn     *websocket.Conn
	Token      string
	RemoteAddr string
}

var WsConnCache = ttlcache.New(
	ttlcache.WithCapacity[string, *WsConnStruct](5000),
	ttlcache.WithTTL[string, *WsConnStruct](time.Hour*24),
)

func ApiV2WsPush(c echo.Context) error {
	token := strings.TrimSpace(c.QueryParams().Get("token"))

	if cc := WsConnCache.Get(token); cc != nil {
		// disconnect
		cc.Value().WsConn.Close()
		WsConnCache.Delete(token)
	}

	conn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}

	connStruct := &WsConnStruct{
		WsConn:     conn,
		Token:      token,
		RemoteAddr: conn.RemoteAddr().String(),
	}

	WsConnCache.Set(token, connStruct, ttlcache.DefaultTTL)

	return nil //functions.WsRPC.WebsocketServer(ctx, c.Response().Writer, c.Request())
}
