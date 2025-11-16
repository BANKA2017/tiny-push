package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/labstack/echo/v4"
	"github.com/lesismal/nbio/nbhttp/websocket"
)

var (
	upgrader = newUpgrader()
)

func newUpgrader() *websocket.Upgrader {
	u := websocket.NewUpgrader()
	u.KeepaliveTime = time.Hour*24 + time.Second*time.Duration(rand.Float64()*60.0)
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

// like autopush
type PushBody struct {
	MessageType string `json:"message_type"`
	ChannelID   string `json:"channel_id"`
	Version     string `json:"version"`
	Data        string `json:"data"`
	Headers     *struct {
		Encryption string `json:"encryption,omitempty"`
		CryptoKey  string `json:"crypto_key,omitempty"`
		Encoding   string `json:"encoding,omitempty"`
	} `json:"headers,omitempty"`
}

type PushQueueItem struct {
	Conn *websocket.Conn
	Body PushBody
}

type WsConnStruct struct {
	WsConn  *websocket.Conn
	Token   string
	Channel []string
	// RemoteAddr string
}

const PushConnSize = 5000

var WsConnCache = ttlcache.New(
	ttlcache.WithCapacity[string, *WsConnStruct](PushConnSize),
	ttlcache.WithTTL[string, *WsConnStruct](time.Hour*24),
)

func init() {
	WsConnCache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, i *ttlcache.Item[string, *WsConnStruct]) {
		wsconn := i.Value()

		if wsconn.WsConn == nil {
			return
		}

		body := PushBody{
			MessageType: "close",
			ChannelID:   "",
			Version:     strconv.Itoa(int(time.Now().UnixMilli())),
		}

		if i.IsExpired() {
			body.Data = "expired"
		} else {
			body.Data = "kick"
		}

		binBody, _ := json.Marshal(body)

		wsconn.WsConn.WriteMessage(websocket.TextMessage, binBody)

		wsconn.WsConn.Close()
	})
}

func CreateWsConn(w http.ResponseWriter, r *http.Request, token string, channel []string) error {
	if cc := WsConnCache.Get(token); cc != nil {
		// disconnect
		WsConnCache.Delete(token)
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}

	connStruct := &WsConnStruct{
		WsConn:  conn,
		Token:   token,
		Channel: channel,
		// RemoteAddr: conn.RemoteAddr().String(),
	}

	WsConnCache.Set(token, connStruct, ttlcache.DefaultTTL)

	return nil
}

func PushBroadcast(message []byte) error {
	WsConnCache.Range(func(item *ttlcache.Item[string, *WsConnStruct]) bool {
		err := item.Value().WsConn.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			log.Println(err)
		}
		return true
	})

	return nil
}

func ApiV2WsPush(c echo.Context) error {
	token := c.Param("token")

	if token == "" {
		token = strings.TrimSpace(c.QueryParams().Get("token"))
	}

	if !regexp.MustCompile(`^[A-Za-z0-9+\-_/]{10,100}$`).MatchString(token) {
		return c.String(http.StatusUnauthorized, "")
	}

	channel := strings.Split(c.QueryParam("channel"), ",")
	newChannel := make([]string, 0)

	for i, ch := range channel {
		if i >= 20 {
			break
		}
		if ch != "" && regexp.MustCompile(`^[A-Za-z0-9+\-_/]{1,100}$`).MatchString(ch) {
			newChannel = append(newChannel, ch)
		}
	}

	if err := CreateWsConn(c.Response().Writer, c.Request(), token, newChannel); err != nil {
		log.Println(err)
		return c.String(http.StatusInternalServerError, "")
	}

	return nil //functions.WsRPC.WebsocketServer(ctx, c.Response().Writer, c.Request())
}
