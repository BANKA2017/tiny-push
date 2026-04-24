package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BANKA2017/tiny-push/functions"
	"github.com/BANKA2017/tiny-push/model"
	mtcws "github.com/kdnetwork/message-transfer-core/websocket"
	"github.com/labstack/echo/v4"
	"github.com/lesismal/nbio/nbhttp/websocket"
)

var WsCore mtcws.WsCoreCtx

func InitWsCore() {
	WsCore = mtcws.WsCoreCtx{
		TTL:            time.Hour * 24,
		ConnSize:       5000,
		ConnectTimeout: time.Second * 10,
	}

	WsCore.Init()
	WsCore.InitUpgrader()

	WsCore.OnConnected = func(w *mtcws.WsConnContext) error {
		fmt.Println("OnOpen:", w.Conn.RemoteAddr().String())

		// load messages from db
		now := time.Now().Unix()

		messages, err := GetCache(w.ID)
		if err != nil {
			return err
		}

		for _, message := range messages {
			if message.ExpiredAt > now {
				if err := w.SendWebsocketMessage([]byte(message.Message)); err != nil {
					log.Println(err)
				}
			}
		}

		//TODO ack

		return nil
	}

	WsCore.OnDisConnected = func(w *mtcws.WsConnContext) error {
		fmt.Println("OnClose:", w.Conn.RemoteAddr().String())

		if w.Conn == nil {
			return errors.New("no conn")
		}

		body := PushBody{
			MessageType: "close",
			ChannelID:   "",
			Version:     strconv.Itoa(int(time.Now().UnixMilli())),
			Data:        w.Store["disconnect_reason"],
		}

		binBody, _ := json.Marshal(body)

		return w.Conn.WriteMessage(websocket.TextMessage, binBody)
	}

	WsCore.OnMessage = func(w *mtcws.WsConnContext, msg []byte) ([]byte, error) {
		if len(msg) == 0 {
			return []byte{}, nil
		}

		var ack PushAck
		if err := functions.JsonDecode(msg, &ack); err != nil {
			log.Println("invalid ack message:", string(msg))
			return []byte{}, nil
		}

		msgVersions := []string{}
		for _, m := range ack.Messages {
			msgVersions = append(msgVersions, m.Version)
		}

		functions.GormDB.R.Model(&model.V2MessageCache{}).Where("uaid = ? AND version IN ?", w.ID, msgVersions).Update("expired_at", 0)

		return []byte{}, nil
	}
}

type PushAck struct {
	MessageType string           `json:"message_type"`
	Messages    []PushAckMessage `json:"messages"`
}

type PushAckMessage struct {
	ChannelID string `json:"channel_id"`
	Version   string `json:"version"`
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
	Conn *mtcws.WsConnContext
	Body *PushBody
}

type WsConnStruct struct {
	WsConn  *websocket.Conn
	Token   string
	Channel []string
	// RemoteAddr string
}

func PushBroadcast(message []byte) error {
	WsCore.BroadcastToWebSocket(message, "")

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

	if _, err := WsCore.WebsocketServer(c.Response().Writer, c.Request(), &mtcws.WsConnConfigExt{
		ConnType: "push_v2",
		NodeID:   token,
		Store: map[string]string{
			"push_channel": strings.Join(newChannel, ","),
		},
	}); err != nil {
		log.Println(err)
		return c.String(http.StatusInternalServerError, "")
	}

	return nil //functions.WsRPC.WebsocketServer(ctx, c.Response().Writer, c.Request())
}
