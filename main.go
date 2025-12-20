package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/BANKA2017/tiny-push/api"
	"github.com/BANKA2017/tiny-push/functions"
	"github.com/BANKA2017/tiny-push/share"
	"github.com/lesismal/nbio/nbhttp/websocket"
	"gorm.io/gorm/logger"
)

var err error

func main() {
	fmt.Println("🔔TinyPush\n--- info ---")
	flag.StringVar(&share.Address, "addr", "", "Service path")
	flag.StringVar(&share.DBPath, "db_path", "", "Database path")
	flag.BoolVar(&share.TestMode, "test", false, "Test mode")
	flag.Parse()

	if share.Address == "" {
		log.Fatal("tiny-push: address is empty!")
	}

	logLevel := logger.Error
	if share.TestMode {
		logLevel = logger.Info
	}
	functions.GormDB.R, functions.GormDB.W, err = functions.ConnectToSQLite(share.DBPath, logLevel, "tiny-push")

	if err != nil {
		log.Fatal(err)
	}

	// init vapid data
	err = functions.InitSettings()
	if err != nil {
		functions.Setup()
		err = functions.InitSettings()
		if err != nil {
			log.Fatal(err)
		}
	}

	updateTimeTicker := time.NewTicker(time.Millisecond * 200)
	oneMinuteTicker := time.NewTicker(time.Minute)
	deleteExpiredGlobalJWT := time.NewTicker(time.Minute)
	defer updateTimeTicker.Stop()
	defer oneMinuteTicker.Stop()
	defer deleteExpiredGlobalJWT.Stop()

	// ws conn
	api.InitWsCore()
	defer api.WsCore.Stop()

	go func() {
		for {
			select {
			case <-updateTimeTicker.C:
				functions.UpdateNow()
			case <-oneMinuteTicker.C:
				// TODO ??
				functions.GormDB.W.Where("last_used <= ?", functions.Now.Add(time.Hour*24*30*3*-1).UnixMilli())
				api.WsCore.WebsocketConnPool.DeleteExpired()
			case q := <-api.PushQueue:
				jsonPayload, _ := json.Marshal(q.Body)
				if err = q.Conn.WriteMessage(websocket.TextMessage, jsonPayload); err != nil {
					log.Println(err)
				}
			}
		}
	}()

	api.Api()
}
