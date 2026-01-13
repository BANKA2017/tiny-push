package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/BANKA2017/tiny-push/api"
	"github.com/BANKA2017/tiny-push/functions"
	"github.com/BANKA2017/tiny-push/model"
	"github.com/BANKA2017/tiny-push/share"
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

	functions.GormDB.ServicePrefix = "tiny-push"
	functions.GormDB.LogLevel = logLevel
	functions.GormDB.WALMode = true

	if err = functions.GormDB.ConnectToSQLite(share.DBPath); err != nil {
		log.Fatal(err)
	}

	// init vapid data
	if err = functions.InitSettings(); err != nil {
		functions.Setup()
		if err = functions.InitSettings(); err != nil {
			log.Fatal(err)
		}
	}

	oneMinuteTicker := time.NewTicker(time.Minute)
	deleteExpiredGlobalJWT := time.NewTicker(time.Minute)
	defer oneMinuteTicker.Stop()
	defer deleteExpiredGlobalJWT.Stop()

	// ws conn
	api.InitWsCore()
	defer api.WsCore.Stop()

	go func() {
		for {
			select {
			case <-oneMinuteTicker.C:
				// TODO ??
				functions.GormDB.W.Where("last_used <= ?", time.Now().Add(time.Hour*24*30*3*-1).UnixMilli()).Delete(&model.Channel{})
				functions.GormDB.W.Where("expired_at <= ?", time.Now().Unix()).Delete(&model.V2MessageCache{})
				api.WsCore.WebsocketConnPool.DeleteExpired()
			case q := <-api.PushQueue:
				jsonPayload, _ := json.Marshal(q.Body)
				if err = q.Conn.SendWebsocketMessage(jsonPayload); err != nil {
					log.Println(err)
				}
			}
		}
	}()

	api.Api()
}
