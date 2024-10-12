package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/BANKA2017/tiny-push/api"
	"github.com/BANKA2017/tiny-push/functions"
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
	deleteExpiredUUID := time.NewTicker(time.Minute)
	deleteExpiredGlobalJWT := time.NewTicker(time.Minute)
	defer updateTimeTicker.Stop()
	defer deleteExpiredUUID.Stop()
	defer deleteExpiredGlobalJWT.Stop()

	go func() {
		for {
			select {
			case <-updateTimeTicker.C:
				functions.UpdateNow()
			case <-deleteExpiredUUID.C:
				// TODO ??
				functions.GormDB.W.Where("last_used <= ?", functions.Now.Add(time.Hour*24*30*3*-1).UnixMilli())
			case <-deleteExpiredGlobalJWT.C:
				now := functions.Now
				functions.GlobalJWT.Range(func(key, value any) bool {
					v, _ := value.(functions.GlobalJWTContent)
					if v.Expire <= now.UnixMilli() {
						functions.GlobalJWT.Delete(key)
					}
					return true
				})
			}
		}
	}()

	api.Api()
}
