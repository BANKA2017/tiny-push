package functions

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BANKA2017/tiny-push/assets"
	"github.com/BANKA2017/tiny-push/model"
	"github.com/BANKA2017/tiny-push/share"
)

func Setup() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("📌TinyPush")

	fmt.Println("input the sub (e.g. `mailto:your@example.com`)")
	fmt.Print("-> ")
	subStr, _ := reader.ReadString('\n')
	subStr = strings.TrimSpace(subStr)
	if subStr == "" {
		fmt.Println("❌Invalid sub")
		os.Exit(0)
	}

	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	keyStr := strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(key.Bytes()), "=", "")

	fmt.Println("⌛Drop tables")
	GormDB.W.Migrator().DropTable(&model.Channel{}, &model.Setting{}, &model.V2MessageCache{})

	fmt.Println("⌛Create tables")
	GormDB.W.Migrator().CreateTable(&model.Channel{}, &model.Setting{}, &model.V2MessageCache{})

	fmt.Println("⌛Insert settings")
	GormDB.W.Create(&[]model.Setting{
		{
			Key:   "key",
			Value: keyStr,
		}, {
			Key:   "sub",
			Value: subStr,
			// }, {
			// 	Key:   "ttl",
			// 	Value: strconv.Itoa(60 * 60 * 24), // 24h
		},
	})

	trigger, err := assets.EmbeddedDB.ReadFile("db/sqlite.trigger.sql")
	if err != nil {
		return err
	}

	GormDB.W.Exec("DROP TRIGGER v2_message_cache_limit;")
	GormDB.W.Exec(strings.Replace(string(trigger), "{V2TriggerCacheLimit}", strconv.Itoa(share.V2CacheSize), 1))

	fmt.Println("🎉Success!")

	return nil
}
