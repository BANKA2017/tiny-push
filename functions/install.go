package functions

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/BANKA2017/tiny-push/model"
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
	GormDB.W.Migrator().DropTable(&model.Channel{}, &model.Setting{})

	fmt.Println("⌛Create tables")
	GormDB.W.Migrator().CreateTable(&model.Channel{})
	GormDB.W.Migrator().CreateTable(&model.Setting{})

	fmt.Println("⌛Insert settings")
	GormDB.W.Create(&[]model.Setting{
		{
			Key:   "key",
			Value: keyStr,
		}, {
			Key:   "sub",
			Value: subStr,
		},
	})

	fmt.Println("🎉Success!")

	return nil
}
