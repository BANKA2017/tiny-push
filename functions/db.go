package functions

import (
	"fmt"
	"log"
	"os"

	"github.com/BANKA2017/tiny-push/model"
	"github.com/BANKA2017/tiny-push/share"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var GormDB = new(GormDBPool)

type GormDBPool struct {
	R *gorm.DB
	W *gorm.DB
}

func ConnectToSQLite(path string, logLevel logger.LogLevel, servicePrefix string) (*gorm.DB, *gorm.DB, error) {
	var writeDBHandle = new(gorm.DB)
	var readDBHandle = new(gorm.DB)
	var err error
	if _, err = os.Stat(path); err != nil {
		log.Println("db:", path, "is not exists")
	}
	// sqlite
	// write

	writeDBHandle, err = gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		log.Println(servicePrefix+" w:", err)
	}
	connw, err := writeDBHandle.DB()
	connw.SetMaxOpenConns(1)

	if err != nil {
		log.Println(servicePrefix+" w:", err)
	}

	//read
	readDBHandle, err = gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		log.Println(servicePrefix+" r:", err)
	}
	// connr, err := readDBHandle.DB()
	// connr.SetMaxOpenConns(max(4, runtime.NumCPU()))

	if err != nil {
		log.Println(servicePrefix+" r:", err)
	}
	log.Println(servicePrefix + ": sqlite connected!")

	writeDBHandle.Exec("PRAGMA journal_mode = WAL;PRAGMA busy_timeout = 5000;PRAGMA synchronous = NORMAL;PRAGMA cache_size = 100000;PRAGMA foreign_keys = true;PRAGMA temp_store = memory;")
	return readDBHandle, writeDBHandle, err
}

func GetUUID(uuid string) (*model.Channel, error) {
	c := new(model.Channel)
	err := GormDB.R.Model(&model.Channel{}).Where("uuid = ?", uuid).First(c).Error

	if err != nil {
		log.Println("getUUID:", uuid, err)
	}

	return c, err
}

func SetUUID(data model.Channel) error {
	return GormDB.W.Create(&data).Error
}

func DeleteUUID(uuid string) error {
	return GormDB.W.Where("uuid = ?", uuid).Delete(&model.Channel{}).Error
}

func UpdateUUID(data *model.Channel) error {
	uuid := data.UUID

	if uuid == "" {
		return fmt.Errorf("updateUUID: empty uuid")
	}

	uuidData := new(model.Channel)
	err := GormDB.W.Model(&model.Channel{}).Where("uuid = ?", uuid).First(uuidData).Error

	if err != nil {
		return err
	}

	return GormDB.W.Model(&model.Channel{}).Where("uuid = ?", uuid).Updates(data).Error
}

func InitSettings() error {
	var err error
	tmpSettings := new([]model.Setting)
	GormDB.R.Model(&model.Setting{}).Find(tmpSettings)
	if len(*tmpSettings) >= 2 {
		tmpSettingsKV := make(map[string]string)
		for _, setting := range *tmpSettings {
			tmpSettingsKV[setting.Key] = setting.Value
		}
		share.Vapid.PrivateKey = tmpSettingsKV["key"]
		share.ECCPrivateKey, err = ImportKey(share.Vapid.PrivateKey)
		if err != nil {
			return err
		}
		share.Vapid.Sub = tmpSettingsKV["sub"]
		return nil
	}
	return fmt.Errorf("no settings")
}
