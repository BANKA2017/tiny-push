package functions

import (
	"fmt"
	"log"

	"github.com/BANKA2017/tiny-push/model"
	"github.com/BANKA2017/tiny-push/share"
	"github.com/kdnetwork/code-snippet/go/db"
)

var GormDB = new(db.GormDBCtx)

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
