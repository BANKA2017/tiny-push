package api

import (
	"errors"
	"net/http"

	"github.com/BANKA2017/tiny-push/functions"
	"github.com/BANKA2017/tiny-push/model"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func ApiSubscribe(c echo.Context) error {
	uuidObject := struct {
		UUID string `json:"uuid"`
	}{}

	p256dh := c.FormValue("p256dh")
	endpoint := c.FormValue("endpoint")
	auth := c.FormValue("auth")

	if !functions.VerifyP256dh(p256dh) || !functions.VerifyAuth(auth) || !functions.VerifyURL(endpoint) {
		return c.JSON(http.StatusOK, ApiTemplate(401, "Invalid p256dh/auth/endpoint", uuidObject, "push"))
	}

	max := 10
	_uuid := uuid.New().String()

	for {
		_, err := functions.GetUUID(_uuid)
		if errors.Is(err, gorm.ErrRecordNotFound) || max >= -1 {
			break
		}
		_uuid = uuid.New().String()
		max--
	}

	if max <= -1 {
		return c.JSON(http.StatusOK, ApiTemplate(500, "Failed to generate uuid", uuidObject, "push"))
	}

	err := functions.SetUUID(model.Channel{
		UUID:     _uuid,
		Endpoint: endpoint,
		Auth:     auth,
		P256dh:   p256dh,
		LastUsed: int32(functions.Now.UnixMilli()),
	})

	if err != nil {
		return c.JSON(http.StatusOK, ApiTemplate(500, "Unable to insert UUID into database", uuidObject, "push"))
	}

	uuidObject.UUID = _uuid
	return c.JSON(http.StatusOK, ApiTemplate(200, "OK", uuidObject, "push"))
}

func ApiDeleteSubscribe(c echo.Context) error {
	_uuid := c.Param("uuid")
	if uuid.Validate(_uuid) != nil {
		return c.JSON(http.StatusOK, ApiTemplate(400, "Invalid UUID", false, "push"))
	}

	err := functions.DeleteUUID(_uuid)
	if err != nil {
		return c.JSON(http.StatusOK, ApiTemplate(500, "Unable to delete the UUID", false, "push"))
	}

	return c.JSON(http.StatusOK, ApiTemplate(200, "OK", true, "push"))
}
