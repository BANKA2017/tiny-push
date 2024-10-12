package api

import (
	"net/http"

	"github.com/BANKA2017/tiny-push/functions"
	"github.com/BANKA2017/tiny-push/share"
	"github.com/labstack/echo/v4"
)

func ApiVapid(c echo.Context) error {
	return c.JSON(http.StatusOK, ApiTemplate(200, "OK", map[string]string{
		"vapid": functions.GetPublicKey(share.ECCPrivateKey),
	}, "push"))
}
