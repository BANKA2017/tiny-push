package api

import (
	"io/fs"
	"net/http"

	"github.com/BANKA2017/tiny-push/assets"
	"github.com/BANKA2017/tiny-push/share"
	"github.com/labstack/echo/v4"
)

func Api() {
	e := echo.New()
	//e.Use(middleware.Logger())
	e.Use(SetHeaders)

	api := e.Group("/api")
	api.GET("/vapid", ApiVapid)
	api.POST("/subscribe/", ApiSubscribe)
	api.DELETE("/subscribe/:uuid", ApiDeleteSubscribe)
	api.POST("/push/:uuid", ApiPush)
	api.POST("/push/", ApiPush)
	api.Any("/*", EchoReject)
	if share.TestMode {
		e.Static("/*", "assets/fe")
	} else {
		fe, _ := fs.Sub(assets.EmbeddedFrontent, "fe")
		e.GET("/*", echo.WrapHandler(http.FileServer(http.FS(fe))))
	}

	e.Logger.Fatal(e.Start(share.Address))
}
