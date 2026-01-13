package api

import (
	"io/fs"
	"net/http"

	"github.com/BANKA2017/tiny-push/assets"
	"github.com/BANKA2017/tiny-push/share"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func Api() {
	e := echo.New()
	e.Pre(middleware.RemoveTrailingSlash())
	//e.Use(middleware.Logger())
	e.Use(SetHeaders)

	api := e.Group("/api")
	api.GET("/vapid", ApiVapid)
	api.POST("/subscribe/", ApiSubscribe)
	api.DELETE("/subscribe/:uuid", ApiDeleteSubscribe)
	api.POST("/push/:uuid", ApiPush)
	api.POST("/push/", ApiPush)
	api.Any("/*", EchoReject)

	apiv2 := api.Group("/v2")
	apiv2.GET("/ws/:token", ApiV2WsPush)
	apiv2.POST("/push/:token/:channel", ApiV2Push)
	apiv2.POST("/push/:token", ApiV2Push)

	if share.TestMode {
		e.Static("/*", "assets/fe")
	} else {
		fe, _ := fs.Sub(assets.EmbeddedFrontend, "fe")
		e.GET("/*", echo.WrapHandler(http.FileServer(http.FS(fe))))
	}

	e.Logger.Fatal(e.Start(share.Address))
}
