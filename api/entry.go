package api

import (
	"io/fs"
	"strings"

	"github.com/labstack/echo/v5/middleware"

	"github.com/BANKA2017/tiny-push/assets"
	"github.com/BANKA2017/tiny-push/share"
	"github.com/labstack/echo/v5"
)

func Api() {
	e := echo.New()
	// e.Pre(middleware.RemoveTrailingSlash())
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
	apiv2.GET("/cache/:token", ApiV2GetCache)
	apiv2.DELETE("/cache/:token/:version", ApiV2DeleteCache)

	if share.TestMode {
		e.Static("/*", "assets/fe")
	} else {
		fe, _ := fs.Sub(assets.EmbeddedFrontend, "fe")

		e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
			Filesystem: fe,
			HTML5:      true,
			Skipper:    IsAPIPath,
		}))
	}

	if err := e.Start(share.Address); err != nil {
		e.Logger.Error("failed to start server", "error", err)
	}
}

func IsAPIPath(c *echo.Context) bool {
	path := c.Path()

	return path == "/api" || strings.HasPrefix(path, "/api/")
}
