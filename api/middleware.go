package api

import "github.com/labstack/echo/v4"

func SetHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Add("X-Powered-By", "TinyPush!")
		c.Response().Header().Add("Access-Control-Allow-Methods", "*")
		return next(c)
	}
}
