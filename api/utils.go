package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type _ApiTemplate struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
	Version string `json:"version"`
}

var EchoEmptyObject = make(map[string]any, 0)
var EchoEmptyArray = make([]string, 0)

func ApiTemplate[T any](code int, message string, data T, version string) _ApiTemplate {
	return _ApiTemplate{
		Code:    code,
		Message: message,
		Data:    data,
		Version: version,
	}
}

func EchoReject(c echo.Context) error {
	return c.JSON(http.StatusForbidden, ApiTemplate(403, "Invalid request", EchoEmptyObject, "push"))
}

func EchoNoContent(c echo.Context) error {
	return c.NoContent(http.StatusOK)
}
