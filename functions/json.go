package functions

import (
	"encoding/json/v2"
)

func JsonDecode[T any](jsonByte []byte, template *T) error {
	return json.Unmarshal(jsonByte, template)
}

func JsonEncode[T any](data T) ([]byte, error) {
	return json.Marshal(data)
}
