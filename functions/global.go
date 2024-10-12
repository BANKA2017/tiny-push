package functions

import (
	"time"
)

var Now = time.Now()

func UpdateNow() {
	Now = time.Now()
}

func ConcatBuffer(byteData ...[]byte) []byte {
	tmpBuffer := []byte{}
	for _, buf := range byteData {
		tmpBuffer = append(tmpBuffer, buf...)
	}
	return tmpBuffer
}

func VariableWrapper[T any](anyValue T) T {
	return anyValue
}

func VariablePtrWrapper[T any](anyValue T) *T {
	return &anyValue
}
