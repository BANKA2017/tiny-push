package functions

func ConcatBuffer(byteData ...[]byte) []byte {
	var tmpBuffer []byte
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

func When[T any](c bool, d1, d2 T) T {
	if c {
		return d1
	} else {
		return d2
	}
}
