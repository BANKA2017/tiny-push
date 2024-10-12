package share

import "crypto/ecdsa"

var Address = ""
var DBPath = ""
var TestMode = false

var Vapid = struct {
	PrivateKey string
	Sub        string
}{}

var ECCPrivateKey *ecdsa.PrivateKey
