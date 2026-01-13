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

var V2DefaultTTL = 60 * 60 * 24
var V2MaximumTTL = 60 * 60 * 24
var V2CacheSize = 10
