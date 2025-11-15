package functions

import (
	"crypto/ecdh"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
)

var PushEndpointHostList = []string{
	// https://github.com/pushpad/known-push-services/blob/master/whitelist
	"android.googleapis.com",
	"fcm.googleapis.com",
	"updates.push.services.mozilla.com",
	"updates-autopush.stage.mozaws.net",
	"updates-autopush.dev.mozaws.net",

	// self-service
	"push.nest.moe",
}

func VerifyURL(_url string) bool {
	parsedURL, err := url.ParseRequestURI(_url)

	if err != nil {
		return false
	} else if parsedURL.Scheme != "https" {
		return false
	} else if !slices.Contains(PushEndpointHostList, parsedURL.Host) && !strings.HasSuffix(parsedURL.Host, ".notify.windows.com") && !strings.HasSuffix(parsedURL.Path, ".push.apple.com") {
		return false
	}

	return true
}

func VerifyP256dh(_p256dh string) bool {
	decodedP256DH, err := base64.RawURLEncoding.DecodeString(_p256dh)
	if err != nil {
		return false
	}

	if len(decodedP256DH) != 65 || decodedP256DH[0] != 0x04 {
		return false
	}

	_, err = ecdh.P256().NewPublicKey(decodedP256DH)
	return err == nil
}

func VerifyAuth(_auth string) bool {
	decodedAuth, err := base64.RawURLEncoding.DecodeString(_auth)
	if err != nil {
		return false
	}
	return len(decodedAuth) == 16
}
