//go:build android || ios

package vpnc

import (
	"sslcon/session"
)

func ConfigInterface(cSess *session.ConnSession) error { return nil }

func SetRoutes(cSess *session.ConnSession) error { return nil }

func ResetRoutes(cSess *session.ConnSession) {}

func GetLocalInterface() error { return nil }
