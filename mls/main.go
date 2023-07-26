package mls

import (
	"crypto/rand"
	"github.com/cisco/go-mls"
)

var (
	groupId = []byte{0x00}
	userId  = []byte{0x01}
	suite   = mls.P256_AES128GCM_SHA256_P256
	scheme  = suite.Scheme()
)

func randomBytes(size int) []byte {
	out := make([]byte, size)
	rand.Read(out)
	return out
}
