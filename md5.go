package httpdigest

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func md5hex(format string, v ...interface{}) string {
	md5b := md5.Sum([]byte(fmt.Sprintf(format, v...)))
	return hex.EncodeToString(md5b[:])
}

func newCnonce() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	str0 := hex.EncodeToString(buf)
	return base64.StdEncoding.EncodeToString([]byte(str0))
}
