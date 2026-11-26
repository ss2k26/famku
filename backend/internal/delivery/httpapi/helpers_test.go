package httpapi_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"
)

func newJar() (http.CookieJar, error) { return cookiejar.New(nil) }

// totpNow computes the RFC 6238 code independently of the implementation under test.
func totpNow(t *testing.T, secret string, stepOffset int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatal(err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(time.Now().Unix()/30+stepOffset))
	m := hmac.New(sha1.New, key)
	m.Write(buf[:])
	s := m.Sum(nil)
	o := s[len(s)-1] & 0xf
	v := (uint32(s[o]&0x7f)<<24 | uint32(s[o+1])<<16 | uint32(s[o+2])<<8 | uint32(s[o+3])) % 1_000_000
	return fmt.Sprintf("%06d", v)
}
