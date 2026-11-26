package security

import (
	"crypto/hmac"
	"crypto/sha1" // RFC 6238 default; authenticator apps expect HMAC-SHA1
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP implements RFC 6238 (6 digits, 30 s step, +-1 step of clock drift).
type TOTP struct{}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func (TOTP) NewSecret() (string, error) { return b32.EncodeToString(randBytes(20)), nil }

func (TOTP) URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func hotp(key []byte, counter uint64) string {
	mac := hmac.New(sha1.New, key)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	s := mac.Sum(nil)
	off := s[len(s)-1] & 0x0f
	code := (uint32(s[off]&0x7f)<<24 | uint32(s[off+1])<<16 | uint32(s[off+2])<<8 | uint32(s[off+3])) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

func (TOTP) Verify(secret, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	cur := now.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		step := cur + d
		if step < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(step))), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
