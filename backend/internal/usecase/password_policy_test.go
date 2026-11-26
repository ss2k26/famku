package usecase

import "testing"

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		pw, email string
		ok        bool
	}{
		{"correct horse battery", "a@x.io", true},
		{"short", "a@x.io", false},
		{"password1234", "a@x.io", false},
		{"aaaaaaaaaaaaaa", "a@x.io", false},
		{"my-ana.smith-secret", "ana.smith@x.io", false},
		{"Ünïcödé pässphräse 🙂 ok", "a@x.io", true},
	}
	for _, c := range cases {
		if err := ValidatePassword(c.pw, c.email, "Ana"); (err == nil) != c.ok {
			t.Errorf("%q: ok=%v err=%v", c.pw, c.ok, err)
		}
	}
	long := make([]rune, MaxPasswordLen+1)
	for i := range long {
		long[i] = rune('a' + i%26)
	}
	if ValidatePassword(string(long), "a@x.io", "Ana") == nil {
		t.Error("over-long password accepted")
	}
}
