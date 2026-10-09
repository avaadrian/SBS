package transport

import "testing"

func TestCheckURL(t *testing.T) {
	cases := []struct {
		url      string
		insecure bool
		ok       bool
	}{
		{"https://sbs.example.com", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"http://localhost:8080", false, true},
		{"http://[::1]:8080", false, true},
		{"http://sbs.example.com", false, false}, // plaintext to a network host
		{"http://sbs.example.com", true, true},   // explicit opt-in
		{"ftp://sbs.example.com", false, false},  // unsupported scheme
	}
	for _, c := range cases {
		err := checkURL(c.url, c.insecure)
		if (err == nil) != c.ok {
			t.Errorf("checkURL(%q, insecure=%v) err=%v, want ok=%v", c.url, c.insecure, err, c.ok)
		}
	}
}
