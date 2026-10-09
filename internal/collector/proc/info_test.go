package proc

import (
	"os"
	"testing"
)

func TestDecodeAddr(t *testing.T) {
	cases := map[string]string{
		"0100007F:1F90":                         "127.0.0.1:8080",
		"00000000000000000000000001000000:0016": "[::1]:22",
		"0000000000000000FFFF00000100007F:01BB": "127.0.0.1:443",
	}
	for in, want := range cases {
		if got := decodeAddr(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestReadSelf(t *testing.T) {
	p := Read(os.Getpid())
	if p == nil || p.PID != os.Getpid() || p.PPID != os.Getppid() || p.Exe == "" {
		t.Fatalf("bad self record: %+v", p)
	}
}
