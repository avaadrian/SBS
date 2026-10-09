package scanner

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const sigs = `
hashes:
  - sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    name: Hello.Hash
signatures:
  - name: Two.Of.Three
    strings: ["alpha", "beta", "hex:00ff"]
    condition: "2"
  - name: NoCase.All
    nocase: true
    strings: ["Foo", "BAR"]
    condition: all
`

func TestScanBytes(t *testing.T) {
	s := New()
	if err := s.Add([]byte(sigs), "t"); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"hello":                   {"Hello.Hash"},
		"alpha and beta":          {"Two.Of.Three"},
		"alpha \x00\xff":          {"Two.Of.Three"},
		"only alpha":              nil,
		"fOO then bar":            {"NoCase.All"},
		"foo alone":               nil,
		"alpha beta foo BAR ok!!": {"Two.Of.Three", "NoCase.All"},
	}
	for in, want := range cases {
		_, got := s.ScanBytes([]byte(in))
		if len(got) != len(want) {
			t.Errorf("%q: got %v want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i].Signature != want[i] {
				t.Errorf("%q: got %s want %s", in, got[i].Signature, want[i])
			}
		}
	}
}

func TestBadSignatures(t *testing.T) {
	for _, y := range []string{
		"hashes: [{sha256: abc, name: x}]",
		"signatures: [{name: x, strings: [a], condition: '3'}]",
		"signatures: [{name: x, strings: ['hex:zz']}]",
		"signatures: [{strings: [a]}]",
	} {
		if err := New().Add([]byte(y), "t"); err == nil {
			t.Errorf("%s: expected error", y)
		}
	}
}

func TestScanFileCacheAndSize(t *testing.T) {
	s := New()
	s.Add([]byte(sigs), "t")
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	os.WriteFile(p, []byte("hello"), 0o644)
	if _, m, _ := s.ScanFile(p); len(m) != 1 {
		t.Fatalf("want 1 match, got %v", m)
	}
	os.WriteFile(p, []byte("clean file"), 0o644)
	if _, m, _ := s.ScanFile(p); len(m) != 0 {
		t.Fatalf("stale cache: %v", m)
	}
	s.MaxSize = 3
	if sha, m, _ := s.ScanFile(p); sha != "" || m != nil {
		t.Fatalf("oversized file should be skipped")
	}
}

func TestEICARHex(t *testing.T) {
	// Sanity check that the hex in assets decodes to the EICAR marker.
	b, _ := hex.DecodeString("45494341522d5354414e444152442d414e544956495255532d544553542d46494c45")
	if string(b) != "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" {
		t.Fatal(string(b))
	}
}
