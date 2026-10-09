package response

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKillRefuses(t *testing.T) {
	a := NewActioner()
	for _, pid := range []int{0, 1, -1} {
		if r := a.Kill(pid); r.OK {
			t.Errorf("Kill(%d) should be refused", pid)
		}
	}
	// The agent must never kill itself.
	r := a.Kill(os.Getpid())
	if r.OK {
		t.Fatalf("Kill(self) should be refused")
	}
	if r.Error == "" {
		t.Fatalf("refusal should carry an error")
	}
	if r.Action != "kill" {
		t.Fatalf("action = %q", r.Action)
	}
	// Target records the pid string.
	if r2 := a.Kill(1); r2.Target != "1" {
		t.Fatalf("target = %q, want 1", r2.Target)
	}
}

func TestQuarantineMovesAndStrips(t *testing.T) {
	a := NewActioner()
	dir := t.TempDir()
	src := filepath.Join(dir, "evil.sh")
	if err := os.WriteFile(src, []byte("#!/bin/sh\nrm -rf /\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	qdir := filepath.Join(dir, "quarantine")

	r := a.Quarantine(src, qdir)
	if !r.OK {
		t.Fatalf("quarantine failed: %q", r.Error)
	}
	if r.Detail == "" {
		t.Fatalf("detail should be the destination path")
	}
	// Original is gone.
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	// Destination exists with no permission bits.
	st, err := os.Stat(r.Detail)
	if err != nil {
		t.Fatalf("destination missing: %v", err)
	}
	if st.Mode().Perm() != 0 {
		t.Fatalf("destination perms = %o, want 0", st.Mode().Perm())
	}
	// Destination name is <sha256-of-path>-<basename>.
	if filepath.Dir(r.Detail) != qdir {
		t.Fatalf("destination not in quarantine dir: %s", r.Detail)
	}
	if filepath.Base(r.Detail)[64:] != "-evil.sh" {
		t.Fatalf("destination basename = %q", filepath.Base(r.Detail))
	}
}

func TestQuarantineRefuses(t *testing.T) {
	a := NewActioner()
	qdir := filepath.Join(t.TempDir(), "q")

	// A pseudo-filesystem path.
	if r := a.Quarantine("/proc/1/stat", qdir); r.OK {
		t.Errorf("should refuse /proc path")
	}
	// A directory is not a regular file.
	dir := t.TempDir()
	if r := a.Quarantine(dir, qdir); r.OK {
		t.Errorf("should refuse a directory")
	}
	// A missing file.
	if r := a.Quarantine(filepath.Join(dir, "nope"), qdir); r.OK {
		t.Errorf("should refuse a missing file")
	}
}
