package response

import (
	"os"
	"path/filepath"
	"testing"
)

// TestQuarantineRefusesSystemTrees checks the expanded protected-root deny-list.
func TestQuarantineRefusesSystemTrees(t *testing.T) {
	a := NewActioner()
	q := t.TempDir()
	for _, p := range []string{"/etc/ld.so.preload", "/usr/bin/x", "/bin/sh", "/boot/vmlinuz", "/proc/1/mem"} {
		if r := a.Quarantine(p, q); r.OK {
			t.Errorf("quarantine should refuse %s", p)
		}
	}
}

// TestQuarantineRefusesSymlink ensures a symlink is never followed/moved.
func TestQuarantineRefusesSymlink(t *testing.T) {
	a := NewActioner()
	dir := t.TempDir()
	q := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("sensitive"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	r := a.Quarantine(link, q)
	if r.OK {
		t.Fatal("quarantine should refuse a symlink")
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("target must be untouched: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "sensitive" {
		t.Error("target contents changed")
	}
}

// TestQuarantineRegularFileStripsPerms covers the normal path.
func TestQuarantineRegularFileStripsPerms(t *testing.T) {
	a := NewActioner()
	dir := t.TempDir()
	q := t.TempDir()
	p := filepath.Join(dir, "evil")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := a.Quarantine(p, q)
	if !r.OK {
		t.Fatalf("quarantine failed: %s", r.Error)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("original should be gone")
	}
	fi, err := os.Stat(r.Detail)
	if err != nil {
		t.Fatalf("quarantined file missing: %v", err)
	}
	if fi.Mode().Perm() != 0 {
		t.Errorf("quarantined perms = %o, want 0", fi.Mode().Perm())
	}
}
