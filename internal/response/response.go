// Package response performs automatic response actions on alerts: killing a
// process or moving a file into quarantine. The actions refuse the obviously
// dangerous cases (killing init or the agent itself, quarantining pseudo-files)
// so a bad rule cannot take down the host.
package response

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// protectedRoots are filesystem trees the agent never quarantines from:
// pseudo-filesystems and the core system trees whose files must not be moved
// or have their permissions stripped.
var protectedRoots = []string{
	"/proc", "/sys", "/dev", "/run",
	"/boot", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
	"/usr", "/etc",
}

// Actioner runs response actions. It is safe for concurrent use.
type Actioner struct{}

// NewActioner returns an Actioner.
func NewActioner() *Actioner { return &Actioner{} }

// Kill sends SIGKILL to pid. It refuses to kill init (pid <= 1), the agent's
// own process, or the agent's process group, so a misfire cannot stop the
// agent or the whole system.
func (a *Actioner) Kill(pid int) event.ActionResult {
	res := event.ActionResult{Action: "kill", Target: strconv.Itoa(pid), Time: time.Now().UTC()}
	switch {
	case pid <= 1:
		// pid 0 and negatives signal whole process groups; 1 is init.
		res.Error = "refusing to kill pid <= 1"
		return res
	case pid == os.Getpid():
		res.Error = "refusing to kill self"
		return res
	case pid == syscall.Getpgrp():
		res.Error = "refusing to kill own process group"
		return res
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	return res
}

// Quarantine moves path into quarantineDir and strips its permissions. The
// destination is "<sha256-of-path>-<basename>". It falls back to copy+remove
// when a rename crosses filesystems. It refuses pseudo-filesystems and anything
// that is not a regular file.
func (a *Actioner) Quarantine(path, quarantineDir string) event.ActionResult {
	res := event.ActionResult{Action: "quarantine", Target: path, Time: time.Now().UTC()}
	clean := filepath.Clean(path)
	for _, r := range protectedRoots {
		if clean == r || strings.HasPrefix(clean, r+"/") {
			res.Error = "refusing to quarantine under " + r
			return res
		}
	}
	// Lstat: a symlink is not a regular file and must not be followed.
	st, err := os.Lstat(path)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if !st.Mode().IsRegular() {
		res.Error = "not a regular file"
		return res
	}
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		res.Error = err.Error()
		return res
	}
	sum := sha256.Sum256([]byte(path))
	dest := filepath.Join(quarantineDir, hex.EncodeToString(sum[:])+"-"+filepath.Base(path))
	// The source lives in an attacker-writable directory, so between the Lstat
	// above and this move it may be swapped for a symlink (TOCTOU). os.Rename
	// moves the symlink itself, and a path-based chmod would then follow it and
	// hit an arbitrary file. So after any move we re-open the destination with
	// O_NOFOLLOW and strip permissions through that fd, never through the path.
	if err := os.Rename(path, dest); err != nil {
		if cerr := copyRemove(path, dest); cerr != nil {
			res.Error = cerr.Error()
			return res
		}
	}
	f, err := os.OpenFile(dest, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// A symlink was moved into place, or the file vanished: discard it.
		os.Remove(dest)
		res.Error = "quarantine destination is not a regular file: " + err.Error()
		return res
	}
	defer f.Close()
	if fi, e := f.Stat(); e != nil || !fi.Mode().IsRegular() {
		os.Remove(dest)
		res.Error = "quarantine destination is not a regular file"
		return res
	}
	// Strip all permissions so the quarantined file cannot be run or read.
	if err := f.Chmod(0o000); err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	res.Detail = dest
	return res
}

// copyRemove copies src to dst then removes src, for renames across filesystems.
// The source is opened O_NOFOLLOW so a symlink swapped in after the caller's
// regular-file check cannot redirect the read to another file; the destination
// is created O_EXCL so a pre-planted symlink there is not written through.
func copyRemove(src, dst string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	if fi, err := in.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file")
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	in.Close()
	return os.Remove(src)
}
