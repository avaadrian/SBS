// Package response performs automatic response actions on alerts: killing a
// process or moving a file into quarantine. The actions refuse the obviously
// dangerous cases (killing init or the agent itself, quarantining pseudo-files)
// so a bad rule cannot take down the host.
package response

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// protectedRoots are filesystem trees the agent never quarantines from.
var protectedRoots = []string{"/proc", "/sys", "/dev"}

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
	// Rename is atomic within a filesystem; across one (EXDEV) fall back to copy.
	if err := os.Rename(path, dest); err != nil {
		if cerr := copyRemove(path, dest); cerr != nil {
			res.Error = cerr.Error()
			return res
		}
	}
	// Strip all permissions so the quarantined file cannot be run or read.
	if err := os.Chmod(dest, 0o000); err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	res.Detail = dest
	return res
}

// copyRemove copies src to dst then removes src, for renames across filesystems.
func copyRemove(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
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
