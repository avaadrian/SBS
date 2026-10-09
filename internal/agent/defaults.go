package agent

import (
	"path/filepath"

	"github.com/avaadrian/sbs/internal/collector/fs"
)

// defaultWatch is the built-in list of watched paths. Tags are what file
// rules match on: persistence, preload, accounts, ssh, drop.
//
// Rather than recursively watching all of /home (which would register an
// inotify watch per directory and signature-scan every file written anywhere
// under it — a resource and inotify-exhaustion risk), it enumerates the
// existing per-user ~/.ssh directories once at startup.
func defaultWatch() []fs.Watch {
	w := []fs.Watch{
		{Path: "/etc/cron.d", Tag: "persistence"},
		{Path: "/etc/crontab", Tag: "persistence"},
		{Path: "/var/spool/cron", Tag: "persistence", Recursive: true},
		{Path: "/etc/systemd/system", Tag: "persistence", Recursive: true},
		{Path: "/etc/init.d", Tag: "persistence"},
		{Path: "/etc/rc.local", Tag: "persistence"},
		{Path: "/etc/profile.d", Tag: "persistence"},
		{Path: "/etc/ld.so.preload", Tag: "preload"},
		{Path: "/etc/passwd", Tag: "accounts"},
		{Path: "/etc/shadow", Tag: "accounts"},
		{Path: "/etc/sudoers", Tag: "accounts"},
		{Path: "/etc/sudoers.d", Tag: "accounts"},
		{Path: "/root/.ssh", Tag: "ssh"},
		{Path: "/tmp", Tag: "drop"},
		{Path: "/dev/shm", Tag: "drop"},
		{Path: "/var/tmp", Tag: "drop"},
	}
	// Each user's ~/.ssh, enumerated once (new homes created later are not
	// covered until a restart — a deliberate tradeoff against watching /home).
	if dirs, err := filepath.Glob("/home/*/.ssh"); err == nil {
		for _, d := range dirs {
			w = append(w, fs.Watch{Path: d, Tag: "ssh"})
		}
	}
	return w
}
