package agent

import "github.com/avaadrian/sbs/internal/collector/fs"

// defaultWatch is the built-in list of watched paths. Tags are what file
// rules match on: persistence, preload, accounts, ssh, drop.
func defaultWatch() []fs.Watch {
	return []fs.Watch{
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
}
