// Package fs watches filesystem paths with inotify.
package fs

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// Watch is one configured path. A file path (or a path that does not exist
// yet) is watched through its parent directory.
type Watch struct {
	Path      string `yaml:"path"`
	Tag       string `yaml:"tag"`
	Recursive bool   `yaml:"recursive"`
}

const mask = syscall.IN_CREATE | syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO |
	syscall.IN_DELETE | syscall.IN_ATTRIB | syscall.IN_DONT_FOLLOW

type target struct {
	dir       string
	only      string // when watching a single file: its base name
	tag       string
	recursive bool
}

// Watcher turns inotify events into file events.
type Watcher struct {
	fd      int
	mu      sync.Mutex
	targets map[int32][]target
}

// New creates a watcher and registers every configured path. Paths that
// cannot be watched are logged and skipped.
func New(watches []Watch) (*Watcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("inotify: %w", err)
	}
	w := &Watcher{fd: fd, targets: map[int32][]target{}}
	for _, wt := range watches {
		path := filepath.Clean(os.ExpandEnv(wt.Path))
		st, err := os.Stat(path)
		switch {
		case err == nil && st.IsDir():
			if wt.Recursive {
				filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
					if err == nil && d.IsDir() {
						w.add(target{dir: p, tag: wt.Tag, recursive: true})
					}
					return nil
				})
			} else {
				w.add(target{dir: path, tag: wt.Tag})
			}
		default:
			// A file, or a path that may be created later: watch the parent.
			if err := w.add(target{dir: filepath.Dir(path), only: filepath.Base(path), tag: wt.Tag}); err != nil {
				log.Printf("fs: cannot watch %s: %v", path, err)
			}
		}
	}
	return w, nil
}

func (w *Watcher) add(t target) error {
	wd, err := syscall.InotifyAddWatch(w.fd, t.dir, mask)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.targets[int32(wd)] = append(w.targets[int32(wd)], t)
	w.mu.Unlock()
	return nil
}

// Run reads inotify events until ctx is done.
func (w *Watcher) Run(ctx context.Context, out chan<- *event.Event) error {
	go func() {
		<-ctx.Done()
		syscall.Close(w.fd)
	}()
	buf := make([]byte, 64<<10)
	for {
		n, err := syscall.Read(w.fd, buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("inotify read: %w", err)
		}
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			wd := int32(binary.LittleEndian.Uint32(buf[off:]))
			m := binary.LittleEndian.Uint32(buf[off+4:])
			nameLen := int(binary.LittleEndian.Uint32(buf[off+12:]))
			name := strings.TrimRight(string(buf[off+syscall.SizeofInotifyEvent:off+syscall.SizeofInotifyEvent+nameLen]), "\x00")
			off += syscall.SizeofInotifyEvent + nameLen
			if m&syscall.IN_Q_OVERFLOW != 0 {
				log.Printf("fs: inotify queue overflow, events dropped")
				continue
			}
			w.mu.Lock()
			ts := w.targets[wd]
			w.mu.Unlock()
			for _, t := range ts {
				if t.only != "" && t.only != name {
					continue
				}
				path := filepath.Join(t.dir, name)
				if m&syscall.IN_ISDIR != 0 {
					if t.recursive && m&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0 {
						w.add(target{dir: path, tag: t.tag, recursive: true})
					}
					continue
				}
				ev := &event.Event{Time: time.Now().UTC(), Type: event.TypeFile, Source: "inotify",
					File: &event.File{Path: path, Op: op(m), Tag: t.tag}}
				if st, err := os.Lstat(path); err == nil {
					ev.File.Size = st.Size()
					ev.File.Mode = fmt.Sprintf("%#o", uint32(st.Mode().Perm())|setid(st.Mode()))
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}

func op(m uint32) string {
	switch {
	case m&syscall.IN_CREATE != 0:
		return "create"
	case m&syscall.IN_MOVED_TO != 0:
		return "rename"
	case m&syscall.IN_DELETE != 0:
		return "delete"
	case m&syscall.IN_ATTRIB != 0:
		return "chmod"
	}
	return "modify"
}

func setid(m os.FileMode) uint32 {
	var v uint32
	if m&os.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		v |= 0o1000
	}
	return v
}
