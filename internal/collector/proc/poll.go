package proc

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/avaadrian/sbs/internal/event"
)

// Poller finds new processes by scanning /proc on an interval. It works
// without privileges but misses processes shorter than the interval.
type Poller struct {
	Interval time.Duration
	seen     map[int]string // pid -> start time + exe
}

// Run emits an event for every new process (and every re-exec) until ctx is done.
// Processes already running at start are recorded but not reported.
func (p *Poller) Run(ctx context.Context, out chan<- *event.Event, skip func(pid int) bool) error {
	if p.Interval <= 0 {
		p.Interval = 100 * time.Millisecond
	}
	p.seen = map[int]string{}
	p.scan(ctx, nil, skip)
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			p.scan(ctx, out, skip)
		}
	}
}

func (p *Poller) scan(ctx context.Context, out chan<- *event.Event, skip func(int) bool) {
	ents, err := os.ReadDir(ProcRoot)
	if err != nil {
		return
	}
	alive := make(map[int]bool, len(ents))
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		alive[pid] = true
		exe, _ := os.Readlink(ProcRoot + "/" + e.Name() + "/exe")
		key := startTime(pid) + "|" + exe
		if p.seen[pid] == key {
			continue
		}
		p.seen[pid] = key
		if out == nil || (skip != nil && skip(pid)) {
			continue
		}
		if pr := Read(pid); pr != nil {
			select {
			case out <- NewEvent(pr, "procfs"):
			case <-ctx.Done():
				return
			}
		}
	}
	for pid := range p.seen {
		if !alive[pid] {
			delete(p.seen, pid)
		}
	}
}
