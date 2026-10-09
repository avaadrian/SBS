//go:build ebpf

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/avaadrian/sbs/internal/collector/proc"
	"github.com/avaadrian/sbs/internal/event"
)

// source is the event.Event.Source value this collector stamps on its events.
const source = "ebpf"

// dropPollInterval is how often Run checks the in-kernel dropped-sample counter.
const dropPollInterval = 5 * time.Second

// Collector streams process-exec events from the kernel. It loads a CO-RE eBPF
// program (see bpf/exec.bpf.c), attaches it to the sched_process_exec
// tracepoint, and reads exec records from a BPF ring buffer.
//
// It implements the same Run(ctx, out, skip) interface as the netlink and
// procfs collectors in internal/collector/proc, so it is a drop-in process
// source.
type Collector struct {
	objs   bpfObjects
	link   link.Link
	reader *ringbuf.Reader
}

// Open loads and attaches the eBPF program and opens the ring buffer reader.
//
// Requirements: a Linux kernel with BTF (/sys/kernel/btf/vmlinux), ring buffer
// support (>= 5.8) and the capabilities to load BPF and attach a tracepoint
// (CAP_BPF + CAP_PERFMON on >= 5.8, or CAP_SYS_ADMIN; in practice: root).
func Open() (*Collector, error) {
	// Raise RLIMIT_MEMLOCK. Needed on kernels < 5.11 that account BPF memory
	// against it; a no-op cost on newer kernels.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock rlimit: %w", err)
	}

	c := &Collector{}
	if err := loadBpfObjects(&c.objs, nil); err != nil {
		// Surface the verifier log when the program is rejected; it is the
		// single most useful thing for debugging a load failure.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("ebpf: load objects: %+v", ve)
		}
		return nil, fmt.Errorf("ebpf: load objects: %w", err)
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", c.objs.HandleExec, nil)
	if err != nil {
		c.objs.Close()
		return nil, fmt.Errorf("ebpf: attach sched_process_exec tracepoint: %w", err)
	}
	c.link = tp

	rd, err := ringbuf.NewReader(c.objs.Events)
	if err != nil {
		c.link.Close()
		c.objs.Close()
		return nil, fmt.Errorf("ebpf: open ring buffer: %w", err)
	}
	c.reader = rd
	return c, nil
}

// Run emits a process event for every exec until ctx is cancelled. It mirrors
// proc.Netlink.Run: out receives one *event.Event per exec, and skip (when
// non-nil) suppresses events for a pid (the agent uses it to drop its own).
func (c *Collector) Run(ctx context.Context, out chan<- *event.Event, skip func(pid int) bool) error {
	// Unblock the blocking reader.Read when the context is cancelled.
	go func() {
		<-ctx.Done()
		c.reader.Close()
	}()

	// Periodically report exec events the kernel had to drop (ring buffer full).
	go c.watchDrops(ctx)

	var rec ringbuf.Record
	for {
		if err := c.reader.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil // reader closed by Close() or ctx cancel
			}
			return fmt.Errorf("ebpf: ring buffer read: %w", err)
		}

		var e bpfExecEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue // truncated/garbage record; skip it
		}

		pid := int(e.Pid)
		if skip != nil && skip(pid) {
			continue
		}

		p := proc.Read(pid)
		if p == nil {
			// The process already exited before we could read /proc. This is
			// exactly the race the /proc-based collectors lose; here we still
			// have the pid, uid, comm and filename captured in the kernel, so
			// emit a best-effort record instead of dropping the exec.
			p = fromKernel(&e)
		}

		select {
		case out <- proc.NewEvent(p, source):
		case <-ctx.Done():
			return nil
		}
	}
}

// Close detaches the program and releases all eBPF resources. It is safe to
// call after a failed Open on a partially initialised Collector.
func (c *Collector) Close() error {
	var first error
	if c.reader != nil {
		if err := c.reader.Close(); err != nil {
			first = err
		}
	}
	if c.link != nil {
		if err := c.link.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := c.objs.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

// watchDrops polls the per-CPU dropped-sample counter and logs the total
// whenever it grows, so lost execs are visible rather than silent.
func (c *Collector) watchDrops(ctx context.Context) {
	t := time.NewTicker(dropPollInterval)
	defer t.Stop()
	var last uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if total, err := c.droppedTotal(); err == nil && total > last {
				log.Printf("ebpf: ring buffer full, %d exec event(s) dropped (total %d)", total-last, total)
				last = total
			}
		}
	}
}

// droppedTotal sums the per-CPU dropped counters into a single total.
func (c *Collector) droppedTotal() (uint64, error) {
	perCPU := make([]uint64, runtime.NumCPU())
	if err := c.objs.Dropped.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// fromKernel builds a minimal Process from the data captured in the eBPF
// program, used when /proc enrichment fails because the process already exited.
func fromKernel(e *bpfExecEvent) *event.Process {
	exe := cstr(e.Filename[:])
	return &event.Process{
		PID:     int(e.Pid),
		UID:     int(e.Uid),
		Comm:    cstr(e.Comm[:]),
		Exe:     exe,
		Cmdline: exe, // argv is not captured in v1; the exec path is the best we have
	}
}

// cstr converts a NUL-terminated C byte array to a Go string.
func cstr(b []uint8) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
