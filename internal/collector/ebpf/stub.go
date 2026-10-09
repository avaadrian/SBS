//go:build !ebpf

package ebpf

import (
	"context"

	"github.com/avaadrian/sbs/internal/event"
)

// Collector is a placeholder so the package compiles under the default build
// tags without pulling in the eBPF toolchain or the cilium/ebpf dependency.
// The functional implementation is in collector.go, gated by //go:build ebpf.
type Collector struct{}

// Open always fails in the stub build. Callers should treat ErrNotBuilt as a
// signal to fall back to another process source (netlink or procfs).
func Open() (*Collector, error) {
	return nil, ErrNotBuilt
}

// Run never executes in the stub build; Open fails first. It exists only so
// the stub Collector satisfies the same interface as the real one.
func (c *Collector) Run(ctx context.Context, out chan<- *event.Event, skip func(pid int) bool) error {
	return ErrNotBuilt
}

// Close is a no-op in the stub build.
func (c *Collector) Close() error { return nil }
