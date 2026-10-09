// Package ebpf is an eBPF-based process-exec collector for the SBS agent.
//
// It attaches a CO-RE eBPF program to the kernel's sched_process_exec
// tracepoint and streams one record per successful exec through a BPF ring
// buffer. Compared with the /proc poller it cannot miss short-lived processes,
// and compared with the netlink process connector it also captures the exec'd
// filename and comm directly from the kernel, so a record is still useful even
// when the process has already exited by the time /proc is read.
//
// The collector exposes the same interface as the other process collectors in
// internal/collector/proc, so the agent can select it as a drop-in process
// source:
//
//	c, err := ebpf.Open()
//	if err != nil { ... }
//	defer c.Close()
//	err = c.Run(ctx, out, skip)
//
// The real implementation lives in collector.go behind the "ebpf" build tag and
// depends on a compiled BPF object. Building without that tag (the default)
// uses the stub in stub.go, whose Open returns an error; this keeps the default
// build free of any eBPF toolchain or cilium/ebpf runtime dependency while the
// package still compiles with `go build ./...`.
//
// See BUILD.md for how to (re)generate the BPF object and build with -tags ebpf.
package ebpf

import "errors"

// ErrNotBuilt is returned by Open when the agent was compiled without the
// "ebpf" build tag, so the eBPF program and its cilium/ebpf runtime are not
// linked in. Callers treat it as a signal to fall back to another process
// source (netlink or procfs). It is defined here (untagged) so both the stub
// and the real build, and callers in other packages, can reference it.
var ErrNotBuilt = errors.New("ebpf collector not built (rebuild with -tags ebpf)")

// Regenerate the BPF object and Go bindings (bpf_bpfel.o / bpf_bpfel.go) from
// bpf/exec.bpf.c. Requires clang; run with the ebpf tag so the generated,
// ebpf-tagged files are picked up: `go generate -tags ebpf ./internal/collector/ebpf/`.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type exec_event -tags ebpf -go-package ebpf bpf bpf/exec.bpf.c
