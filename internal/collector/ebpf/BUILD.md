# eBPF process-exec collector

An eBPF-based replacement for the netlink / procfs process collectors. It
attaches a CO-RE eBPF program to the kernel's `sched_process_exec` tracepoint
and streams one record per exec through a BPF ring buffer. It exposes the same
interface as the collectors in `internal/collector/proc`:

```go
c, err := ebpf.Open()
if err != nil { /* fall back to another source */ }
defer c.Close()
err = c.Run(ctx, out, skip) // out chan<- *event.Event, skip func(pid int) bool
```

## Why eBPF

- **No missed short-lived processes.** The tracepoint fires inside `execve`, so
  there is no `/proc` race like the poller has.
- **Survivable enrichment.** The exec'd filename, comm, pid and uid are captured
  in the kernel, so a record is still useful when the process has already exited
  before user space reads `/proc` (the weakness of both the poller and the
  netlink connector). `/proc` is still used to enrich the common case
  (`proc.Read`); the kernel data is the fallback.

## Build tags

The package compiles in two forms:

| Build | File | Behaviour |
| --- | --- | --- |
| default (`go build ./...`) | `stub.go` (`//go:build !ebpf`) | `Open()` returns `ErrNotBuilt`; **no** cilium/ebpf code is linked and no eBPF toolchain is needed. |
| `-tags ebpf` | `collector.go` + generated `bpf_bpfel.go`/`bpf_bpfel.o` | the real collector. |

So the default build and the default test suite are completely unaffected by
this package.

```sh
# Default (stub) build — always works, no privileges, no toolchain:
go build ./...

# Real collector:
go build -tags ebpf ./...
go test  -tags ebpf ./internal/collector/ebpf/   # parses the embedded object; no root needed
```

## Runtime requirements

Loading and attaching the program (i.e. a successful `Open()`) needs:

- **Linux ≥ 5.8** for BPF ring buffers (`BPF_MAP_TYPE_RINGBUF`).
- **Kernel BTF**: `/sys/kernel/btf/vmlinux` must exist (`CONFIG_DEBUG_INFO_BTF=y`).
  The loader uses it to apply the program's CO-RE relocations.
- **Capabilities**: `CAP_BPF` + `CAP_PERFMON` (kernel ≥ 5.8) to load the program
  and read the ring buffer, plus the ability to attach a tracepoint
  (historically `CAP_SYS_ADMIN`). In practice: run as **root**.
- `RLIMIT_MEMLOCK` is raised automatically (needed only on kernels < 5.11).

If any of these are missing, `Open()` returns a descriptive error and the caller
should fall back to the netlink or procfs source.

## Regenerating the BPF object

The committed `bpf_bpfel.o` (the compiled program) and `bpf_bpfel.go` (its Go
bindings) are produced from `bpf/exec.bpf.c` by
[`bpf2go`](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go). You only need
to regenerate them if you change the C program.

Requirements: `clang` (tested with clang 18) and the `ebpf` build tag so the
generated, `ebpf`-tagged files are picked up by `go generate`:

```sh
go generate -tags ebpf ./internal/collector/ebpf/
```

which runs (see `doc.go`):

```sh
go run github.com/cilium/ebpf/cmd/bpf2go \
    -target bpfel -type exec_event -tags ebpf -go-package ebpf \
    bpf bpf/exec.bpf.c
```

`-target bpfel` emits a little-endian object (covers amd64 and arm64). Commit
the regenerated `bpf_bpfel.o` and `bpf_bpfel.go`.

### Headers: no bpftool / libbpf-dev required

A normal CO-RE program `#include`s a generated `vmlinux.h`
(`bpftool btf dump file /sys/kernel/btf/vmlinux format c`) and libbpf's
`<bpf/bpf_helpers.h>`. Neither `bpftool` nor `libbpf-dev` is guaranteed to be
present, so this package is self-contained and vendors minimal substitutes under
`bpf/include/`:

- `vmlinux_min.h` — the integer typedefs plus the `sched_process_exec`
  tracepoint struct, named exactly as in the kernel BTF and wrapped in the
  libbpf `preserve_access_index` pragma, so field reads become CO-RE
  relocations that the loader resolves against the running kernel.
- `bpf_min.h` — the `SEC`/`__uint`/`__type` map macros and prototypes for the
  seven BPF helpers the program calls, each as a function pointer whose value is
  its `enum bpf_func_id` number (stable UAPI).

If you prefer the standard toolchain, install `libbpf-dev` and `bpftool`,
replace the two includes in `bpf/exec.bpf.c` with:

```c
#include "vmlinux.h"            // bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
```

and regenerate. The program itself does not otherwise change.

## go.mod

This package adds one dependency:

```
github.com/cilium/ebpf v0.19.0
```

v0.19.0 is used deliberately: it is the newest release whose `go` directive
(`go 1.23.0`) is satisfied by this module's Go 1.24 toolchain. v0.20+ require
Go ≥ 1.24.x and v0.22 requires Go 1.25, which would force a toolchain bump.

`go mod tidy` keeps this dependency (it evaluates build-tagged imports) and
records it as a direct require; module-graph pruning means no extra entries
appear in the `require` block beyond `cilium/ebpf` itself.

## Limitations (v1)

- **argv / full cmdline** is not captured in the kernel. When `/proc` enrichment
  succeeds (the normal case) the full cmdline is read from
  `/proc/<pid>/cmdline`. When the process has already exited, the fallback
  record sets `Cmdline` to the exec'd path (from the tracepoint) — the path is
  present but the arguments are not. Capturing argv would require also hooking
  `sys_enter_execve`/`execveat`.
- **Ring-buffer overflow** (an exec storm filling the 4 MiB buffer) drops
  events. A ring buffer does not report lost samples to user space, so the
  program counts drops in a per-CPU map (`dropped`) and `Run` logs the total
  when it grows.
- Only `execve`/`execveat` are observed (process creation). Fork/exit and other
  lifecycle events are out of scope.
