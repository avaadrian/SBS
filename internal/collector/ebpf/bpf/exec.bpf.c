// SPDX-License-Identifier: GPL-2.0
//
// exec.bpf.c - a CO-RE eBPF program that reports every process exec.
//
// It attaches to the sched/sched_process_exec tracepoint, which fires once per
// successful execve/execveat after the new program image is installed. Unlike
// polling /proc, this cannot miss a short-lived process, and unlike the
// netlink process connector it also captures the executable filename straight
// from the kernel (so enrichment still works even when the process has already
// exited by the time user space looks at /proc).
//
// For each exec it reserves a record in a BPF ring buffer and fills in the
// userspace PID (tgid), the thread id, the real UID, the comm and the exec'd
// filename, then submits it. User space (collector.go) reads the ring buffer,
// enriches the record from /proc, and emits an *event.Event.
//
// The program is Compile Once - Run Everywhere: field accesses on the
// tracepoint context are CO-RE relocations (see vmlinux_min.h), resolved by
// the loader against the running kernel's BTF.

#include "include/vmlinux_min.h"
#include "include/bpf_min.h"

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// exec_event is the record written to the ring buffer. Its layout is shared
// with user space: bpf2go generates the matching Go struct (bpfExecEvent) from
// this type's BTF, and collector.go decodes each ring-buffer record into it.
// TestExecEventLayout guards the size, so keep the two in sync.
struct exec_event {
	__u32 pid;  // thread group id == userspace PID (what /proc is keyed on)
	__u32 tid;  // kernel thread id (equals pid for the exec'ing task)
	__u32 uid;  // real UID
	__u32 _pad; // explicit padding so comm/filename are predictably aligned
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[MAX_FILENAME_LEN];
};

// Anchor struct exec_event in the object's BTF so bpf2go's `-type exec_event`
// can find it by name and emit the matching Go struct (bpfExecEvent).
const struct exec_event *unused_exec_event __attribute__((unused));

// 4 MiB ring buffer. Sized generously because exec storms (shell scripts,
// build systems) can be bursty; overflow is handled as lost samples.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

// Per-CPU count of exec events dropped because the ring buffer was full. A
// ring buffer (unlike a perf buffer) does not surface lost samples to user
// space, so we count them in the kernel and let the collector read the total.
// Per-CPU means the increment needs no atomics.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct exec_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		// Ring buffer full: record the drop so the collector can report it.
		__u32 k = 0;
		__u64 *d = bpf_map_lookup_elem(&dropped, &k);
		if (d)
			*d += 1; // per-CPU slot, so no atomic needed
		return 0;
	}

	e->pid = (__u32)(pid_tgid >> 32);
	e->tid = (__u32)pid_tgid;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->_pad = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// The filename string lives at `ctx + (data_loc & 0xffff)` inside the
	// tracepoint record; the high 16 bits hold its length (unused here).
	unsigned short off = (unsigned short)(ctx->__data_loc_filename & 0xffff);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
				  (char *)ctx + off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Ring buffer and probe_read_kernel helpers are GPL-only, so the program must
// declare a GPL-compatible license.
char LICENSE[] SEC("license") = "GPL";
