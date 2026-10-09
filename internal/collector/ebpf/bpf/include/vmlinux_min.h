/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vmlinux_min.h - a hand-written, minimal substitute for the full vmlinux.h
 * that `bpftool btf dump file /sys/kernel/btf/vmlinux format c` would emit.
 *
 * bpftool is not available in every build environment, so instead of a
 * multi-megabyte generated header we declare only the kernel types this
 * program actually touches:
 *
 *   - the fixed-width integer and pid_t typedefs, and
 *   - the `sched_process_exec` tracepoint context struct.
 *
 * The struct is named exactly as it appears in the kernel's BTF
 * (`trace_event_raw_sched_process_exec`) and wrapped in the libbpf
 * `preserve_access_index` pragma so that every field read becomes a CO-RE
 * relocation. The loader (cilium/ebpf) resolves those relocations against the
 * running kernel's BTF at load time, which is what makes the object portable
 * across kernel versions (Compile Once - Run Everywhere).
 *
 * To regenerate the real, complete header on a host that has bpftool:
 *     bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 * and replace the #include in exec.bpf.c. See BUILD.md.
 */
#ifndef __VMLINUX_MIN_H__
#define __VMLINUX_MIN_H__

#ifndef __bpf__
/* Only meaningful when compiled with clang -target bpf. */
#endif

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef short __s16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;

typedef int pid_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

/*
 * Emit CO-RE relocations for every field access in the structs below. This is
 * the same mechanism libbpf's generated vmlinux.h uses.
 */
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

/* Common header shared by every ftrace tracepoint record. */
struct trace_entry {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

/*
 * Layout of the sched_process_exec tracepoint, matching the kernel's
 * `trace_event_raw_sched_process_exec`. `__data_loc_filename` is a packed
 * u32: the low 16 bits are the byte offset of the filename string from the
 * start of the record, the high 16 bits are its length.
 */
struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	__u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
};

#pragma clang attribute pop

#endif /* __VMLINUX_MIN_H__ */
