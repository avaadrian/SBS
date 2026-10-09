/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * bpf_min.h - a minimal, self-contained substitute for libbpf's
 * <bpf/bpf_helpers.h> and <bpf/bpf_helper_defs.h>.
 *
 * The usual CO-RE toolchain depends on the libbpf development headers being
 * installed (package libbpf-dev / the kernel's tools/lib/bpf). Those are not
 * present in every build environment, so rather than vendor the full
 * auto-generated bpf_helper_defs.h (~200 helper prototypes) we declare only
 * the handful of helpers this program calls.
 *
 * Each helper is a function pointer whose integer value is the helper ID from
 * `enum bpf_func_id` in include/uapi/linux/bpf.h. Those IDs are stable UAPI.
 * This is exactly the shape libbpf's generated header uses:
 *     static <ret> (* const name)(args) = (void *) BPF_FUNC_xxx;
 *
 * If you have libbpf-dev installed you may instead replace this header with the
 * standard includes:
 *     #include <bpf/bpf_helpers.h>
 *     #include <bpf/bpf_core_read.h>
 * See BUILD.md.
 */
#ifndef __BPF_MIN_H__
#define __BPF_MIN_H__

/* Place a symbol in a named ELF section (program, maps, license). */
#define SEC(name) __attribute__((section(name), used))

/*
 * BTF map definition macros. A BTF-defined map is a struct whose members
 * encode the map attributes as array/pointer types; libbpf and cilium/ebpf
 * read the member types out of BTF. `__uint(k, v)` encodes an integer
 * attribute v, `__type(k, v)` encodes a key/value type.
 */
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* Map type constants, from enum bpf_map_type in uapi/linux/bpf.h. */
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27

/* Ring buffer reservation flags, from uapi/linux/bpf.h. */
#define BPF_RB_NO_WAKEUP 1
#define BPF_RB_FORCE_WAKEUP 2

/*
 * Helper IDs from enum bpf_func_id (uapi/linux/bpf.h). Stable UAPI.
 */
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_get_current_uid_gid 15
#define BPF_FUNC_get_current_comm 16
#define BPF_FUNC_probe_read_kernel_str 115
#define BPF_FUNC_ringbuf_reserve 131
#define BPF_FUNC_ringbuf_submit 132
#define BPF_FUNC_ringbuf_discard 133

/* Look up a map element by key; returns a pointer to the value or NULL. */
static void *(*const bpf_map_lookup_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;

/* u64: (tgid << 32) | pid, where pid is the kernel thread id. */
static __u64 (*const bpf_get_current_pid_tgid)(void) =
	(void *)BPF_FUNC_get_current_pid_tgid;

/* u64: (gid << 32) | uid. */
static __u64 (*const bpf_get_current_uid_gid)(void) =
	(void *)BPF_FUNC_get_current_uid_gid;

/* Copy the current task's comm (TASK_COMM_LEN bytes) into buf. */
static long (*const bpf_get_current_comm)(void *buf, __u32 size_of_buf) =
	(void *)BPF_FUNC_get_current_comm;

/* NUL-terminated copy of a kernel string into dst; returns bytes copied. */
static long (*const bpf_probe_read_kernel_str)(void *dst, __u32 size,
					       const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read_kernel_str;

/* Reserve `size` bytes in ring buffer `ringbuf`; returns ptr or NULL. */
static void *(*const bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
					  __u64 flags) =
	(void *)BPF_FUNC_ringbuf_reserve;

/* Submit a previously reserved record. */
static void (*const bpf_ringbuf_submit)(void *data, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_submit;

/* Discard a previously reserved record. */
static void (*const bpf_ringbuf_discard)(void *data, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_discard;

#endif /* __BPF_MIN_H__ */
