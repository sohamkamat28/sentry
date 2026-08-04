/* Minimal kernel type definitions for the SENTRY sensor.
 *
 * A full vmlinux.h is generated with `bpftool btf dump file /sys/kernel/btf/vmlinux
 * format c` and runs to several megabytes. This program touches exactly three
 * kernel structures, so a hand-written subset is smaller, reviewable, and
 * removes the need to carry a generated artefact matched to one kernel build.
 *
 * Every struct carries preserve_access_index, which is what lets CO-RE relocate
 * field offsets against whatever kernel the probe is actually loaded on. That is
 * the mechanism that makes one compiled object portable across the dozens of
 * kernel versions in a real estate; without it this file would be pinned to the
 * kernel it was written against.
 *
 * If a future probe needs a type not defined here, generate the full header
 * rather than extending this one by hand.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s64 s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __sum16;

typedef __u32 __wsum;
typedef _Bool bool;

enum { false = 0, true = 1 };

#define NULL ((void *)0)

/* sockaddr / sockaddr_in — read by the security_socket_connect kprobe to build
 * the pid+fd -> peer tuple map. */
typedef unsigned short __kernel_sa_family_t;
typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

/* socket — only the type is needed; the kprobe reads its sockaddr argument. */
enum sock_type {
	SOCK_STREAM = 1,
	SOCK_DGRAM = 2,
};

struct sock;
struct file;

struct socket {
	short unsigned int type;
	unsigned long flags;
	struct file *file;
	struct sock *sk;
};

/* Register frames.
 *
 * bpf_tracing.h reaches into these to extract probe arguments, and which one it
 * uses is selected by __TARGET_ARCH_*. Both are declared so one header serves an
 * arm64 and an amd64 build of the same program. */
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};

/* UAPI constants from linux/bpf.h.
 *
 * A generated vmlinux.h carries these because it dumps the whole kernel BTF.
 * Only the map types and flags this program uses are declared here. */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
