/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sovmm_ioctl.h - Shared header between kernel module and userspace
 *
 * Defines the ioctl interface for the SO2 VMM kernel driver.
 * Mirrors a simplified KVM-like API:
 *   1. open("/dev/sovmm")
 *   2. ioctl(SOVMM_CREATE_VM)      - enable VMX, create VMCS
 *   3. ioctl(SOVMM_SET_MEMORY)     - copy guest code, build EPT
 *   4. ioctl(SOVMM_SET_SREGS)      - set segment registers
 *   5. ioctl(SOVMM_SET_REGS)       - set general purpose registers
 *   6. ioctl(SOVMM_RUN) in a loop  - run guest, get exit info
 *   7. close(fd)                    - tear down VMX
 */
#ifndef SOVMM_IOCTL_H
#define SOVMM_IOCTL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* Guest VM memory size: 1MB */
#define SOVMM_MEM_SIZE		(1 << 20)

/* ---- Segment descriptor (mirrors simplified kvm_segment) ---- */
struct sovmm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;       /* segment type (4 bits) */
	__u8  present;
	__u8  dpl;
	__u8  db;         /* D/B flag */
	__u8  s;          /* descriptor type: 0=system, 1=code/data */
	__u8  l;          /* 64-bit mode (CS only) */
	__u8  g;          /* granularity */
	__u8  unusable;   /* 1 = segment is unusable */
};

/* ---- Special registers ---- */
struct sovmm_sregs {
	struct sovmm_segment cs, ds, es, fs, gs, ss;
	struct sovmm_segment tr, ldt;
	__u64 cr0;
	__u64 cr3;
	__u64 cr4;
	__u64 efer;
	__u64 gdt_base;
	__u32 gdt_limit;
	__u64 idt_base;
	__u32 idt_limit;
};

/* ---- General purpose registers ---- */
struct sovmm_regs {
	__u64 rax, rcx, rdx, rbx;
	__u64 rsp, rbp, rsi, rdi;
	__u64 r8, r9, r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip;
	__u64 rflags;
};

/* ---- Memory region (guest code) ---- */
struct sovmm_memory_region {
	__u64 guest_phys_addr;  /* must be 0 for now */
	__u64 memory_size;      /* up to SOVMM_MEM_SIZE */
	__u64 userspace_addr;   /* pointer to user buffer */
};

/* ---- Run result (returned after each SOVMM_RUN) ---- */
#define SOVMM_EXIT_HLT			12
#define SOVMM_EXIT_IO			30
#define SOVMM_EXIT_EPT_VIOLATION	48
#define SOVMM_EXIT_FAIL			0xFF00

struct sovmm_run {
	__u32 exit_reason;
	__u32 insn_len;
	union {
		/* I/O exit info */
		struct {
			__u16 port;
			__u8  direction;  /* 0 = out, 1 = in */
			__u8  size;       /* access size in bytes */
			__u32 data;       /* value (for out) */
		} io;
		/* EPT violation info */
		struct {
			__u64 gpa;
			__u8  is_write;
		} ept;
	};
};

/* ---- Guest memory read (for checking values after halt) ---- */
struct sovmm_guest_mem {
	__u64 guest_addr;
	__u64 size;
	__u64 userspace_addr;
};

/* ---- ioctl numbers ---- */
#define SOVMM_MAGIC 'S'

#define SOVMM_CREATE_VM		_IO(SOVMM_MAGIC, 1)
#define SOVMM_SET_MEMORY	_IOW(SOVMM_MAGIC, 2, struct sovmm_memory_region)
#define SOVMM_SET_REGS		_IOW(SOVMM_MAGIC, 3, struct sovmm_regs)
#define SOVMM_GET_REGS		_IOR(SOVMM_MAGIC, 4, struct sovmm_regs)
#define SOVMM_SET_SREGS		_IOW(SOVMM_MAGIC, 5, struct sovmm_sregs)
#define SOVMM_GET_SREGS		_IOR(SOVMM_MAGIC, 6, struct sovmm_sregs)
#define SOVMM_RUN		_IOR(SOVMM_MAGIC, 7, struct sovmm_run)
#define SOVMM_READ_GUEST_MEM	_IOWR(SOVMM_MAGIC, 8, struct sovmm_guest_mem)

#endif /* SOVMM_IOCTL_H */
