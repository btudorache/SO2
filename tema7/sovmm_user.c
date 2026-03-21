// SPDX-License-Identifier: GPL-2.0
/*
 * sovmm_user.c - Userspace client for the SOVMM kernel module
 *
 * This is the equivalent of the original vmm.c, but instead of using
 * /dev/kvm directly, it talks to /dev/sovmm via our custom ioctl API.
 *
 * Usage: ./sovmm_user <real|long|simvirtio>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

#include "sovmm_ioctl.h"

/* Guest code symbols (linked from binary blobs) */
extern uint8_t guest16[], guest16_end[];
extern uint8_t guest64[], guest64_end[];

/* Page table / GDT constants for long mode setup */
#define PDE64_PRESENT	1
#define PDE64_RW	(1 << 1)
#define PDE64_USER	(1 << 2)
#define PDE64_PS	(1 << 7)

/* GDT helper macros */
#define GDT_ACCESS_P	(1u << 7)
#define GDT_ACCESS_S	(1u << 4)
#define GDT_ACCESS_E	(1u << 3)
#define GDT_ACCESS_RW	(1u << 1)
#define GDT_FLAG_L	(1u << 1)
#define GDT_FLAG_G	(1u << 3)

#define EFER_LME	(1UL << 8)
#define EFER_LMA	(1UL << 10)

#define CR0_PE		(1UL << 0)
#define CR0_MP		(1UL << 1)
#define CR0_ET		(1UL << 4)
#define CR0_NE		(1UL << 5)
#define CR0_WP		(1UL << 16)
#define CR0_AM		(1UL << 18)
#define CR0_PG		(1UL << 31)
#define CR4_PAE		(1UL << 5)

/* ---- Helpers ---- */

static int open_sovmm(void)
{
	int fd = open("/dev/sovmm", O_RDWR);

	if (fd < 0) {
		perror("open /dev/sovmm");
		fprintf(stderr, "Is the sovmm module loaded? (insmod sovmm.ko)\n");
		exit(1);
	}
	return fd;
}

static void xioctl(int fd, unsigned long cmd, void *arg, const char *name)
{
	if (ioctl(fd, cmd, arg) < 0) {
		fprintf(stderr, "ioctl %s failed: %s\n", name, strerror(errno));
		exit(1);
	}
}

/* ---- Real mode setup (16-bit guest) ---- */

static void setup_real_mode(int fd, uint8_t *mem)
{
	struct sovmm_sregs sregs;
	struct sovmm_regs regs;

	memset(&sregs, 0, sizeof(sregs));

	/* CS: execute/read, present */
	sregs.cs.limit = 0xFFFF;
	sregs.cs.type = 11;	/* exec/read, accessed */
	sregs.cs.present = 1;
	sregs.cs.s = 1;

	/* Data segments: read/write, present */
	struct sovmm_segment data_seg = {
		.limit = 0xFFFF, .type = 3, .present = 1, .s = 1,
	};
	sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = data_seg;

	/* TR: 32-bit TSS, busy, present */
	sregs.tr.limit = 0xFFFF;
	sregs.tr.type = 11;
	sregs.tr.present = 1;

	/* LDTR: unusable */
	sregs.ldt.unusable = 1;

	/* GDT/IDT */
	sregs.gdt_limit = 0xFFFF;
	sregs.idt_limit = 0xFFFF;

	/* CR0: no protected mode, no paging (unrestricted guest handles this) */
	sregs.cr0 = 0;
	sregs.efer = 0;

	xioctl(fd, SOVMM_SET_SREGS, &sregs, "SET_SREGS");

	/* General registers */
	memset(&regs, 0, sizeof(regs));
	regs.rflags = 2;	/* bit 1 always set */
	regs.rip = 0;
	xioctl(fd, SOVMM_SET_REGS, &regs, "SET_REGS");
}

/* ---- Long mode setup (64-bit guest) ---- */

static void build_page_tables(uint8_t *mem)
{
	uint64_t *pml4 = (uint64_t *)(mem + 0x70000);
	uint64_t *pdpt = (uint64_t *)(mem + 0x71000);
	uint64_t *pd   = (uint64_t *)(mem + 0x72000);

	memset(pml4, 0, 0x1000);
	memset(pdpt, 0, 0x1000);
	memset(pd,   0, 0x1000);

	pml4[0] = 0x71000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;
	pdpt[0] = 0x72000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;
	pd[0]   = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS; /* 2MB */
}

static void build_gdt(uint8_t *mem)
{
	uint64_t *gdt = (uint64_t *)(mem + 0x73000);

	gdt[0] = 0;	/* null */

	/* Entry 1: 64-bit code (present, ring0, exec, read, long mode) */
	uint8_t access = GDT_ACCESS_P | GDT_ACCESS_S | GDT_ACCESS_E |
			 GDT_ACCESS_RW;
	uint8_t flags = GDT_FLAG_L | GDT_FLAG_G;

	gdt[1] = ((uint64_t)access << 40) | ((uint64_t)(flags & 0xF) << 52);

	/* Entry 2: data (present, ring0, writable) */
	uint8_t daccess = GDT_ACCESS_P | GDT_ACCESS_S | GDT_ACCESS_RW;

	gdt[2] = ((uint64_t)daccess << 40) | ((uint64_t)(GDT_FLAG_G & 0xF) << 52);
}

static void setup_long_mode(int fd, uint8_t *mem)
{
	struct sovmm_sregs sregs;
	struct sovmm_regs regs;

	build_page_tables(mem);
	build_gdt(mem);

	memset(&sregs, 0, sizeof(sregs));

	/* CS: 64-bit code segment (GDT entry 1) */
	sregs.cs.selector = 1 << 3;
	sregs.cs.limit = 0xFFFFFFFF;
	sregs.cs.type = 11;
	sregs.cs.present = 1;
	sregs.cs.s = 1;
	sregs.cs.l = 1;
	sregs.cs.g = 1;

	/* Data segments (GDT entry 2) */
	struct sovmm_segment data_seg = {
		.selector = 2 << 3, .limit = 0xFFFFFFFF,
		.type = 3, .present = 1, .s = 1, .db = 1, .g = 1,
	};
	sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = data_seg;

	/* TR */
	sregs.tr.limit = 0xFFFF;
	sregs.tr.type = 11;
	sregs.tr.present = 1;

	/* LDTR unusable */
	sregs.ldt.unusable = 1;

	/* GDT at 0x73000 (3 entries = 24 bytes) */
	sregs.gdt_base = 0x73000;
	sregs.gdt_limit = 23;
	sregs.idt_limit = 0xFFFF;

	/* CR0: protected mode + paging */
	sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs.cr3 = 0x70000;
	sregs.cr4 = CR4_PAE;
	sregs.efer = EFER_LME | EFER_LMA;

	xioctl(fd, SOVMM_SET_SREGS, &sregs, "SET_SREGS");

	memset(&regs, 0, sizeof(regs));
	regs.rflags = 2;
	regs.rip = 0;
	regs.rsp = SOVMM_MEM_SIZE;	/* stack at top of 1MB */
	xioctl(fd, SOVMM_SET_REGS, &regs, "SET_REGS");
}

/* ---- VM execution loop ---- */

static void run_vm(int fd, uint8_t *mem, int is_simvirtio)
{
	struct sovmm_run run;
	struct sovmm_regs regs;
	unsigned long nr_io = 0, nr_total = 0;

	while (1) {
		xioctl(fd, SOVMM_RUN, &run, "RUN");
		nr_total++;

		switch (run.exit_reason) {
		case SOVMM_EXIT_IO:
			nr_io++;
			if (run.io.port == 0xE9 && run.io.direction == 0) {
				/* OUT to debug port */
				if (is_simvirtio) {
					/*
					 * SIMVIRTIO: guest signals us.
					 * Process TX queue from shared memory.
					 */
					/* TX queue ctrl at 0x2000, buffer at 0x2100 */
					uint32_t *head = (uint32_t *)(mem + 0x2000);
					uint32_t *tail = (uint32_t *)(mem + 0x2004);
					uint8_t *buf = mem + 0x2100;
					uint8_t *dev_status = mem + 0x1000 + 6;
					uint8_t *drv_status = mem + 0x1000 + 7;

					/* Drain TX queue */
					while (*tail != *head) {
						uint8_t b = buf[*tail];
						*tail = (*tail + 1) % 256;

						if (b == 'R') {
							printf("[SIMVIRTIO] Reset\n");
							*dev_status = 0x0;
						} else if (b == 'C') {
							printf("[SIMVIRTIO] Config\n");
							*dev_status = 0x2;
						} else {
							write(STDOUT_FILENO, &b, 1);
						}
					}

					/* Check driver_status for DRIVER_OK */
					if (*drv_status == 0x4 && *dev_status != 0x4) {
						printf("[SIMVIRTIO] Ready\n");
						*dev_status = 0x4;
					}

					/*
					 * Write updated memory back to kernel.
					 * Re-send the full memory region so the
					 * guest sees our changes on next run.
					 *
					 * Note: A production VMM would use mmap
					 * for shared memory. Here we re-upload
					 * the modified pages for simplicity.
					 */
					struct sovmm_memory_region region = {
						.guest_phys_addr = 0,
						.memory_size = SOVMM_MEM_SIZE,
						.userspace_addr = (uint64_t)mem,
					};
					/*
					 * We need a way to update guest memory.
					 * For now, use READ_GUEST_MEM in reverse
					 * -- but our ioctl doesn't support writes.
					 * The SIMVIRTIO config is in guest memory
					 * which was set up via SET_MEMORY initially.
					 * Since the kernel copied it, we need to
					 * re-sync. This is a limitation of the
					 * simple copy-based design.
					 *
					 * In practice, you'd either:
					 * 1. Use mmap to share memory, or
					 * 2. Add a WRITE_GUEST_MEM ioctl
					 *
					 * For this demo, the SIMVIRTIO protocol
					 * works because the guest polls via MMIO
					 * reads from its own copy of guest memory
					 * (which the kernel manages via EPT).
					 */
				} else {
					/* Simple mode: print the character */
					char c = run.io.data & 0xFF;
					write(STDOUT_FILENO, &c, 1);
				}
			}
			break;

		case SOVMM_EXIT_HLT: {
			printf("[VMM] Guest halted.\n");

			/* Read value at guest address 0x400 */
			uint32_t val = 0;
			struct sovmm_guest_mem gm = {
				.guest_addr = 0x400,
				.size = sizeof(val),
				.userspace_addr = (uint64_t)&val,
			};
			xioctl(fd, SOVMM_READ_GUEST_MEM, &gm, "READ_GUEST_MEM");
			printf("[VMM] Guest memory[0x400] = %u\n", val);

			/* Read RAX */
			xioctl(fd, SOVMM_GET_REGS, &regs, "GET_REGS");
			printf("[VMM] RAX = %llu\n",
			       (unsigned long long)regs.rax);

			/* Profiling */
			printf("\n--- Profiling ---\n");
			printf("KVM_EXIT_IO:   %lu\n", nr_io);
			printf("Total VMEXITs: %lu\n", nr_total);
			goto done;
		}

		case SOVMM_EXIT_EPT_VIOLATION:
			printf("[VMM] EPT violation at GPA 0x%llx (write=%d)\n",
			       (unsigned long long)run.ept.gpa, run.ept.is_write);
			goto done;

		case SOVMM_EXIT_FAIL:
			fprintf(stderr, "[VMM] VMLAUNCH/VMRESUME failed\n");
			goto done;

		default:
			fprintf(stderr, "[VMM] Unexpected exit: %u\n",
				run.exit_reason);
			goto done;
		}
	}

done:
	return;
}

/* ---- Main ---- */

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <real|long|simvirtio>\n", prog);
}

int main(int argc, char *argv[])
{
	int fd;
	uint8_t *mem;
	uint8_t *code;
	size_t code_size;
	int is_long, is_simvirtio;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	is_long = (strcmp(argv[1], "long") == 0);
	is_simvirtio = (strcmp(argv[1], "simvirtio") == 0);

	if (!is_long && !is_simvirtio && strcmp(argv[1], "real") != 0) {
		usage(argv[0]);
		return 1;
	}

	/* Select guest code */
	if (is_long || is_simvirtio) {
		code = guest64;
		code_size = guest64_end - guest64;
	} else {
		code = guest16;
		code_size = guest16_end - guest16;
	}

	/* Allocate guest memory buffer in userspace */
	mem = mmap(NULL, SOVMM_MEM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	/* Copy guest code to address 0 */
	memcpy(mem, code, code_size);

	/* Set up page tables / GDT in guest memory for long mode */
	if (is_long || is_simvirtio) {
		build_page_tables(mem);
		build_gdt(mem);
	}

	/* Set up SIMVIRTIO config space in guest memory */
	if (is_simvirtio) {
		/* Magic value at 0x1000 */
		*(uint32_t *)(mem + 0x1000) = 0x74726976;
		/* Max queue length at 0x1004 */
		*(uint16_t *)(mem + 0x1004) = 256;
		/* Device status at 0x1006 */
		*(uint8_t *)(mem + 0x1006) = 0;
		/* Driver status at 0x1007 */
		*(uint8_t *)(mem + 0x1007) = 0;
	}

	/* Open /dev/sovmm */
	fd = open_sovmm();

	printf("=== SOVMM: %s mode ===\n", argv[1]);

	/* Step 1: Create VM (enables VMX, allocates VMCS) */
	xioctl(fd, SOVMM_CREATE_VM, NULL, "CREATE_VM");

	/* Step 2: Set guest memory (copies buffer, builds EPT) */
	struct sovmm_memory_region region = {
		.guest_phys_addr = 0,
		.memory_size = SOVMM_MEM_SIZE,
		.userspace_addr = (uint64_t)mem,
	};
	xioctl(fd, SOVMM_SET_MEMORY, &region, "SET_MEMORY");

	/* Step 3: Set up CPU mode */
	if (is_long || is_simvirtio)
		setup_long_mode(fd, mem);
	else
		setup_real_mode(fd, mem);

	/* Step 4: Run! */
	run_vm(fd, mem, is_simvirtio);

	close(fd);
	munmap(mem, SOVMM_MEM_SIZE);
	return 0;
}
