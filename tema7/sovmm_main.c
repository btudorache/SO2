// SPDX-License-Identifier: GPL-2.0
/*
 * sovmm_main.c - SO2 VMM kernel module using Intel VT-x (VMX)
 *
 * Architecture:
 *   This module exposes /dev/sovmm, a char device with a KVM-like ioctl API.
 *   Internally it directly programs VMX hardware:
 *
 *   1. VMXON    - enables VMX operation on the current CPU
 *   2. VMCS     - a per-VM hardware structure controlling guest/host state
 *   3. EPT      - Extended Page Tables for guest physical -> host physical mapping
 *   4. VMLAUNCH - enters the guest; CPU runs guest code until an exit event
 *   5. VM exit  - CPU saves guest state, restores host state, returns here
 *
 *   The module pins the process to one CPU so VMX state stays consistent.
 *   It requires KVM to be unloaded (VMX is exclusive per-CPU).
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <asm/special_insns.h>
#include <asm/processor.h>

#include "sovmm_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SO2");
MODULE_DESCRIPTION("Simple VMM using Intel VT-x");

/* ====================================================================
 * Section 1: VMCS field encodings (Intel SDM Vol. 3, Appendix B)
 * ==================================================================== */

/* 16-bit guest state */
#define VMCS_GUEST_ES_SEL		0x0800
#define VMCS_GUEST_CS_SEL		0x0802
#define VMCS_GUEST_SS_SEL		0x0804
#define VMCS_GUEST_DS_SEL		0x0806
#define VMCS_GUEST_FS_SEL		0x0808
#define VMCS_GUEST_GS_SEL		0x080A
#define VMCS_GUEST_LDTR_SEL		0x080C
#define VMCS_GUEST_TR_SEL		0x080E

/* 16-bit host state */
#define VMCS_HOST_ES_SEL		0x0C00
#define VMCS_HOST_CS_SEL		0x0C02
#define VMCS_HOST_SS_SEL		0x0C04
#define VMCS_HOST_DS_SEL		0x0C06
#define VMCS_HOST_FS_SEL		0x0C08
#define VMCS_HOST_GS_SEL		0x0C0A
#define VMCS_HOST_TR_SEL		0x0C0E

/* 64-bit control */
#define VMCS_EPTP			0x201A

/* 64-bit read-only */
#define VMCS_GUEST_PHYS_ADDR		0x2400

/* 64-bit guest state */
#define VMCS_LINK_POINTER		0x2800
#define VMCS_GUEST_DEBUGCTL		0x2802
#define VMCS_GUEST_EFER			0x2806

/* 64-bit host state */
#define VMCS_HOST_EFER			0x2C02

/* 32-bit control */
#define VMCS_PIN_BASED_CTLS		0x4000
#define VMCS_PROC_BASED_CTLS		0x4002
#define VMCS_EXCEPTION_BITMAP		0x4004
#define VMCS_EXIT_CTLS			0x400C
#define VMCS_ENTRY_CTLS			0x4012
#define VMCS_PROC_BASED_CTLS2		0x401E

/* 32-bit read-only */
#define VMCS_EXIT_REASON		0x4402
#define VMCS_EXIT_INTR_INFO		0x4404
#define VMCS_EXIT_INSN_LEN		0x440C

/* 32-bit guest state */
#define VMCS_GUEST_ES_LIMIT		0x4800
#define VMCS_GUEST_CS_LIMIT		0x4802
#define VMCS_GUEST_SS_LIMIT		0x4804
#define VMCS_GUEST_DS_LIMIT		0x4806
#define VMCS_GUEST_FS_LIMIT		0x4808
#define VMCS_GUEST_GS_LIMIT		0x480A
#define VMCS_GUEST_LDTR_LIMIT		0x480C
#define VMCS_GUEST_TR_LIMIT		0x480E
#define VMCS_GUEST_GDTR_LIMIT		0x4810
#define VMCS_GUEST_IDTR_LIMIT		0x4812
#define VMCS_GUEST_ES_AR		0x4814
#define VMCS_GUEST_CS_AR		0x4816
#define VMCS_GUEST_SS_AR		0x4818
#define VMCS_GUEST_DS_AR		0x481A
#define VMCS_GUEST_FS_AR		0x481C
#define VMCS_GUEST_GS_AR		0x481E
#define VMCS_GUEST_LDTR_AR		0x4820
#define VMCS_GUEST_TR_AR		0x4822
#define VMCS_GUEST_INTERRUPTIBILITY	0x4824
#define VMCS_GUEST_ACTIVITY		0x4826
#define VMCS_GUEST_SYSENTER_CS		0x482A

/* 32-bit host state */
#define VMCS_HOST_SYSENTER_CS		0x4C00

/* Natural-width control */
#define VMCS_CR0_MASK			0x6000
#define VMCS_CR4_MASK			0x6002
#define VMCS_CR0_READ_SHADOW		0x6004
#define VMCS_CR4_READ_SHADOW		0x6006

/* Natural-width read-only */
#define VMCS_EXIT_QUALIFICATION		0x6400

/* Natural-width guest state */
#define VMCS_GUEST_CR0			0x6800
#define VMCS_GUEST_CR3			0x6802
#define VMCS_GUEST_CR4			0x6804
#define VMCS_GUEST_ES_BASE		0x6806
#define VMCS_GUEST_CS_BASE		0x6808
#define VMCS_GUEST_SS_BASE		0x680A
#define VMCS_GUEST_DS_BASE		0x680C
#define VMCS_GUEST_FS_BASE		0x680E
#define VMCS_GUEST_GS_BASE		0x6810
#define VMCS_GUEST_LDTR_BASE		0x6812
#define VMCS_GUEST_TR_BASE		0x6814
#define VMCS_GUEST_GDTR_BASE		0x6816
#define VMCS_GUEST_IDTR_BASE		0x6818
#define VMCS_GUEST_DR7			0x681A
#define VMCS_GUEST_RSP			0x681C
#define VMCS_GUEST_RIP			0x681E
#define VMCS_GUEST_RFLAGS		0x6820
#define VMCS_GUEST_PENDING_DBG		0x6822
#define VMCS_GUEST_SYSENTER_ESP		0x6824
#define VMCS_GUEST_SYSENTER_EIP		0x6826

/* Natural-width host state */
#define VMCS_HOST_CR0			0x6C00
#define VMCS_HOST_CR3			0x6C02
#define VMCS_HOST_CR4			0x6C04
#define VMCS_HOST_FS_BASE		0x6C06
#define VMCS_HOST_GS_BASE		0x6C08
#define VMCS_HOST_TR_BASE		0x6C0A
#define VMCS_HOST_GDTR_BASE		0x6C0C
#define VMCS_HOST_IDTR_BASE		0x6C0E
#define VMCS_HOST_SYSENTER_ESP		0x6C10
#define VMCS_HOST_SYSENTER_EIP		0x6C12
#define VMCS_HOST_RSP			0x6C14
#define VMCS_HOST_RIP			0x6C16

/* ====================================================================
 * Section 2: VMX control bits
 * ==================================================================== */

/* Pin-based controls */
#define PIN_EXT_INTR_EXIT		(1u << 0)
#define PIN_NMI_EXIT			(1u << 3)

/* Primary processor-based controls */
#define PROC_HLT_EXIT			(1u << 7)
#define PROC_UNCOND_IO_EXIT		(1u << 24)
#define PROC_ACTIVATE_SECONDARY		(1u << 31)

/* Secondary processor-based controls */
#define PROC2_EPT			(1u << 1)
#define PROC2_UNRESTRICTED_GUEST	(1u << 7)

/* VM-exit controls */
#define EXIT_HOST_ADDR_64		(1u << 9)
#define EXIT_SAVE_EFER			(1u << 20)
#define EXIT_LOAD_EFER			(1u << 21)

/* VM-entry controls */
#define ENTRY_IA32E_GUEST		(1u << 9)
#define ENTRY_LOAD_EFER			(1u << 15)

/* EPT entry bits */
#define EPT_R				(1ULL << 0)
#define EPT_W				(1ULL << 1)
#define EPT_X				(1ULL << 2)
#define EPT_RWX				(EPT_R | EPT_W | EPT_X)
#define EPT_MT_WB			(6ULL << 3)
#define EPT_PAGE_SIZE			(1ULL << 7)

/* Exit reasons */
#define EXIT_HLT			12
#define EXIT_IO				30
#define EXIT_EPT_VIOLATION		48

/* MSR addresses */
#define MSR_VMX_BASIC			0x480
#define MSR_VMX_PINBASED_CTLS		0x481
#define MSR_VMX_PROCBASED_CTLS		0x482
#define MSR_VMX_EXIT_CTLS		0x483
#define MSR_VMX_ENTRY_CTLS		0x484
#define MSR_VMX_PROCBASED_CTLS2		0x48B
#define MSR_VMX_CR0_FIXED0		0x486
#define MSR_VMX_CR0_FIXED1		0x487
#define MSR_VMX_CR4_FIXED0		0x488
#define MSR_VMX_CR4_FIXED1		0x489
#define MSR_IA32_FEATURE_CTL		0x3A
#define MSR_IA32_EFER			0xC0000080
#define MSR_IA32_FS_BASE		0xC0000100
#define MSR_IA32_GS_BASE		0xC0000101
#define MSR_IA32_SYSENTER_CS_MSR	0x174
#define MSR_IA32_SYSENTER_ESP_MSR	0x175
#define MSR_IA32_SYSENTER_EIP_MSR	0x176

/* Feature control MSR bits */
#define FEAT_CTL_LOCKED			(1u << 0)
#define FEAT_CTL_VMX_ENABLED		(1u << 2)

/* CR0/CR4 bits */
#define X86_CR0_PE			(1UL << 0)
#define X86_CR0_NE			(1UL << 5)
#define X86_CR0_PG			(1UL << 31)
#define X86_CR4_VMXE			(1UL << 13)

/* EFER bits */
#define EFER_LME			(1UL << 8)

/* ====================================================================
 * Section 3: Per-VM state
 * ==================================================================== */

struct sovmm_vm {
	/* VMX regions (page-aligned, need physical addresses) */
	void		*vmxon_region;
	phys_addr_t	vmxon_phys;
	void		*vmcs;
	phys_addr_t	vmcs_phys;

	/* Guest physical memory */
	struct page	*guest_pages;
	void		*guest_mem;		/* kernel VA */
	phys_addr_t	guest_phys;		/* contiguous PA base */
	unsigned long	guest_mem_size;

	/* EPT tables (4 pages: PML4, PDPT, PD, PT) */
	void		*ept_pml4;
	void		*ept_pdpt;
	void		*ept_pd;
	void		*ept_pt;

	/* Guest GPRs (saved/restored by assembly code) */
	unsigned long	guest_regs[16];

	/* Guest state managed via VMCS */
	unsigned long	guest_rip;
	unsigned long	guest_rsp;
	unsigned long	guest_rflags;

	/* Control state */
	int		vmx_enabled;
	int		vmcs_loaded;
	int		launched;
	int		cpu;		/* pinned CPU */

	/* VMX revision ID (from MSR_VMX_BASIC) */
	u32		vmx_rev_id;
};

/* ====================================================================
 * Section 4: VMX instruction wrappers (inline assembly)
 * ==================================================================== */

static inline int vmx_on(phys_addr_t phys)
{
	u8 err;

	asm volatile("vmxon %[pa]; setna %[err]"
		     : [err] "=rm"(err)
		     : [pa] "m"(phys)
		     : "cc", "memory");
	return err ? -EIO : 0;
}

static inline void vmx_off(void)
{
	asm volatile("vmxoff" ::: "cc");
}

static inline int vmx_clear(phys_addr_t phys)
{
	u8 err;

	asm volatile("vmclear %[pa]; setna %[err]"
		     : [err] "=rm"(err)
		     : [pa] "m"(phys)
		     : "cc", "memory");
	return err ? -EIO : 0;
}

static inline int vmx_ptrld(phys_addr_t phys)
{
	u8 err;

	asm volatile("vmptrld %[pa]; setna %[err]"
		     : [err] "=rm"(err)
		     : [pa] "m"(phys)
		     : "cc", "memory");
	return err ? -EIO : 0;
}

static inline void vmx_write(u32 field, u64 value)
{
	asm volatile("vmwrite %1, %0" :: "r"((u64)field), "rm"(value) : "cc");
}

static inline u64 vmx_read(u32 field)
{
	u64 value;

	asm volatile("vmread %1, %0" : "=rm"(value) : "r"((u64)field) : "cc");
	return value;
}

/* Assembly function from sovmm_vmx_asm.S */
extern int sovmm_vmx_run(unsigned long *guest_regs, int launched);
/* HOST_RIP target (defined in sovmm_vmx_asm.S) */
extern void sovmm_vmx_return(void);

/* ====================================================================
 * Section 5: VMX capability detection and enable/disable
 * ==================================================================== */

static int vmx_check_support(struct sovmm_vm *vm)
{
	u32 ecx;
	u64 feat_ctl, vmx_basic;

	/* CPUID.1:ECX.VMX (bit 5) */
	asm volatile("cpuid"
		     : "=c"(ecx)
		     : "a"(1)
		     : "ebx", "edx");
	if (!(ecx & (1u << 5))) {
		pr_err("sovmm: CPU does not support VMX\n");
		return -ENODEV;
	}

	/* Check IA32_FEATURE_CONTROL MSR */
	rdmsrl(MSR_IA32_FEATURE_CTL, feat_ctl);
	if ((feat_ctl & FEAT_CTL_LOCKED) &&
	    !(feat_ctl & FEAT_CTL_VMX_ENABLED)) {
		pr_err("sovmm: VMX disabled in BIOS\n");
		return -ENODEV;
	}

	/* Read VMX revision ID */
	rdmsrl(MSR_VMX_BASIC, vmx_basic);
	vm->vmx_rev_id = (u32)(vmx_basic & 0x7FFFFFFF);

	return 0;
}

/*
 * Adjust VMX control field value using MSR-defined allowed bits.
 * MSR low 32 bits = must-be-1, high 32 bits = may-be-1.
 */
static u32 vmx_adjust_ctrl(u32 desired, u32 msr_addr)
{
	u64 msr_val;
	u32 must1, may1;

	rdmsrl(msr_addr, msr_val);
	must1 = (u32)msr_val;
	may1 = (u32)(msr_val >> 32);
	return (desired | must1) & may1;
}

static int vmx_enable(struct sovmm_vm *vm)
{
	unsigned long cr4;

	/* Allocate VMXON region (4KB, physically contiguous) */
	vm->vmxon_region = (void *)get_zeroed_page(GFP_KERNEL);
	if (!vm->vmxon_region)
		return -ENOMEM;
	vm->vmxon_phys = virt_to_phys(vm->vmxon_region);

	/* Write revision ID to first 4 bytes */
	*(u32 *)vm->vmxon_region = vm->vmx_rev_id;

	/* Enable VMX in CR4 */
	cr4 = __read_cr4();
	if (cr4 & X86_CR4_VMXE) {
		pr_err("sovmm: VMX already enabled (KVM loaded?)\n");
		free_page((unsigned long)vm->vmxon_region);
		return -EBUSY;
	}
	cr4_set_bits(X86_CR4_VMXE);

	/* Execute VMXON */
	if (vmx_on(vm->vmxon_phys)) {
		pr_err("sovmm: VMXON failed\n");
		cr4_clear_bits(X86_CR4_VMXE);
		free_page((unsigned long)vm->vmxon_region);
		return -EIO;
	}

	vm->vmx_enabled = 1;
	return 0;
}

static void vmx_disable(struct sovmm_vm *vm)
{
	if (!vm->vmx_enabled)
		return;

	if (vm->vmcs_loaded) {
		vmx_clear(vm->vmcs_phys);
		vm->vmcs_loaded = 0;
	}

	vmx_off();
	cr4_clear_bits(X86_CR4_VMXE);
	vm->vmx_enabled = 0;

	free_page((unsigned long)vm->vmxon_region);
	vm->vmxon_region = NULL;
}

/* ====================================================================
 * Section 6: EPT (Extended Page Tables) setup
 * ==================================================================== */

static int setup_ept(struct sovmm_vm *vm)
{
	u64 *pml4, *pdpt, *pd, *pt;
	phys_addr_t pml4_pa, pdpt_pa, pd_pa, pt_pa;
	int i, nr_pages;

	/* Allocate EPT table pages */
	vm->ept_pml4 = (void *)get_zeroed_page(GFP_KERNEL);
	vm->ept_pdpt = (void *)get_zeroed_page(GFP_KERNEL);
	vm->ept_pd   = (void *)get_zeroed_page(GFP_KERNEL);
	vm->ept_pt   = (void *)get_zeroed_page(GFP_KERNEL);
	if (!vm->ept_pml4 || !vm->ept_pdpt || !vm->ept_pd || !vm->ept_pt)
		return -ENOMEM;

	pml4_pa = virt_to_phys(vm->ept_pml4);
	pdpt_pa = virt_to_phys(vm->ept_pdpt);
	pd_pa   = virt_to_phys(vm->ept_pd);
	pt_pa   = virt_to_phys(vm->ept_pt);

	pml4 = (u64 *)vm->ept_pml4;
	pdpt = (u64 *)vm->ept_pdpt;
	pd   = (u64 *)vm->ept_pd;
	pt   = (u64 *)vm->ept_pt;

	/*
	 * EPT hierarchy:
	 *   PML4[0] -> PDPT -> PD -> PT (4KB pages)
	 *   Maps guest physical 0..guest_mem_size to host physical pages
	 */
	pml4[0] = pdpt_pa | EPT_RWX;
	pdpt[0] = pd_pa   | EPT_RWX;
	pd[0]   = pt_pa   | EPT_RWX;

	/* Fill PT entries - guest pages are physically contiguous */
	nr_pages = vm->guest_mem_size >> PAGE_SHIFT;
	for (i = 0; i < nr_pages && i < 512; i++)
		pt[i] = (vm->guest_phys + i * PAGE_SIZE) | EPT_RWX | EPT_MT_WB;

	return 0;
}

static void free_ept(struct sovmm_vm *vm)
{
	if (vm->ept_pml4) free_page((unsigned long)vm->ept_pml4);
	if (vm->ept_pdpt) free_page((unsigned long)vm->ept_pdpt);
	if (vm->ept_pd)   free_page((unsigned long)vm->ept_pd);
	if (vm->ept_pt)   free_page((unsigned long)vm->ept_pt);
	vm->ept_pml4 = vm->ept_pdpt = vm->ept_pd = vm->ept_pt = NULL;
}

/* ====================================================================
 * Section 7: VMCS setup
 * ==================================================================== */

static void write_segment(struct sovmm_segment *seg,
			   u32 sel_field, u32 base_field,
			   u32 limit_field, u32 ar_field)
{
	u32 ar;

	vmx_write(sel_field, seg->selector);
	vmx_write(base_field, seg->base);
	vmx_write(limit_field, seg->limit);

	ar = seg->type;
	ar |= (seg->s & 1) << 4;
	ar |= (seg->dpl & 3) << 5;
	ar |= (seg->present & 1) << 7;
	ar |= (seg->l & 1) << 13;
	ar |= (seg->db & 1) << 14;
	ar |= (seg->g & 1) << 15;
	if (seg->unusable)
		ar |= (1u << 16);
	vmx_write(ar_field, ar);
}

/*
 * Read host TR base from GDT.
 * In 64-bit mode, TSS descriptor is 16 bytes (spans two GDT entries).
 */
static unsigned long get_tr_base(unsigned long gdt_base, u16 tr_sel)
{
	u8 *entry = (u8 *)(gdt_base + (tr_sel & ~7));
	unsigned long base;

	base  = *(u16 *)(entry + 2);		/* bits 15:0 */
	base |= (unsigned long)entry[4] << 16;	/* bits 23:16 */
	base |= (unsigned long)entry[7] << 24;	/* bits 31:24 */
	base |= (unsigned long)*(u32 *)(entry + 8) << 32; /* bits 63:32 */
	return base;
}

static void setup_vmcs_host_state(struct sovmm_vm *vm)
{
	struct desc_ptr gdt, idt;
	u16 cs, ss, ds, es, fs, gs, tr;
	unsigned long cr0, cr3, cr4;
	unsigned long fs_base, gs_base, tr_base;
	unsigned long efer, sysenter_cs, sysenter_esp, sysenter_eip;

	/* Read current host state */
	native_store_gdt(&gdt);
	store_idt(&idt);

	savesegment(cs, cs);
	savesegment(ss, ss);
	savesegment(ds, ds);
	savesegment(es, es);
	savesegment(fs, fs);
	savesegment(gs, gs);
	asm volatile("str %0" : "=r"(tr));

	cr0 = read_cr0();
	cr3 = __read_cr3();
	cr4 = __read_cr4();

	rdmsrl(MSR_IA32_FS_BASE, fs_base);
	rdmsrl(MSR_IA32_GS_BASE, gs_base);
	tr_base = get_tr_base(gdt.address, tr);

	rdmsrl(MSR_IA32_EFER, efer);
	rdmsrl(MSR_IA32_SYSENTER_CS_MSR, sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP_MSR, sysenter_esp);
	rdmsrl(MSR_IA32_SYSENTER_EIP_MSR, sysenter_eip);

	/* Write host state to VMCS */
	vmx_write(VMCS_HOST_CS_SEL, cs & 0xF8);
	vmx_write(VMCS_HOST_SS_SEL, ss & 0xF8);
	vmx_write(VMCS_HOST_DS_SEL, ds & 0xF8);
	vmx_write(VMCS_HOST_ES_SEL, es & 0xF8);
	vmx_write(VMCS_HOST_FS_SEL, fs & 0xF8);
	vmx_write(VMCS_HOST_GS_SEL, gs & 0xF8);
	vmx_write(VMCS_HOST_TR_SEL, tr & 0xF8);

	vmx_write(VMCS_HOST_CR0, cr0);
	vmx_write(VMCS_HOST_CR3, cr3);
	vmx_write(VMCS_HOST_CR4, cr4);

	vmx_write(VMCS_HOST_FS_BASE, fs_base);
	vmx_write(VMCS_HOST_GS_BASE, gs_base);
	vmx_write(VMCS_HOST_TR_BASE, tr_base);
	vmx_write(VMCS_HOST_GDTR_BASE, gdt.address);
	vmx_write(VMCS_HOST_IDTR_BASE, idt.address);

	vmx_write(VMCS_HOST_EFER, efer);
	vmx_write(VMCS_HOST_SYSENTER_CS, sysenter_cs);
	vmx_write(VMCS_HOST_SYSENTER_ESP, sysenter_esp);
	vmx_write(VMCS_HOST_SYSENTER_EIP, sysenter_eip);

	/* HOST_RSP is set in assembly, HOST_RIP = our exit handler */
	vmx_write(VMCS_HOST_RIP, (unsigned long)sovmm_vmx_return);
}

static void setup_vmcs_controls(struct sovmm_vm *vm)
{
	u32 pin, proc, proc2, exit_ctl, entry_ctl;

	/* Pin-based: nothing special needed */
	pin = vmx_adjust_ctrl(0, MSR_VMX_PINBASED_CTLS);

	/* Primary proc-based: HLT exit + I/O exit + activate secondary */
	proc = vmx_adjust_ctrl(
		PROC_HLT_EXIT | PROC_UNCOND_IO_EXIT | PROC_ACTIVATE_SECONDARY,
		MSR_VMX_PROCBASED_CTLS);

	/* Secondary: EPT + unrestricted guest (for real mode support) */
	proc2 = vmx_adjust_ctrl(
		PROC2_EPT | PROC2_UNRESTRICTED_GUEST,
		MSR_VMX_PROCBASED_CTLS2);

	/* Exit controls: 64-bit host + save/load EFER */
	exit_ctl = vmx_adjust_ctrl(
		EXIT_HOST_ADDR_64 | EXIT_SAVE_EFER | EXIT_LOAD_EFER,
		MSR_VMX_EXIT_CTLS);

	/* Entry controls: load EFER (IA32E mode set later via SET_SREGS) */
	entry_ctl = vmx_adjust_ctrl(ENTRY_LOAD_EFER, MSR_VMX_ENTRY_CTLS);

	vmx_write(VMCS_PIN_BASED_CTLS, pin);
	vmx_write(VMCS_PROC_BASED_CTLS, proc);
	vmx_write(VMCS_PROC_BASED_CTLS2, proc2);
	vmx_write(VMCS_EXIT_CTLS, exit_ctl);
	vmx_write(VMCS_ENTRY_CTLS, entry_ctl);

	/* No exception interception */
	vmx_write(VMCS_EXCEPTION_BITMAP, 0);

	/* CR0/CR4 masks: don't intercept guest writes */
	vmx_write(VMCS_CR0_MASK, 0);
	vmx_write(VMCS_CR4_MASK, 0);
	vmx_write(VMCS_CR0_READ_SHADOW, 0);
	vmx_write(VMCS_CR4_READ_SHADOW, 0);

	/* Set EPTP: WB memory type (6), 4-level walk (3 << 3) */
	vmx_write(VMCS_EPTP,
		  virt_to_phys(vm->ept_pml4) | (3ULL << 3) | 6ULL);
}

/*
 * Adjust guest CR0/CR4 to satisfy VMX requirements.
 * Some bits must be 1 or 0 per MSR_VMX_CR{0,4}_FIXED{0,1}.
 */
static unsigned long adjust_guest_cr0(unsigned long desired)
{
	u64 fixed0, fixed1;

	rdmsrl(MSR_VMX_CR0_FIXED0, fixed0);
	rdmsrl(MSR_VMX_CR0_FIXED1, fixed1);

	/* Unrestricted guest: PE and PG don't need to be forced on */
	fixed0 &= ~(X86_CR0_PE | X86_CR0_PG);

	return (desired | (unsigned long)fixed0) & (unsigned long)fixed1;
}

static unsigned long adjust_guest_cr4(unsigned long desired)
{
	u64 fixed0, fixed1;

	rdmsrl(MSR_VMX_CR4_FIXED0, fixed0);
	rdmsrl(MSR_VMX_CR4_FIXED1, fixed1);
	return (desired | (unsigned long)fixed0) & (unsigned long)fixed1;
}

static void setup_vmcs_guest_defaults(struct sovmm_vm *vm)
{
	/* Guest state defaults */
	vmx_write(VMCS_GUEST_DR7, 0x400);
	vmx_write(VMCS_GUEST_DEBUGCTL, 0);
	vmx_write(VMCS_GUEST_INTERRUPTIBILITY, 0);
	vmx_write(VMCS_GUEST_ACTIVITY, 0);	/* active */
	vmx_write(VMCS_GUEST_PENDING_DBG, 0);
	vmx_write(VMCS_GUEST_SYSENTER_CS, 0);
	vmx_write(VMCS_GUEST_SYSENTER_ESP, 0);
	vmx_write(VMCS_GUEST_SYSENTER_EIP, 0);
	vmx_write(VMCS_LINK_POINTER, ~0ULL);	/* required sentinel */
}

/* ====================================================================
 * Section 8: ioctl handlers
 * ==================================================================== */

static int sovmm_create_vm(struct sovmm_vm *vm)
{
	int ret;

	preempt_disable();
	vm->cpu = smp_processor_id();

	ret = vmx_check_support(vm);
	if (ret)
		goto out;

	ret = vmx_enable(vm);
	if (ret)
		goto out;

	/* Allocate VMCS */
	vm->vmcs = (void *)get_zeroed_page(GFP_KERNEL);
	if (!vm->vmcs) {
		ret = -ENOMEM;
		goto out_vmx;
	}
	vm->vmcs_phys = virt_to_phys(vm->vmcs);
	*(u32 *)vm->vmcs = vm->vmx_rev_id;

	/* Load VMCS */
	ret = vmx_clear(vm->vmcs_phys);
	if (ret)
		goto out_vmcs;
	ret = vmx_ptrld(vm->vmcs_phys);
	if (ret)
		goto out_vmcs;
	vm->vmcs_loaded = 1;

	preempt_enable();

	pr_info("sovmm: VM created on CPU %d, rev_id=%08x\n",
		vm->cpu, vm->vmx_rev_id);
	return 0;

out_vmcs:
	free_page((unsigned long)vm->vmcs);
	vm->vmcs = NULL;
out_vmx:
	vmx_disable(vm);
out:
	preempt_enable();
	return ret;
}

static int sovmm_set_memory(struct sovmm_vm *vm,
			     struct sovmm_memory_region __user *uarg)
{
	struct sovmm_memory_region region;
	int ret;

	if (copy_from_user(&region, uarg, sizeof(region)))
		return -EFAULT;

	if (region.memory_size > SOVMM_MEM_SIZE || region.memory_size == 0)
		return -EINVAL;
	if (region.guest_phys_addr != 0)
		return -EINVAL;	/* only support mapping at GPA 0 for now */

	/* Allocate guest memory: physically contiguous pages */
	vm->guest_mem_size = PAGE_ALIGN(region.memory_size);
	vm->guest_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO,
				      get_order(vm->guest_mem_size));
	if (!vm->guest_pages)
		return -ENOMEM;

	vm->guest_mem = page_address(vm->guest_pages);
	vm->guest_phys = page_to_phys(vm->guest_pages);

	/* Copy guest code from userspace */
	if (copy_from_user(vm->guest_mem,
			   (void __user *)region.userspace_addr,
			   region.memory_size)) {
		__free_pages(vm->guest_pages, get_order(vm->guest_mem_size));
		vm->guest_mem = NULL;
		return -EFAULT;
	}

	/* Build EPT */
	ret = setup_ept(vm);
	if (ret)
		return ret;

	/* Set up VMCS (needs EPT ready) */
	preempt_disable();
	vmx_ptrld(vm->vmcs_phys);
	setup_vmcs_controls(vm);
	setup_vmcs_host_state(vm);
	setup_vmcs_guest_defaults(vm);
	preempt_enable();

	pr_info("sovmm: mapped %lu bytes of guest memory at HPA %llx\n",
		vm->guest_mem_size, (u64)vm->guest_phys);
	return 0;
}

static int sovmm_set_sregs(struct sovmm_vm *vm,
			    struct sovmm_sregs __user *uarg)
{
	struct sovmm_sregs sregs;
	unsigned long cr0, cr4;
	u32 entry_ctl;

	if (copy_from_user(&sregs, uarg, sizeof(sregs)))
		return -EFAULT;

	preempt_disable();
	vmx_ptrld(vm->vmcs_phys);

	/* Segments */
	write_segment(&sregs.cs, VMCS_GUEST_CS_SEL, VMCS_GUEST_CS_BASE,
		      VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_AR);
	write_segment(&sregs.ds, VMCS_GUEST_DS_SEL, VMCS_GUEST_DS_BASE,
		      VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR);
	write_segment(&sregs.es, VMCS_GUEST_ES_SEL, VMCS_GUEST_ES_BASE,
		      VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR);
	write_segment(&sregs.fs, VMCS_GUEST_FS_SEL, VMCS_GUEST_FS_BASE,
		      VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR);
	write_segment(&sregs.gs, VMCS_GUEST_GS_SEL, VMCS_GUEST_GS_BASE,
		      VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR);
	write_segment(&sregs.ss, VMCS_GUEST_SS_SEL, VMCS_GUEST_SS_BASE,
		      VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR);
	write_segment(&sregs.tr, VMCS_GUEST_TR_SEL, VMCS_GUEST_TR_BASE,
		      VMCS_GUEST_TR_LIMIT, VMCS_GUEST_TR_AR);
	write_segment(&sregs.ldt, VMCS_GUEST_LDTR_SEL, VMCS_GUEST_LDTR_BASE,
		      VMCS_GUEST_LDTR_LIMIT, VMCS_GUEST_LDTR_AR);

	/* GDT / IDT */
	vmx_write(VMCS_GUEST_GDTR_BASE, sregs.gdt_base);
	vmx_write(VMCS_GUEST_GDTR_LIMIT, sregs.gdt_limit);
	vmx_write(VMCS_GUEST_IDTR_BASE, sregs.idt_base);
	vmx_write(VMCS_GUEST_IDTR_LIMIT, sregs.idt_limit);

	/* Control registers (adjusted for VMX requirements) */
	cr0 = adjust_guest_cr0(sregs.cr0);
	cr4 = adjust_guest_cr4(sregs.cr4);
	vmx_write(VMCS_GUEST_CR0, cr0);
	vmx_write(VMCS_GUEST_CR3, sregs.cr3);
	vmx_write(VMCS_GUEST_CR4, cr4);

	/* EFER */
	vmx_write(VMCS_GUEST_EFER, sregs.efer);

	/* Update entry controls: enable IA-32e mode for 64-bit guests */
	entry_ctl = (u32)vmx_read(VMCS_ENTRY_CTLS);
	if (sregs.efer & EFER_LME)
		entry_ctl |= ENTRY_IA32E_GUEST;
	else
		entry_ctl &= ~ENTRY_IA32E_GUEST;
	vmx_write(VMCS_ENTRY_CTLS, entry_ctl);

	preempt_enable();
	return 0;
}

static int sovmm_set_regs(struct sovmm_vm *vm,
			   struct sovmm_regs __user *uarg)
{
	struct sovmm_regs regs;

	if (copy_from_user(&regs, uarg, sizeof(regs)))
		return -EFAULT;

	/* GPRs saved in array (assembly loads/stores these) */
	vm->guest_regs[0]  = regs.rax;
	vm->guest_regs[1]  = regs.rcx;
	vm->guest_regs[2]  = regs.rdx;
	vm->guest_regs[3]  = regs.rbx;
	/* [4] = RSP placeholder (managed via VMCS) */
	vm->guest_regs[5]  = regs.rbp;
	vm->guest_regs[6]  = regs.rsi;
	vm->guest_regs[7]  = regs.rdi;
	vm->guest_regs[8]  = regs.r8;
	vm->guest_regs[9]  = regs.r9;
	vm->guest_regs[10] = regs.r10;
	vm->guest_regs[11] = regs.r11;
	vm->guest_regs[12] = regs.r12;
	vm->guest_regs[13] = regs.r13;
	vm->guest_regs[14] = regs.r14;
	vm->guest_regs[15] = regs.r15;

	/* RIP, RSP, RFLAGS go to VMCS */
	vm->guest_rip = regs.rip;
	vm->guest_rsp = regs.rsp;
	vm->guest_rflags = regs.rflags;

	return 0;
}

static int sovmm_get_regs(struct sovmm_vm *vm,
			   struct sovmm_regs __user *uarg)
{
	struct sovmm_regs regs = {
		.rax = vm->guest_regs[0],
		.rcx = vm->guest_regs[1],
		.rdx = vm->guest_regs[2],
		.rbx = vm->guest_regs[3],
		.rsp = vm->guest_rsp,
		.rbp = vm->guest_regs[5],
		.rsi = vm->guest_regs[6],
		.rdi = vm->guest_regs[7],
		.r8  = vm->guest_regs[8],
		.r9  = vm->guest_regs[9],
		.r10 = vm->guest_regs[10],
		.r11 = vm->guest_regs[11],
		.r12 = vm->guest_regs[12],
		.r13 = vm->guest_regs[13],
		.r14 = vm->guest_regs[14],
		.r15 = vm->guest_regs[15],
		.rip = vm->guest_rip,
		.rflags = vm->guest_rflags,
	};

	if (copy_to_user(uarg, &regs, sizeof(regs)))
		return -EFAULT;
	return 0;
}

/* ====================================================================
 * Section 9: VM run + exit handling
 * ==================================================================== */

static int sovmm_run_vm(struct sovmm_vm *vm, struct sovmm_run __user *uarg)
{
	struct sovmm_run run;
	u32 exit_reason;
	u64 qual;
	int ret;

	if (!vm->vmx_enabled || !vm->vmcs_loaded || !vm->guest_mem)
		return -EINVAL;

	memset(&run, 0, sizeof(run));

	preempt_disable();

	/* Ensure our VMCS is current */
	vmx_ptrld(vm->vmcs_phys);

	/* Write guest RIP/RSP/RFLAGS (may have been updated since last run) */
	vmx_write(VMCS_GUEST_RIP, vm->guest_rip);
	vmx_write(VMCS_GUEST_RSP, vm->guest_rsp);
	vmx_write(VMCS_GUEST_RFLAGS, vm->guest_rflags);

	/* Update host state (CR3 etc. might differ between calls) */
	setup_vmcs_host_state(vm);

	/*
	 * Enter the guest!
	 * sovmm_vmx_run saves/restores GPRs and handles VMLAUNCH vs VMRESUME.
	 * Returns 0 on VM exit, 1 on VMLAUNCH/VMRESUME failure.
	 */
	ret = sovmm_vmx_run(vm->guest_regs, vm->launched);

	if (ret) {
		preempt_enable();
		pr_err("sovmm: VMLAUNCH/VMRESUME failed\n");
		run.exit_reason = SOVMM_EXIT_FAIL;
		if (copy_to_user(uarg, &run, sizeof(run)))
			return -EFAULT;
		return -EIO;
	}

	vm->launched = 1;

	/* Read guest state after exit */
	exit_reason = (u32)vmx_read(VMCS_EXIT_REASON) & 0xFFFF;
	qual = vmx_read(VMCS_EXIT_QUALIFICATION);
	vm->guest_rip = vmx_read(VMCS_GUEST_RIP);
	vm->guest_rsp = vmx_read(VMCS_GUEST_RSP);
	vm->guest_rflags = vmx_read(VMCS_GUEST_RFLAGS);

	run.exit_reason = exit_reason;

	switch (exit_reason) {
	case EXIT_IO: {
		u32 insn_len = (u32)vmx_read(VMCS_EXIT_INSN_LEN);

		run.insn_len = insn_len;
		run.io.size = (qual & 7) + 1;
		run.io.direction = (qual >> 3) & 1;
		run.io.port = (qual >> 16) & 0xFFFF;
		if (run.io.direction == 0) /* OUT */
			run.io.data = (u32)vm->guest_regs[0]; /* RAX */

		/* Advance RIP past the I/O instruction */
		vm->guest_rip += insn_len;
		break;
	}

	case EXIT_HLT:
		run.insn_len = (u32)vmx_read(VMCS_EXIT_INSN_LEN);
		vm->guest_rip += run.insn_len;
		break;

	case EXIT_EPT_VIOLATION:
		run.ept.gpa = vmx_read(VMCS_GUEST_PHYS_ADDR);
		run.ept.is_write = (qual >> 1) & 1;
		break;

	default:
		pr_warn("sovmm: unhandled exit reason %u\n", exit_reason);
		break;
	}

	preempt_enable();

	if (copy_to_user(uarg, &run, sizeof(run)))
		return -EFAULT;
	return 0;
}

static int sovmm_read_guest_mem(struct sovmm_vm *vm,
				struct sovmm_guest_mem __user *uarg)
{
	struct sovmm_guest_mem gm;

	if (copy_from_user(&gm, uarg, sizeof(gm)))
		return -EFAULT;
	if (!vm->guest_mem)
		return -EINVAL;
	if (gm.guest_addr + gm.size > vm->guest_mem_size)
		return -EINVAL;
	if (copy_to_user((void __user *)gm.userspace_addr,
			 vm->guest_mem + gm.guest_addr, gm.size))
		return -EFAULT;
	return 0;
}

/* ====================================================================
 * Section 10: File operations
 * ==================================================================== */

static int sovmm_open(struct inode *inode, struct file *file)
{
	struct sovmm_vm *vm;

	vm = kzalloc(sizeof(*vm), GFP_KERNEL);
	if (!vm)
		return -ENOMEM;

	file->private_data = vm;
	pr_info("sovmm: device opened\n");
	return 0;
}

static int sovmm_release(struct inode *inode, struct file *file)
{
	struct sovmm_vm *vm = file->private_data;

	if (!vm)
		return 0;

	preempt_disable();

	/* Clean up VMX state */
	vmx_disable(vm);

	preempt_enable();

	/* Free VMCS page */
	if (vm->vmcs)
		free_page((unsigned long)vm->vmcs);

	/* Free EPT tables */
	free_ept(vm);

	/* Free guest memory */
	if (vm->guest_pages)
		__free_pages(vm->guest_pages, get_order(vm->guest_mem_size));

	kfree(vm);
	pr_info("sovmm: device closed, VMX disabled\n");
	return 0;
}

static long sovmm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sovmm_vm *vm = file->private_data;

	switch (cmd) {
	case SOVMM_CREATE_VM:
		return sovmm_create_vm(vm);

	case SOVMM_SET_MEMORY:
		return sovmm_set_memory(vm,
			(struct sovmm_memory_region __user *)arg);

	case SOVMM_SET_REGS:
		return sovmm_set_regs(vm, (struct sovmm_regs __user *)arg);

	case SOVMM_GET_REGS:
		return sovmm_get_regs(vm, (struct sovmm_regs __user *)arg);

	case SOVMM_SET_SREGS:
		return sovmm_set_sregs(vm, (struct sovmm_sregs __user *)arg);

	case SOVMM_RUN:
		return sovmm_run_vm(vm, (struct sovmm_run __user *)arg);

	case SOVMM_READ_GUEST_MEM:
		return sovmm_read_guest_mem(vm,
			(struct sovmm_guest_mem __user *)arg);

	default:
		return -ENOTTY;
	}
}

static const struct file_operations sovmm_fops = {
	.owner		= THIS_MODULE,
	.open		= sovmm_open,
	.release	= sovmm_release,
	.unlocked_ioctl	= sovmm_ioctl,
};

static struct miscdevice sovmm_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "sovmm",
	.fops	= &sovmm_fops,
};

/* ====================================================================
 * Section 11: Module init / exit
 * ==================================================================== */

static int __init sovmm_init(void)
{
	int ret;

	ret = misc_register(&sovmm_dev);
	if (ret) {
		pr_err("sovmm: failed to register misc device\n");
		return ret;
	}

	pr_info("sovmm: module loaded, /dev/sovmm available\n");
	return 0;
}

static void __exit sovmm_exit(void)
{
	misc_deregister(&sovmm_dev);
	pr_info("sovmm: module unloaded\n");
}

module_init(sovmm_init);
module_exit(sovmm_exit);
