/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sovmm_vmx_asm.S - VMX entry/exit assembly for SOVMM kernel module
 *
 * Provides sovmm_vmx_run(guest_regs, launched):
 *   - Saves host callee-saved registers
 *   - Sets HOST_RSP in VMCS to current stack
 *   - Loads guest GPRs from array
 *   - Executes VMLAUNCH (first run) or VMRESUME (subsequent)
 *   - On VM exit: saves guest GPRs back to array
 *   - Returns 0 on successful VM exit, 1 on VMLAUNCH/VMRESUME failure
 *
 * sovmm_vmx_return is the HOST_RIP target (where CPU jumps on VM exit).
 */

/* Guest register offsets in the unsigned long[16] array */
#define REGS_RAX  0x00
#define REGS_RCX  0x08
#define REGS_RDX  0x10
#define REGS_RBX  0x18
/* 0x20 = RSP slot (managed via VMCS, not GPR array) */
#define REGS_RBP  0x28
#define REGS_RSI  0x30
#define REGS_RDI  0x38
#define REGS_R8   0x40
#define REGS_R9   0x48
#define REGS_R10  0x50
#define REGS_R11  0x58
#define REGS_R12  0x60
#define REGS_R13  0x68
#define REGS_R14  0x70
#define REGS_R15  0x78

/* VMCS field encoding for HOST_RSP */
#define VMCS_HOST_RSP  0x6C14

.text

/*
 * int sovmm_vmx_run(unsigned long *guest_regs, int launched)
 *
 * Arguments (x86_64 calling convention):
 *   %rdi = pointer to guest_regs[16] array
 *   %esi = 0 for VMLAUNCH, nonzero for VMRESUME
 *
 * Returns:
 *   %eax = 0 on VM exit (success), 1 on failure
 */
.global sovmm_vmx_run
sovmm_vmx_run:
	/* Save callee-saved host registers */
	push %rbx
	push %rbp
	push %r12
	push %r13
	push %r14
	push %r15

	/* Push guest_regs pointer - will be recovered after VM exit */
	push %rdi

	/*
	 * Set HOST_RSP = current RSP (after all pushes).
	 * On VM exit, the CPU restores RSP from this VMCS field,
	 * so our pushed values are accessible.
	 * Note: vmwrite modifies FLAGS.
	 */
	mov $VMCS_HOST_RSP, %rax
	vmwrite %rsp, %rax

	/*
	 * Test 'launched' flag AFTER vmwrite (which clobbers FLAGS).
	 * MOV instructions below do NOT affect FLAGS, so ZF is
	 * preserved until the conditional jump.
	 */
	test %esi, %esi

	/* Load all guest GPRs from the array */
	mov REGS_RAX(%rdi), %rax
	mov REGS_RCX(%rdi), %rcx
	mov REGS_RDX(%rdi), %rdx
	mov REGS_RBX(%rdi), %rbx
	mov REGS_RBP(%rdi), %rbp
	mov REGS_RSI(%rdi), %rsi
	mov REGS_R8(%rdi),  %r8
	mov REGS_R9(%rdi),  %r9
	mov REGS_R10(%rdi), %r10
	mov REGS_R11(%rdi), %r11
	mov REGS_R12(%rdi), %r12
	mov REGS_R13(%rdi), %r13
	mov REGS_R14(%rdi), %r14
	mov REGS_R15(%rdi), %r15
	mov REGS_RDI(%rdi), %rdi	/* load guest RDI LAST (trashes pointer) */

	/* Branch: ZF still reflects test %esi,%esi from above */
	jnz .Lresume

	vmlaunch
	jmp .Lfail

.Lresume:
	vmresume
	/* fall through to .Lfail if VMRESUME fails */

.Lfail:
	/*
	 * VMLAUNCH/VMRESUME failed.
	 * All GPRs hold guest values we loaded, but guest never ran.
	 * Stack top has saved guest_regs pointer.
	 */
	pop %rdi		/* discard saved regs pointer */
	mov $1, %eax		/* return 1 = failure */
	jmp .Lout

/*
 * VM exit handler - HOST_RIP in VMCS points here.
 * CPU restores host state and jumps here on any VM exit.
 * All GPRs contain guest values at this point.
 */
.global sovmm_vmx_return
sovmm_vmx_return:
	/*
	 * RSP was restored from HOST_RSP (set above).
	 * Stack top = saved guest_regs pointer (pushed before vmlaunch).
	 *
	 * Swap guest RDI with saved pointer using xchg:
	 *   before: %rdi = guest_rdi, (%rsp) = regs_ptr
	 *   after:  %rdi = regs_ptr,  (%rsp) = guest_rdi
	 */
	xchg %rdi, (%rsp)

	/* Save guest GPRs back to the array */
	mov %rax, REGS_RAX(%rdi)
	mov %rcx, REGS_RCX(%rdi)
	mov %rdx, REGS_RDX(%rdi)
	mov %rbx, REGS_RBX(%rdi)
	mov %rbp, REGS_RBP(%rdi)
	mov %rsi, REGS_RSI(%rdi)
	popq      REGS_RDI(%rdi)	/* pop guest RDI from stack */
	mov %r8,  REGS_R8(%rdi)
	mov %r9,  REGS_R9(%rdi)
	mov %r10, REGS_R10(%rdi)
	mov %r11, REGS_R11(%rdi)
	mov %r12, REGS_R12(%rdi)
	mov %r13, REGS_R13(%rdi)
	mov %r14, REGS_R14(%rdi)
	mov %r15, REGS_R15(%rdi)

	xor %eax, %eax		/* return 0 = VM exit (success) */

.Lout:
	/* Restore callee-saved host registers */
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %rbp
	pop %rbx
	ret
