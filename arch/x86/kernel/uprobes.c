// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * User-space Probes (UProbes) for x86
 *
 * Copyright (C) IBM Corporation, 2008-2011
 * Authors:
 *	Srikar Dronamraju
 *	Jim Keniston
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uprobes.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>

#include <linux/kdebug.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/security.h>
#include <asm/processor.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/mmu_context.h>
#include <asm/nops.h>
#include <asm/cpufeature.h>
#include <asm/cpuid/api.h>

/* Post-execution fixups. */

/* Adjust IP back to vicinity of actual insn */
#define UPROBE_FIX_IP		0x01

/* Adjust the return address of a call insn */
#define UPROBE_FIX_CALL		0x02

/* Instruction will modify TF, don't change it */
#define UPROBE_FIX_SETF		0x04

#define UPROBE_FIX_RIP_SI	0x08
#define UPROBE_FIX_RIP_DI	0x10
#define UPROBE_FIX_RIP_BX	0x20
#define UPROBE_FIX_RIP_MASK	\
	(UPROBE_FIX_RIP_SI | UPROBE_FIX_RIP_DI | UPROBE_FIX_RIP_BX)

#define	UPROBE_TRAP_NR		UINT_MAX

/* Adaptations for mhiramat x86 decoder v14. */
#define OPCODE1(insn)		((insn)->opcode.bytes[0])
#define OPCODE2(insn)		((insn)->opcode.bytes[1])
#define OPCODE3(insn)		((insn)->opcode.bytes[2])
#define MODRM_REG(insn)		X86_MODRM_REG((insn)->modrm.value)

#define W(row, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, ba, bb, bc, bd, be, bf)\
	(((b0##UL << 0x0)|(b1##UL << 0x1)|(b2##UL << 0x2)|(b3##UL << 0x3) |   \
	  (b4##UL << 0x4)|(b5##UL << 0x5)|(b6##UL << 0x6)|(b7##UL << 0x7) |   \
	  (b8##UL << 0x8)|(b9##UL << 0x9)|(ba##UL << 0xa)|(bb##UL << 0xb) |   \
	  (bc##UL << 0xc)|(bd##UL << 0xd)|(be##UL << 0xe)|(bf##UL << 0xf))    \
	 << (row % 32))

/*
 * Good-instruction tables for 32-bit apps.  This is non-const and volatile
 * to keep gcc from statically optimizing it out, as variable_test_bit makes
 * some versions of gcc to think only *(unsigned long*) is used.
 *
 * Opcodes we'll probably never support:
 * 6c-6f - ins,outs. SEGVs if used in userspace
 * e4-e7 - in,out imm. SEGVs if used in userspace
 * ec-ef - in,out acc. SEGVs if used in userspace
 * cc - int3. SIGTRAP if used in userspace
 * ce - into. Not used in userspace - no kernel support to make it useful. SEGVs
 *	(why we support bound (62) then? it's similar, and similarly unused...)
 * f1 - int1. SIGTRAP if used in userspace
 * f4 - hlt. SEGVs if used in userspace
 * fa - cli. SEGVs if used in userspace
 * fb - sti. SEGVs if used in userspace
 *
 * Opcodes which need some work to be supported:
 * 07,17,1f - pop es/ss/ds
 *	Normally not used in userspace, but would execute if used.
 *	Can cause GP or stack exception if tries to load wrong segment descriptor.
 *	We hesitate to run them under single step since kernel's handling
 *	of userspace single-stepping (TF flag) is fragile.
 *	We can easily refuse to support push es/cs/ss/ds (06/0e/16/1e)
 *	on the same grounds that they are never used.
 * cd - int N.
 *	Used by userspace for "int 80" syscall entry. (Other "int N"
 *	cause GP -> SEGV since their IDT gates don't allow calls from CPL 3).
 *	Not supported since kernel's handling of userspace single-stepping
 *	(TF flag) is fragile.
 * cf - iret. Normally not used in userspace. Doesn't SEGV unless arguments are bad
 */
#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
static volatile u32 good_insns_32[256 / 32] = {
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
	/*      ----------------------------------------------         */
	W(0x00, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1) | /* 00 */
	W(0x10, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0) , /* 10 */
	W(0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 20 */
	W(0x30, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 30 */
	W(0x40, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 40 */
	W(0x50, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 50 */
	W(0x60, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0) | /* 60 */
	W(0x70, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 70 */
	W(0x80, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 80 */
	W(0x90, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 90 */
	W(0xa0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* a0 */
	W(0xb0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* b0 */
	W(0xc0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0) | /* c0 */
	W(0xd0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* d0 */
	W(0xe0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0) | /* e0 */
	W(0xf0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1)   /* f0 */
	/*      ----------------------------------------------         */
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
};
#else
#define good_insns_32	NULL
#endif

/* Good-instruction tables for 64-bit apps.
 *
 * Genuinely invalid opcodes:
 * 06,07 - formerly push/pop es
 * 0e - formerly push cs
 * 16,17 - formerly push/pop ss
 * 1e,1f - formerly push/pop ds
 * 27,2f,37,3f - formerly daa/das/aaa/aas
 * 60,61 - formerly pusha/popa
 * 62 - formerly bound. EVEX prefix for AVX512 (not yet supported)
 * 82 - formerly redundant encoding of Group1
 * 9a - formerly call seg:ofs
 * ce - formerly into
 * d4,d5 - formerly aam/aad
 * d6 - formerly undocumented salc
 * ea - formerly jmp seg:ofs
 *
 * Opcodes we'll probably never support:
 * 6c-6f - ins,outs. SEGVs if used in userspace
 * e4-e7 - in,out imm. SEGVs if used in userspace
 * ec-ef - in,out acc. SEGVs if used in userspace
 * cc - int3. SIGTRAP if used in userspace
 * f1 - int1. SIGTRAP if used in userspace
 * f4 - hlt. SEGVs if used in userspace
 * fa - cli. SEGVs if used in userspace
 * fb - sti. SEGVs if used in userspace
 *
 * Opcodes which need some work to be supported:
 * cd - int N.
 *	Used by userspace for "int 80" syscall entry. (Other "int N"
 *	cause GP -> SEGV since their IDT gates don't allow calls from CPL 3).
 *	Not supported since kernel's handling of userspace single-stepping
 *	(TF flag) is fragile.
 * cf - iret. Normally not used in userspace. Doesn't SEGV unless arguments are bad
 */
#if defined(CONFIG_X86_64)
static volatile u32 good_insns_64[256 / 32] = {
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
	/*      ----------------------------------------------         */
	W(0x00, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1) | /* 00 */
	W(0x10, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0) , /* 10 */
	W(0x20, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0) | /* 20 */
	W(0x30, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0) , /* 30 */
	W(0x40, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 40 */
	W(0x50, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 50 */
	W(0x60, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0) | /* 60 */
	W(0x70, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 70 */
	W(0x80, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 80 */
	W(0x90, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1) , /* 90 */
	W(0xa0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* a0 */
	W(0xb0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* b0 */
	W(0xc0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0) | /* c0 */
	W(0xd0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* d0 */
	W(0xe0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0) | /* e0 */
	W(0xf0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1)   /* f0 */
	/*      ----------------------------------------------         */
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
};
#else
#define good_insns_64	NULL
#endif

/* Using this for both 64-bit and 32-bit apps.
 * Opcodes we don't support:
 * 0f 00 - SLDT/STR/LLDT/LTR/VERR/VERW/-/- group. System insns
 * 0f 01 - SGDT/SIDT/LGDT/LIDT/SMSW/-/LMSW/INVLPG group.
 *	Also encodes tons of other system insns if mod=11.
 *	Some are in fact non-system: xend, xtest, rdtscp, maybe more
 * 0f 05 - syscall
 * 0f 06 - clts (CPL0 insn)
 * 0f 07 - sysret
 * 0f 08 - invd (CPL0 insn)
 * 0f 09 - wbinvd (CPL0 insn)
 * 0f 0b - ud2
 * 0f 30 - wrmsr (CPL0 insn) (then why rdmsr is allowed, it's also CPL0 insn?)
 * 0f 34 - sysenter
 * 0f 35 - sysexit
 * 0f 37 - getsec
 * 0f 78 - vmread (Intel VMX. CPL0 insn)
 * 0f 79 - vmwrite (Intel VMX. CPL0 insn)
 *	Note: with prefixes, these two opcodes are
 *	extrq/insertq/AVX512 convert vector ops.
 * 0f ae - group15: [f]xsave,[f]xrstor,[v]{ld,st}mxcsr,clflush[opt],
 *	{rd,wr}{fs,gs}base,{s,l,m}fence.
 *	Why? They are all user-executable.
 */
static volatile u32 good_2byte_insns[256 / 32] = {
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
	/*      ----------------------------------------------         */
	W(0x00, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1) | /* 00 */
	W(0x10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 10 */
	W(0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 20 */
	W(0x30, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1) , /* 30 */
	W(0x40, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 40 */
	W(0x50, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 50 */
	W(0x60, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 60 */
	W(0x70, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1) , /* 70 */
	W(0x80, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 80 */
	W(0x90, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 90 */
	W(0xa0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1) | /* a0 */
	W(0xb0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* b0 */
	W(0xc0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* c0 */
	W(0xd0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* d0 */
	W(0xe0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* e0 */
	W(0xf0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)   /* f0 */
	/*      ----------------------------------------------         */
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
};
#undef W

/*
 * opcodes we may need to refine support for:
 *
 *  0f - 2-byte instructions: For many of these instructions, the validity
 *  depends on the prefix and/or the reg field.  On such instructions, we
 *  just consider the opcode combination valid if it corresponds to any
 *  valid instruction.
 *
 *  8f - Group 1 - only reg = 0 is OK
 *  c6-c7 - Group 11 - only reg = 0 is OK
 *  d9-df - fpu insns with some illegal encodings
 *  f2, f3 - repnz, repz prefixes.  These are also the first byte for
 *  certain floating-point instructions, such as addsd.
 *
 *  fe - Group 4 - only reg = 0 or 1 is OK
 *  ff - Group 5 - only reg = 0-6 is OK
 *
 * others -- Do we need to support these?
 *
 *  0f - (floating-point?) prefetch instructions
 *  07, 17, 1f - pop es, pop ss, pop ds
 *  26, 2e, 36, 3e - es:, cs:, ss:, ds: segment prefixes --
 *	but 64 and 65 (fs: and gs:) seem to be used, so we support them
 *  67 - addr16 prefix
 *  ce - into
 *  f0 - lock prefix
 */

/*
 * TODO:
 * - Where necessary, examine the modrm byte and allow only valid instructions
 * in the different Groups and fpu instructions.
 */

static bool is_prefix_bad(struct insn *insn)
{
	insn_byte_t p;

	for_each_insn_prefix(insn, p) {
		insn_attr_t attr;

		attr = inat_get_opcode_attribute(p);
		switch (attr) {
		case INAT_MAKE_PREFIX(INAT_PFX_ES):
		case INAT_MAKE_PREFIX(INAT_PFX_CS):
		case INAT_MAKE_PREFIX(INAT_PFX_DS):
		case INAT_MAKE_PREFIX(INAT_PFX_SS):
		case INAT_MAKE_PREFIX(INAT_PFX_LOCK):
			return true;
		}
	}
	return false;
}

static int uprobe_init_insn(struct arch_uprobe *auprobe, struct insn *insn)
{
	u32 volatile *good_insns;

	if (is_prefix_bad(insn))
		return -ENOTSUPP;

	/* We should not singlestep on the exception masking instructions */
	if (insn_masking_exception(insn))
		return -ENOTSUPP;

	if (insn->x86_64)
		good_insns = good_insns_64;
	else
		good_insns = good_insns_32;

	if (test_bit(OPCODE1(insn), (unsigned long *)good_insns))
		return 0;

	if (insn->opcode.nbytes == 2) {
		if (test_bit(OPCODE2(insn), (unsigned long *)good_2byte_insns))
			return 0;
	}

	return -ENOTSUPP;
}

#ifdef CONFIG_X86_64

struct uretprobe_syscall_args {
	unsigned long r11;
	unsigned long cx;
	unsigned long ax;
};

asm (
	".pushsection .rodata\n"
	".global uretprobe_trampoline_entry\n"
	"uretprobe_trampoline_entry:\n"
	"push %rax\n"
	"push %rcx\n"
	"push %r11\n"
	"mov $" __stringify(__NR_uretprobe) ", %rax\n"
	"syscall\n"
	".global uretprobe_syscall_check\n"
	"uretprobe_syscall_check:\n"
	"pop %r11\n"
	"pop %rcx\n"
	/*
	 * The uretprobe syscall replaces stored %rax value with final
	 * return address, so we don't restore %rax in here and just
	 * call ret.
	 */
	"ret\n"
	"int3\n"
	".global uretprobe_trampoline_end\n"
	"uretprobe_trampoline_end:\n"
	".popsection\n"
);

extern u8 uretprobe_trampoline_entry[];
extern u8 uretprobe_trampoline_end[];
extern u8 uretprobe_syscall_check[];

void *arch_uretprobe_trampoline(unsigned long *psize)
{
	static uprobe_opcode_t insn = UPROBE_SWBP_INSN;
	struct pt_regs *regs = task_pt_regs(current);

	/*
	 * At the moment the uretprobe syscall trampoline is supported
	 * only for native 64-bit process, the compat process still uses
	 * standard breakpoint.
	 */
	if (user_64bit_mode(regs)) {
		*psize = uretprobe_trampoline_end - uretprobe_trampoline_entry;
		return uretprobe_trampoline_entry;
	}

	*psize = UPROBE_SWBP_INSN_SIZE;
	return &insn;
}

static unsigned long trampoline_check_ip(unsigned long tramp)
{
	return tramp + (uretprobe_syscall_check - uretprobe_trampoline_entry);
}

SYSCALL_DEFINE0(uretprobe)
{
	struct pt_regs *regs = task_pt_regs(current);
	struct uretprobe_syscall_args args;
	unsigned long err, ip, sp, tramp;

	/* If there's no trampoline, we are called from wrong place. */
	tramp = uprobe_get_trampoline_vaddr();
	if (unlikely(tramp == UPROBE_NO_TRAMPOLINE_VADDR))
		goto sigill;

	/* Make sure the ip matches the only allowed sys_uretprobe caller. */
	if (unlikely(regs->ip != trampoline_check_ip(tramp)))
		goto sigill;

	err = copy_from_user(&args, (void __user *)regs->sp, sizeof(args));
	if (err)
		goto sigill;

	/* expose the "right" values of r11/cx/ax/sp to uprobe_consumer/s */
	regs->r11 = args.r11;
	regs->cx  = args.cx;
	regs->ax  = args.ax;
	regs->sp += sizeof(args);
	regs->orig_ax = -1;

	ip = regs->ip;
	sp = regs->sp;

	uprobe_handle_trampoline(regs);

	/*
	 * Some of the uprobe consumers has changed sp, we can do nothing,
	 * just return via iret.
	 * .. or shadow stack is enabled, in which case we need to skip
	 * return through the user space stack address.
	 */
	if (regs->sp != sp || shstk_is_enabled())
		return regs->ax;
	regs->sp -= sizeof(args);

	/* for the case uprobe_consumer has changed r11/cx */
	args.r11 = regs->r11;
	args.cx  = regs->cx;

	/*
	 * ax register is passed through as return value, so we can use
	 * its space on stack for ip value and jump to it through the
	 * trampoline's ret instruction
	 */
	args.ax  = regs->ip;
	regs->ip = ip;

	err = copy_to_user((void __user *)regs->sp, &args, sizeof(args));
	if (err)
		goto sigill;

	/* ensure sysret, see do_syscall_64() */
	regs->r11 = regs->flags;
	regs->cx  = regs->ip;

	return regs->ax;

sigill:
	force_sig(SIGILL);
	return -1;
}

/*
 * If arch_uprobe->insn doesn't use rip-relative addressing, return
 * immediately.  Otherwise, rewrite the instruction so that it accesses
 * its memory operand indirectly through a scratch register.  Set
 * defparam->fixups accordingly. (The contents of the scratch register
 * will be saved before we single-step the modified instruction,
 * and restored afterward).
 *
 * We do this because a rip-relative instruction can access only a
 * relatively small area (+/- 2 GB from the instruction), and the XOL
 * area typically lies beyond that area.  At least for instructions
 * that store to memory, we can't execute the original instruction
 * and "fix things up" later, because the misdirected store could be
 * disastrous.
 *
 * Some useful facts about rip-relative instructions:
 *
 *  - There's always a modrm byte with bit layout "00 reg 101".
 *  - There's never a SIB byte.
 *  - The displacement is always 4 bytes.
 *  - REX.B=1 bit in REX prefix, which normally extends r/m field,
 *    has no effect on rip-relative mode. It doesn't make modrm byte
 *    with r/m=101 refer to register 1101 = R13.
 */
static void riprel_analyze(struct arch_uprobe *auprobe, struct insn *insn)
{
	u8 *cursor;
	u8 reg;
	u8 reg2;

	if (!insn_rip_relative(insn))
		return;

	/*
	 * insn_rip_relative() would have decoded rex_prefix, vex_prefix, modrm.
	 * Clear REX.b bit (extension of MODRM.rm field):
	 * we want to encode low numbered reg, not r8+.
	 */
	if (insn->rex_prefix.nbytes) {
		cursor = auprobe->insn + insn_offset_rex_prefix(insn);
		/* REX byte has 0100wrxb layout, clearing REX.b bit */
		*cursor &= 0xfe;
	}
	/*
	 * Similar treatment for VEX3/EVEX prefix.
	 * TODO: add XOP treatment when insn decoder supports them
	 */
	if (insn->vex_prefix.nbytes >= 3) {
		/*
		 * vex2:     c5    rvvvvLpp   (has no b bit)
		 * vex3/xop: c4/8f rxbmmmmm wvvvvLpp
		 * evex:     62    rxbR00mm wvvvv1pp zllBVaaa
		 * Setting VEX3.b (setting because it has inverted meaning).
		 * Setting EVEX.x since (in non-SIB encoding) EVEX.x
		 * is the 4th bit of MODRM.rm, and needs the same treatment.
		 * For VEX3-encoded insns, VEX3.x value has no effect in
		 * non-SIB encoding, the change is superfluous but harmless.
		 */
		cursor = auprobe->insn + insn_offset_vex_prefix(insn) + 1;
		*cursor |= 0x60;
	}

	/*
	 * Convert from rip-relative addressing to register-relative addressing
	 * via a scratch register.
	 *
	 * This is tricky since there are insns with modrm byte
	 * which also use registers not encoded in modrm byte:
	 * [i]div/[i]mul: implicitly use dx:ax
	 * shift ops: implicitly use cx
	 * cmpxchg: implicitly uses ax
	 * cmpxchg8/16b: implicitly uses dx:ax and bx:cx
	 *   Encoding: 0f c7/1 modrm
	 *   The code below thinks that reg=1 (cx), chooses si as scratch.
	 * mulx: implicitly uses dx: mulx r/m,r1,r2 does r1:r2 = dx * r/m.
	 *   First appeared in Haswell (BMI2 insn). It is vex-encoded.
	 *   Example where none of bx,cx,dx can be used as scratch reg:
	 *   c4 e2 63 f6 0d disp32   mulx disp32(%rip),%ebx,%ecx
	 * [v]pcmpistri: implicitly uses cx, xmm0
	 * [v]pcmpistrm: implicitly uses xmm0
	 * [v]pcmpestri: implicitly uses ax, dx, cx, xmm0
	 * [v]pcmpestrm: implicitly uses ax, dx, xmm0
	 *   Evil SSE4.2 string comparison ops from hell.
	 * maskmovq/[v]maskmovdqu: implicitly uses (ds:rdi) as destination.
	 *   Encoding: 0f f7 modrm, 66 0f f7 modrm, vex-encoded: c5 f9 f7 modrm.
	 *   Store op1, byte-masked by op2 msb's in each byte, to (ds:rdi).
	 *   AMD says it has no 3-operand form (vex.vvvv must be 1111)
	 *   and that it can have only register operands, not mem
	 *   (its modrm byte must have mode=11).
	 *   If these restrictions will ever be lifted,
	 *   we'll need code to prevent selection of di as scratch reg!
	 *
	 * Summary: I don't know any insns with modrm byte which
	 * use SI register implicitly. DI register is used only
	 * by one insn (maskmovq) and BX register is used
	 * only by one too (cmpxchg8b).
	 * BP is stack-segment based (may be a problem?).
	 * AX, DX, CX are off-limits (many implicit users).
	 * SP is unusable (it's stack pointer - think about "pop mem";
	 * also, rsp+disp32 needs sib encoding -> insn length change).
	 */

	reg = MODRM_REG(insn);	/* Fetch modrm.reg */
	reg2 = 0xff;		/* Fetch vex.vvvv */
	if (insn->vex_prefix.nbytes)
		reg2 = insn->vex_prefix.bytes[2];
	/*
	 * TODO: add XOP vvvv reading.
	 *
	 * vex.vvvv field is in bits 6-3, bits are inverted.
	 * But in 32-bit mode, high-order bit may be ignored.
	 * Therefore, let's consider only 3 low-order bits.
	 */
	reg2 = ((reg2 >> 3) & 0x7) ^ 0x7;
	/*
	 * Register numbering is ax,cx,dx,bx, sp,bp,si,di, r8..r15.
	 *
	 * Choose scratch reg. Order is important: must not select bx
	 * if we can use si (cmpxchg8b case!)
	 */
	if (reg != 6 && reg2 != 6) {
		reg2 = 6;
		auprobe->defparam.fixups |= UPROBE_FIX_RIP_SI;
	} else if (reg != 7 && reg2 != 7) {
		reg2 = 7;
		auprobe->defparam.fixups |= UPROBE_FIX_RIP_DI;
		/* TODO (paranoia): force maskmovq to not use di */
	} else {
		reg2 = 3;
		auprobe->defparam.fixups |= UPROBE_FIX_RIP_BX;
	}
	/*
	 * Point cursor at the modrm byte.  The next 4 bytes are the
	 * displacement.  Beyond the displacement, for some instructions,
	 * is the immediate operand.
	 */
	cursor = auprobe->insn + insn_offset_modrm(insn);
	/*
	 * Change modrm from "00 reg 101" to "10 reg reg2". Example:
	 * 89 05 disp32  mov %eax,disp32(%rip) becomes
	 * 89 86 disp32  mov %eax,disp32(%rsi)
	 */
	*cursor = 0x80 | (reg << 3) | reg2;
}

static inline unsigned long *
scratch_reg(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	if (auprobe->defparam.fixups & UPROBE_FIX_RIP_SI)
		return &regs->si;
	if (auprobe->defparam.fixups & UPROBE_FIX_RIP_DI)
		return &regs->di;
	return &regs->bx;
}

/*
 * If we're emulating a rip-relative instruction, save the contents
 * of the scratch register and store the target address in that register.
 */
static void riprel_pre_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	if (auprobe->defparam.fixups & UPROBE_FIX_RIP_MASK) {
		struct uprobe_task *utask = current->utask;
		unsigned long *sr = scratch_reg(auprobe, regs);

		utask->autask.saved_scratch_register = *sr;
		*sr = utask->vaddr + auprobe->defparam.ilen;
	}
}

static void riprel_post_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	if (auprobe->defparam.fixups & UPROBE_FIX_RIP_MASK) {
		struct uprobe_task *utask = current->utask;
		unsigned long *sr = scratch_reg(auprobe, regs);

		*sr = utask->autask.saved_scratch_register;
	}
}

static int tramp_mremap(const struct vm_special_mapping *sm, struct vm_area_struct *new_vma)
{
	return -EPERM;
}

static struct page *tramp_mapping_pages[2] __ro_after_init;

static struct vm_special_mapping tramp_mapping = {
	.name   = "[uprobes-trampoline]",
	.mremap = tramp_mremap,
	.pages  = tramp_mapping_pages,
};


#define LEA_INSN_SIZE		5
#define OPT_INSN_SIZE		(LEA_INSN_SIZE + CALL_INSN_SIZE)
#define REDZONE_SIZE		0x80

static const u8 lea_rsp[] = { 0x48, 0x8d, 0x64, 0x24, 0x80 };

static bool is_opt_insns(const uprobe_opcode_t *insn)
{
	return !memcmp(insn, lea_rsp, LEA_INSN_SIZE) &&
	       insn[LEA_INSN_SIZE] == CALL_INSN_OPCODE;
}

static bool is_swbp_opt_insns(uprobe_opcode_t *insn)
{
	return is_swbp_insn(&insn[0]) &&
	       !memcmp(&insn[1], &lea_rsp[1], LEA_INSN_SIZE - 1) &&
	       insn[LEA_INSN_SIZE] == CALL_INSN_OPCODE;
}

static bool is_reachable_by_call(unsigned long vtramp, unsigned long vaddr)
{
	long delta = (long)(vaddr + OPT_INSN_SIZE - vtramp);

	return delta >= INT_MIN && delta <= INT_MAX;
}

static unsigned long find_nearest_trampoline(unsigned long vaddr)
{
	struct vm_unmapped_area_info info = {
		.length     = PAGE_SIZE,
		.align_mask = ~PAGE_MASK,
	};
	unsigned long low_limit, high_limit;
	unsigned long low_tramp, high_tramp;
	unsigned long call_end = vaddr + OPT_INSN_SIZE;

	if (check_add_overflow(call_end, INT_MIN, &low_limit))
		low_limit = PAGE_SIZE;

	high_limit = call_end + INT_MAX;

	/* Search up from the caller address. */
	info.low_limit = call_end;
	info.high_limit = min(high_limit, TASK_SIZE);
	high_tramp = vm_unmapped_area(&info);

	/* Search down from the caller address. */
	info.low_limit = max(low_limit, PAGE_SIZE);
	info.high_limit = call_end;
	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	low_tramp = vm_unmapped_area(&info);

	if (IS_ERR_VALUE(high_tramp) && IS_ERR_VALUE(low_tramp))
		return -ENOMEM;
	if (IS_ERR_VALUE(high_tramp))
		return low_tramp;
	if (IS_ERR_VALUE(low_tramp))
		return high_tramp;

	/* Return address that's closest to the caller address. */
	if (call_end - low_tramp < high_tramp - call_end)
		return low_tramp;
	return high_tramp;
}

static struct vm_area_struct *get_uprobe_trampoline(struct mm_struct *mm, unsigned long vaddr,
						    bool *new_mapping)
{
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *vma;

	*new_mapping = false;

	if (vaddr > TASK_SIZE || vaddr < PAGE_SIZE)
		return ERR_PTR(-EINVAL);

	for_each_vma(vmi, vma) {
		if (!vma_is_special_mapping(vma, &tramp_mapping))
			continue;
		if (is_reachable_by_call(vma->vm_start, vaddr))
			return vma;
	}

	vaddr = find_nearest_trampoline(vaddr);
	if (IS_ERR_VALUE(vaddr))
		return ERR_PTR(vaddr);

	*new_mapping = true;
	return _install_special_mapping(mm, vaddr, PAGE_SIZE,
				VM_READ|VM_EXEC|VM_MAYEXEC|VM_MAYREAD|VM_IO,
				&tramp_mapping);
}

void arch_uprobe_init_state(struct mm_struct *mm)
{
	INIT_HLIST_HEAD(&mm->uprobes_state.head_ptwrite);
}

static void free_uprobe_ptwrite_page_rcu(struct rcu_head *rcu)
{
	struct uprobe_ptwrite_page *ptw =
		container_of(rcu, struct uprobe_ptwrite_page, rcu);

	__free_page(ptw->page);
	kfree(ptw);
}

void arch_uprobe_clear_state(struct mm_struct *mm)
{
	struct uprobes_state *state = &mm->uprobes_state;
	struct uprobe_ptwrite_page *ptw;
	struct hlist_node *n;

	hlist_for_each_entry_safe(ptw, n, &state->head_ptwrite, node) {
		hlist_del_rcu(&ptw->node);
		call_rcu(&ptw->rcu, free_uprobe_ptwrite_page_rcu);
	}
}

static vm_fault_t ptwrite_fault(const struct vm_special_mapping *sm,
				struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct uprobes_state *state = &vma->vm_mm->uprobes_state;
	struct uprobe_ptwrite_page *ptw;

	rcu_read_lock();
	hlist_for_each_entry_rcu(ptw, &state->head_ptwrite, node) {
		if (ptw->vaddr == vma->vm_start) {
			vmf->page = ptw->page;
			get_page(vmf->page);
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();
	return VM_FAULT_SIGBUS;
}

static int ptwrite_mremap(const struct vm_special_mapping *sm,
			  struct vm_area_struct *new_vma)
{
	return -EPERM;
}

static const struct vm_special_mapping ptwrite_mapping = {
	.name	= "[uprobes-ptwrite]",
	.fault	= ptwrite_fault,
	.mremap	= ptwrite_mremap,
};

static bool __in_uprobe_ptwrite(struct mm_struct *mm, unsigned long ip)
{
	struct vm_area_struct *vma = vma_lookup(mm, ip);

	return vma && vma_is_special_mapping(vma, &ptwrite_mapping);
}

static struct vm_area_struct *
install_uprobe_ptwrite_vma(struct mm_struct *mm, unsigned long addr)
{
	return _install_special_mapping(mm, addr, PAGE_SIZE,
			VM_READ | VM_EXEC | VM_MAYEXEC | VM_MAYREAD |
			VM_IO | VM_DONTCOPY, &ptwrite_mapping);
}

int uprobe_ptwrite_dup_mmap(struct mm_struct *oldmm, struct mm_struct *newmm)
{
	struct uprobes_state *old_state = &oldmm->uprobes_state;
	struct uprobes_state *new_state = &newmm->uprobes_state;
	struct uprobe_ptwrite_page *ptw, *new;
	struct vm_area_struct *vma;
	struct hlist_node *n;

	mmap_assert_write_locked(oldmm);
	mmap_assert_write_locked(newmm);
	hlist_for_each_entry(ptw, &old_state->head_ptwrite, node) {
		void *src, *dst;

		/*
		 * Not using __GFP_ACCOUNT here because it triggered
		 * a deadlock.
		 */
		new = kzalloc_obj(*new, GFP_KERNEL);
		if (!new)
			goto fail;
		new->page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!new->page) {
			kfree(new);
			goto fail;
		}

		src = kmap_local_page(ptw->page);
		dst = kmap_local_page(new->page);
		memcpy(dst, src, PAGE_SIZE);
		kunmap_local(dst);
		kunmap_local(src);
		new->vaddr = ptw->vaddr;
		new->cursor = ptw->cursor;
		new->nblocks = ptw->nblocks;
		memcpy(new->index, ptw->index, sizeof(new->index));

		vma = install_uprobe_ptwrite_vma(newmm, new->vaddr);
		if (IS_ERR(vma)) {
			__free_page(new->page);
			kfree(new);
			goto fail;
		}

		/* Publish the copied page fields before readers can find it. */
		smp_wmb();
		hlist_add_head_rcu(&new->node, &new_state->head_ptwrite);
	}

	return 0;

fail:
	hlist_for_each_entry_safe(new, n, &new_state->head_ptwrite, node) {
		WARN_ON_ONCE(do_munmap(newmm, new->vaddr, PAGE_SIZE, NULL));
	}
	arch_uprobe_clear_state(newmm);
	return -ENOMEM;
}

static bool __in_uprobe_trampoline(struct mm_struct *mm, unsigned long ip)
{
	struct vm_area_struct *vma = vma_lookup(mm, ip);

	return vma && vma_is_special_mapping(vma, &tramp_mapping);
}

static bool in_uprobe_trampoline(unsigned long ip)
{
	struct mm_struct *mm = current->mm;
	bool found, retry = true;
	unsigned int seq;

	rcu_read_lock();
	if (mmap_lock_speculate_try_begin(mm, &seq)) {
		found = __in_uprobe_trampoline(mm, ip);
		retry = mmap_lock_speculate_retry(mm, seq);
	}
	rcu_read_unlock();

	if (retry) {
		mmap_read_lock(mm);
		found = __in_uprobe_trampoline(mm, ip);
		mmap_read_unlock(mm);
	}
	return found;
}

/*
 * See uprobe syscall trampoline; the call to the trampoline will push
 * the return address on the stack, the trampoline itself then pushes
 * cx, r11 and ax.
 */
struct uprobe_syscall_args {
	unsigned long ax;
	unsigned long r11;
	unsigned long cx;
	unsigned long retaddr;
};

SYSCALL_DEFINE0(uprobe)
{
	struct pt_regs *regs = task_pt_regs(current);
	struct uprobe_syscall_args args;
	unsigned long ip, sp, sret;
	int err;

	/* Allow execution only from uprobe trampolines. */
	if (!in_uprobe_trampoline(regs->ip))
		return -EPROTO;

	err = copy_from_user(&args, (void __user *)regs->sp, sizeof(args));
	if (err)
		goto sigill;

	ip = regs->ip;

	/*
	 * expose the "right" values of ax/r11/cx/ip/sp to uprobe_consumer/s, plus:
	 * - adjust ip to the probe address, call saved next instruction address
	 * - adjust sp to the probe's stack frame (check trampoline code)
	 */
	regs->ax  = args.ax;
	regs->r11 = args.r11;
	regs->cx  = args.cx;
	regs->ip  = args.retaddr - OPT_INSN_SIZE;
	regs->sp += sizeof(args) + REDZONE_SIZE;
	regs->orig_ax = -1;

	sp = regs->sp;

	err = shstk_pop((u64 *)&sret);
	if (err == -EFAULT || (!err && sret != args.retaddr))
		goto sigill;

	handle_syscall_uprobe(regs, regs->ip);

	/*
	 * Some of the uprobe consumers has changed sp, we can do nothing,
	 * just return via iret.
	 */
	if (regs->sp != sp) {
		/* skip the trampoline call */
		if (args.retaddr - OPT_INSN_SIZE == regs->ip)
			regs->ip += OPT_INSN_SIZE;
		return regs->ax;
	}

	regs->sp -= sizeof(args) + REDZONE_SIZE;

	/* for the case uprobe_consumer has changed ax/r11/cx */
	args.ax  = regs->ax;
	args.r11 = regs->r11;
	args.cx  = regs->cx;

	/* keep return address unless we are instructed otherwise */
	if (args.retaddr - OPT_INSN_SIZE != regs->ip)
		args.retaddr = regs->ip;

	if (shstk_push(args.retaddr) == -EFAULT)
		goto sigill;

	regs->ip = ip;

	err = copy_to_user((void __user *)regs->sp, &args, sizeof(args));
	if (err)
		goto sigill;

	/* ensure sysret, see do_syscall_64() */
	regs->r11 = regs->flags;
	regs->cx  = regs->ip;
	return 0;

sigill:
	force_sig(SIGILL);
	return -1;
}

asm (
	".pushsection .rodata\n"
	".balign " __stringify(PAGE_SIZE) "\n"
	"uprobe_trampoline_entry:\n"
	"push %rcx\n"
	"push %r11\n"
	"push %rax\n"
	"mov $" __stringify(__NR_uprobe) ", %rax\n"
	"syscall\n"
	"pop %rax\n"
	"pop %r11\n"
	"pop %rcx\n"
	"ret $" __stringify(REDZONE_SIZE) "\n"
	"int3\n"
	".balign " __stringify(PAGE_SIZE) "\n"
	".popsection\n"
);

extern u8 uprobe_trampoline_entry[];

static int __init arch_uprobes_init(void)
{
	tramp_mapping_pages[0] = virt_to_page(uprobe_trampoline_entry);
	return 0;
}

late_initcall(arch_uprobes_init);

enum {
	EXPECT_SWBP,
	EXPECT_OPTIMIZED,
	EXPECT_SWBP_OPTIMIZED,
	EXPECT_BYTE,
};

struct write_opcode_ctx {
	unsigned long base;
	int expect;
	u8 expect_byte;
};

/*
 * Verification callback used by uprobe_write calls to make sure the underlying
 * instruction is in the expected stage of the INT3 update sequence.
 */
static int verify_insn(struct page *page, unsigned long vaddr, uprobe_opcode_t *new_opcode,
		       int nbytes, void *data)
{
	struct write_opcode_ctx *ctx = data;
	uprobe_opcode_t old_opcode[OPT_INSN_SIZE];
	int len;

	/*
	 * Byte-state checks need only the first byte. Optimized-state checks
	 * inspect the complete ten-byte instruction.
	 */
	len = ctx->expect == EXPECT_OPTIMIZED ||
		ctx->expect == EXPECT_SWBP_OPTIMIZED ? OPT_INSN_SIZE : 1;
	if (PAGE_SIZE - (ctx->base & ~PAGE_MASK) < len)
		return -1;
	uprobe_copy_from_page(page, ctx->base, old_opcode, len);

	switch (ctx->expect) {
	case EXPECT_SWBP:
		if (is_swbp_insn(&old_opcode[0]))
			return 1;
		break;
	case EXPECT_OPTIMIZED:
		if (is_opt_insns(&old_opcode[0]))
			return 1;
		break;
	case EXPECT_SWBP_OPTIMIZED:
		if (is_swbp_opt_insns(&old_opcode[0]))
			return 1;
		break;
	case EXPECT_BYTE:
		if (old_opcode[0] == ctx->expect_byte)
			return 1;
		break;
	}

	return -1;
}

/*
 * Modify the optimized instruction by using INT3 breakpoints on SMP.
 * We completely avoid using stop_machine() here, and achieve the
 * synchronization using INT3 breakpoints and SMP cross-calls.
 * (borrowed comment from smp_text_poke_batch_finish)
 *
 * For optimization (int3_update_optimize):
 *   1) Start with the uprobe INT3 trap already installed
 *   2) Update everything but the first byte
 *   3) Replace the first INT3 by the first byte of the LEA instruction
 *
 * For unoptimization (int3_update_unoptimize):
 *   1) Start with the optimized uprobe lea/call instructions
 *   2) Add an INT3 trap to the address that will be patched
 *   3) Restore the NOP bytes before the call opcode
 *   4) Replace the first INT3 by the first byte of the NOP instruction
 *
 * Note that unoptimization deliberately keeps the call opcode and displacement
 * in bytes 5..9. Those bytes become operands of the restored 10-byte NOP.
 *
 * Since there is only a single target uprobe-trampoline for the given nop10
 * instruction address, the CALL instruction will not be changed across
 * unoptimization/optimization cycles.
 * Therefore, any task that is preempted at the CALL instruction is guaranteed
 * to observe that CALL and not anything else.
 */
static int int3_update_optimize(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
				unsigned long vaddr, uprobe_opcode_t *insn)
{
	struct write_opcode_ctx ctx = {
		.base = vaddr,
	};
	int err;

	/*
	 * 1) Initial state after set_swbp() installed the uprobe:
	 *    cc 2e 0f 1f 84 00 00 00 00 00
	 *
	 *    After a previous unoptimization bytes 5..9 may still contain the
	 *    old call instruction, which remains valid for threads already there.
	 */
	smp_text_poke_sync_each_cpu();

	/*
	 * 2) Rewrite the LEA tail and call displacement:
	 *    cc [8d 64 24 80 e8 d0 d1 d2 d3]
	 */
	ctx.expect = EXPECT_SWBP;
	err = uprobe_write(auprobe, vma, vaddr + 1, insn + 1,
			   OPT_INSN_SIZE - 1, verify_insn,
			   true /* is_register */, false /* do_update_ref_ctr */,
			   &ctx);
	if (err)
		return err;

	smp_text_poke_sync_each_cpu();

	/*
	 * 3) Publish the first LEA byte:
	 *    [48] 8d 64 24 80 e8 d0 d1 d2 d3
	 *
	 *    From offset 0 this is:
	 *      lea -0x80(%rsp), %rsp
	 *      call <uprobe-trampoline>
	 */
	ctx.expect = EXPECT_SWBP_OPTIMIZED;
	err = uprobe_write(auprobe, vma, vaddr, insn, 1, verify_insn,
			   true /* is_register */, false /* do_update_ref_ctr */,
			   &ctx);
	if (err)
		goto error;

	smp_text_poke_sync_each_cpu();
	return 0;

error:
	/*
	 * In all intermediate states byte 0 is INT3, so EXPECT_SWBP covers every
	 * case. Restore NOP bytes 1..4, but keep the valid CALL at bytes 5..9
	 * for a thread that had already executed the LEA before a previous
	 * unoptimization.
	 */
	ctx.expect = EXPECT_SWBP;
	uprobe_write(auprobe, vma, vaddr + 1, auprobe->insn + 1,
		     LEA_INSN_SIZE - 1, verify_insn, true, false, &ctx);
	smp_text_poke_sync_each_cpu();
	return err;
}

static int int3_update_unoptimize(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
				  unsigned long vaddr, uprobe_opcode_t *insn)
{
	uprobe_opcode_t int3 = UPROBE_SWBP_INSN;
	struct write_opcode_ctx ctx = {
		.base = vaddr,
		.expect = EXPECT_OPTIMIZED,
	};
	int err;

	/*
	 * Note the first two uprobe_write calls use is_register=true, because they
	 * are intermediate patching states while the probe is still active, so
	 * we force the exclusive anonymous page for the update.
	 * Also we use do_update_ref_ctr=false because refctr was already updated by
	 * the initial int3 install.
	 *
	 * The last uprobe_write to nop10 instruction is called with is_register=false
	 * and do_update_ref_ctr=true to trigger the refctr update and to instruct
	 * uprobe_write to zap the anonymous page if it now matches the file page.
	 *
	 * 1) Initial optimized state:
	 *    48 8d 64 24 80 e8 d0 d1 d2 d3
	 *
	 * 2) Trap new entries before restoring the NOP bytes:
	 *    [cc] 8d 64 24 80 e8 d0 d1 d2 d3
	 */
	err = uprobe_write(auprobe, vma, vaddr, &int3, 1, verify_insn,
			   true /* is_register */, false /* do_update_ref_ctr */,
			   &ctx);
	if (err)
		return err;

	smp_text_poke_sync_each_cpu();

	/*
	 * 3) Restore bytes 1..4 of the original NOP while keeping byte 0 trapped
	 *    and byte 5 as CALL:
	 *    cc [2e 0f 1f 84] e8 d0 d1 d2 d3
	 */
	ctx.expect = EXPECT_SWBP_OPTIMIZED;
	err = uprobe_write(auprobe, vma, vaddr + 1, insn + 1,
			   LEA_INSN_SIZE - 1, verify_insn,
			   true /* is_register */, false /* do_update_ref_ctr */,
			   &ctx);
	if (err)
		return err;

	smp_text_poke_sync_each_cpu();

	/*
	 * 4) Publish the first byte of the original NOP:
	 *    [66] 2e 0f 1f 84 e8 d0 d1 d2 d3
	 *
	 * From offset 0 this is the restored 10-byte NOP; the CALL opcode and
	 * displacement are now only NOP operands.  Offset 5 still decodes as
	 * CALL for a thread that was already there.
	 */
	ctx.expect = EXPECT_SWBP;
	err = uprobe_write(auprobe, vma, vaddr, insn, 1, verify_insn,
			   false /* is_register */, true /* do_update_ref_ctr */,
			   &ctx);
	if (err)
		return err;

	smp_text_poke_sync_each_cpu();
	return 0;
}

/*
 * Modify a five-byte instruction by using INT3 breakpoints on SMP.
 * The caller supplies the byte expected before the update and controls
 * whether the anonymous page and reference counter are updated on the
 * final write.
 */
static int text_poke_5byte(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
				   unsigned long vaddr, u8 *new5, u8 expect_byte,
				   bool skip_int3, bool is_register, bool final_is_register,
				   bool do_update_ref_ctr, bool *first_phase_done)
{
	uprobe_opcode_t int3 = UPROBE_SWBP_INSN;
	struct write_opcode_ctx ctx = {
		.base = vaddr,
		.expect = EXPECT_BYTE,
		.expect_byte = expect_byte,
	};
	int err;

	if (!skip_int3) {
		err = uprobe_write(auprobe, vma, vaddr, &int3, 1, verify_insn,
				   is_register, false, &ctx);
		if (err)
			return err;
	}
	if (first_phase_done)
		*first_phase_done = true;

	smp_text_poke_sync_each_cpu();

	ctx.expect = EXPECT_SWBP;
	err = uprobe_write(auprobe, vma, vaddr + 1, new5 + 1, 4, verify_insn,
			   is_register, false, &ctx);
	if (err)
		return err;

	smp_text_poke_sync_each_cpu();

	err = uprobe_write(auprobe, vma, vaddr, new5, 1, verify_insn,
			   final_is_register, do_update_ref_ctr, &ctx);
	if (err)
		return err;

	smp_text_poke_sync_each_cpu();
	return 0;
}

static int swbp_optimize(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
			 unsigned long vaddr, unsigned long tramp)
{
	u8 insn[OPT_INSN_SIZE], *call = &insn[LEA_INSN_SIZE];

	/*
	 * We have nop10 instruction (with first byte overwritten to int3),
	 * changing it to:
	 *   lea -0x80(%rsp), %rsp
	 *   call tramp
	 */
	memcpy(insn, lea_rsp, LEA_INSN_SIZE);
	__text_gen_insn(call, CALL_INSN_OPCODE,
			(const void *) (vaddr + LEA_INSN_SIZE),
			(const void *) tramp, CALL_INSN_SIZE);
	return int3_update_optimize(auprobe, vma, vaddr, insn);
}

static int swbp_unoptimize(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
			   unsigned long vaddr)
{
	return int3_update_unoptimize(auprobe, vma, vaddr, auprobe->insn);
}

static int copy_from_vaddr(struct mm_struct *mm, unsigned long vaddr, void *dst, int len)
{
	unsigned int gup_flags = FOLL_FORCE|FOLL_SPLIT_PMD;
	struct vm_area_struct *vma;
	struct page *page;

	page = get_user_page_vma_remote(mm, vaddr, gup_flags, &vma);
	if (IS_ERR(page))
		return PTR_ERR(page);
	uprobe_copy_from_page(page, vaddr, dst, len);
	put_page(page);
	return 0;
}

/*
 * ptwrite uprobes: trap-free user-mode instrumentation.
 *
 * Block layout (mm-independent template, built at registration):
 *   ptwriteq hdr(%rip)      ; header: event_id<<48 | nargs<<40 | magic
 *   ptwriteq %reg / imm(%rip)   ; one per arg
 *   jmp probe+5             ; rel32 patched per-mm at install
 *   [u64 slots: header, imm values]
 */

static int ptwrite_emit_reg(u8 *p, u8 reg)
{
	/* ptwriteq %reg : F3 REX.W[.B] 0F AE /4, modrm = 11 100 rrr */
	*p++ = 0xf3;
	*p++ = (reg & 8) ? 0x49 : 0x48;	/* REX.W, +REX.B for r8-r15 */
	*p++ = 0x0f;
	*p++ = 0xae;
	*p++ = 0xe0 | (reg & 7);
	return 5;
}

static int ptwrite_emit_riprel(u8 *p, s32 disp)
{
	/*
	 * ptwriteq disp32(%rip) : F3 48 0F AE 25 <disp32> (9 bytes)
	 * modrm 0x25 = mod 00, reg 100 (/4, PTWRITE), rm 101 (RIP-relative).
	 */
	*p++ = 0xf3;
	*p++ = 0x48;
	*p++ = 0x0f;
	*p++ = 0xae;
	*p++ = 0x25;
	memcpy(p, &disp, 4);
	return 9;
}

static int ptwrite_emit_lfence(u8 *p)
{
	*p++ = 0x0f;
	*p++ = 0xae;
	*p++ = 0xe8;	/* LFENCE */
	return UPROBE_PTWRITE_LFENCE_SIZE;
}

/* The default pacing: one or more fences per word gap. */
static int ptwrite_emit_lfences(u8 *p)
{
	int i;

	for (i = 0; i < UPROBE_PTWRITE_SERIALIZE_LFENCES; i++)
		p += ptwrite_emit_lfence(p);
	return UPROBE_PTWRITE_SERIALIZE_LFENCES *
		UPROBE_PTWRITE_LFENCE_SIZE;
}
bool arch_uprobe_ptwrite_supported(void)
{
	u32 eax, ebx, ecx, edx;

	if (!boot_cpu_has(X86_FEATURE_INTEL_PT))
		return false;
	if (boot_cpu_data.cpuid_level < 0x14)
		return false;

	/* CPUID.(EAX=14H, ECX=0):EBX[4] = PTWRITE */
	cpuid_count(0x14, 0, &eax, &ebx, &ecx, &edx);
	return !!(ebx & BIT(4));
}

/*
 * x86-64 pt_regs member offset -> GPR index (0=rax..15=r15), matching
 * the uprobe_ptwrite_arg.reg convention used by the stub generator.
 * The offsets are what the generic trace-probe register parser
 * (regs_query_register_offset) puts into FETCH_OP_REG.params.
 */
static const struct {
	unsigned int off;
	u8 idx;
} ptwrite_reg_map[] = {
	{ .off = offsetof(struct pt_regs, ax), .idx = 0 },
	{ .off = offsetof(struct pt_regs, cx), .idx = 1 },
	{ .off = offsetof(struct pt_regs, dx), .idx = 2 },
	{ .off = offsetof(struct pt_regs, bx), .idx = 3 },
	{ .off = offsetof(struct pt_regs, sp), .idx = 4 },
	{ .off = offsetof(struct pt_regs, bp), .idx = 5 },
	{ .off = offsetof(struct pt_regs, si), .idx = 6 },
	{ .off = offsetof(struct pt_regs, di), .idx = 7 },
	{ .off = offsetof(struct pt_regs, r8), .idx = 8 },
	{ .off = offsetof(struct pt_regs, r9), .idx = 9 },
	{ .off = offsetof(struct pt_regs, r10), .idx = 10 },
	{ .off = offsetof(struct pt_regs, r11), .idx = 11 },
	{ .off = offsetof(struct pt_regs, r12), .idx = 12 },
	{ .off = offsetof(struct pt_regs, r13), .idx = 13 },
	{ .off = offsetof(struct pt_regs, r14), .idx = 14 },
	{ .off = offsetof(struct pt_regs, r15), .idx = 15 },
};

/*
 * Compile one tracefs fetch arg (arch-neutral form, see
 * uprobe_ptwrite_fetch) into a ptwrite descriptor entry.
 */
int arch_uprobe_ptwrite_fetch(struct uprobe_ptwrite_arg *a,
			      const struct uprobe_ptwrite_fetch *f)
{
	int i, idx = -1;

	switch (f->kind) {
	case UPROBE_PTW_FETCH_REG:
	case UPROBE_PTW_FETCH_MEMREG:
		for (i = 0; i < ARRAY_SIZE(ptwrite_reg_map); i++) {
			if (ptwrite_reg_map[i].off == f->reg) {
				idx = ptwrite_reg_map[i].idx;
				break;
			}
		}
		if (idx < 0)
			return -EINVAL;	/* not an x86-64 GPR */
		a->src = f->kind == UPROBE_PTW_FETCH_REG ?
			 UPROBE_PTW_SRC_REG : UPROBE_PTW_SRC_MEM;
		a->reg = idx;
		if (f->kind == UPROBE_PTW_FETCH_MEMREG)
			a->val = (u64)(s32)f->imm;
		break;
	case UPROBE_PTW_FETCH_STACKP:	/* $stack: SP value, never faults */
		a->src = UPROBE_PTW_SRC_REG;
		a->reg = 4; /* rsp */
		break;
	case UPROBE_PTW_FETCH_STACKN:	/* [rsp + imm] */
		a->src = UPROBE_PTW_SRC_MEM;
		a->reg = 4;	/* rsp */
		a->val = f->imm;
		break;
	case UPROBE_PTW_FETCH_IMM:	/* \IMM */
		a->src = UPROBE_PTW_SRC_IMM;
		a->val = f->imm;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Worst-case paced stub before instruction punning: a 9-byte header, one
 * lead fence, one fence after the header, one fence between each argument,
 * the largest memory form (10 bytes), and the return jump. Data adds one
 * header slot and one slot per immediate.
 */
static_assert((((9 + UPROBE_PTWRITE_SERIALIZE_LFENCES *
				  UPROBE_PTWRITE_LFENCE_SIZE +
			  UPROBE_PTWRITE_MAX_ARGS *
				  (10 + UPROBE_PTWRITE_SERIALIZE_LFENCES *
				   UPROBE_PTWRITE_LFENCE_SIZE) +
			  UPROBE_PTWRITE_COPY_SIZE + 5 + 7) & ~7) +
		       8 * (1 + UPROBE_PTWRITE_MAX_ARGS)) <=
		      UPROBE_PTWRITE_STUB_SIZE,
		      "worst-case ptwrite stub block exceeds UPROBE_PTWRITE_STUB_SIZE");

static bool ptwrite_has_room(const u8 *base, const u8 *p, size_t len)
{
	return p >= base && (size_t)(p - base) <=
		       sizeof(((struct uprobe_ptwrite_arch *)0)->stub) - len;
}

static bool pun_site_is_nop(const u8 *orig, bool allow_nop_run);
static bool ptwrite_site_is_multinop(const u8 *orig, bool allow_nop_run);
static int pun_classify_insn(struct insn *insn, u8 *disp_off, s32 *disp);
static int pun_decode_site(struct inode *inode, struct file *file,
			       loff_t offset, u8 *copy,
			       u8 *disp_off, s32 *disp, bool allow_nop_run);
#define PTW_NEED(_len) do { \
		if (!ptwrite_has_room(code, p, (_len))) \
			return -E2BIG; \
	} while (0)

int arch_uprobe_ptwrite_prepare(struct arch_uprobe *auprobe,
				struct inode *inode, struct file *file,
				loff_t offset,
				const struct uprobe_ptwrite_desc *desc)
{
	struct uprobe_ptwrite_arch *ptw = &auprobe->ptwrite;
	u8 *code = ptw->stub, *p = ptw->stub;
	u16 imm_off[UPROBE_PTWRITE_MAX_ARGS];
	unsigned int data_off;
	unsigned int hdr_off = 0;
	unsigned int imm_idx = 0, n_imm = 0;
	bool paced = false;
	u64 hdr;
	int i, ret;

	if (!desc || desc->nargs == 0)
		return -EINVAL;
	if (desc->nargs > UPROBE_PTWRITE_MAX_ARGS)
		return -E2BIG;
	if (desc->flags & ~(UPROBE_PTWRITE_FL_ALLOW_MEM |
			     UPROBE_PTWRITE_FL_NO_LEAD_PACE |
			     UPROBE_PTWRITE_FL_ALLOW_NOP_RUN))
		return -EINVAL;

	/* The generic registration path copied these bytes before this hook. */
	ptw->allow_nop_run =
		desc->flags & UPROBE_PTWRITE_FL_ALLOW_NOP_RUN;
	memcpy(ptw->orig, auprobe->insn, sizeof(ptw->orig));
	/*
	 * File mappings preserve page offsets, so an unaligned file offset
	 * cannot become an aligned runtime address. Reject it before the probe
	 * is exposed; install-time failures for a future mapping are otherwise
	 * not observable through the tracefs enable operation.
	 */
	if (ptwrite_site_is_multinop(ptw->orig, ptw->allow_nop_run) &&
	    !IS_ALIGNED(offset, sizeof(u64)))
		return -EINVAL;

	for (i = 0; i < desc->nargs; i++) {
		switch (desc->args[i].src) {
		case UPROBE_PTW_SRC_REG:
			if (desc->args[i].reg > 15)
				return -EINVAL;
			break;
		case UPROBE_PTW_SRC_IMM:
			if (n_imm >= ARRAY_SIZE(imm_off))
				return -E2BIG;
			n_imm++;
			break;
		case UPROBE_PTW_SRC_MEM:
			if (!(desc->flags & UPROBE_PTWRITE_FL_ALLOW_MEM))
				return -EINVAL;
			if (desc->args[i].reg > 15)
				return -EINVAL;
			if (desc->args[i].size != 4 &&
			    desc->args[i].size != 8)
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
	}

	paced = !(desc->flags & UPROBE_PTWRITE_FL_NO_LEAD_PACE);
	if (paced) {
		PTW_NEED(UPROBE_PTWRITE_SERIALIZE_LFENCES *
			 UPROBE_PTWRITE_LFENCE_SIZE);
		p += ptwrite_emit_lfences(p);
	}

	/* header word emission (disp32 patched below) */
	PTW_NEED(9);
	hdr_off = p - code;
	p += ptwrite_emit_riprel(p, 0);
	if (paced) {
		PTW_NEED(UPROBE_PTWRITE_SERIALIZE_LFENCES *
			 UPROBE_PTWRITE_LFENCE_SIZE);
		p += ptwrite_emit_lfences(p);
	}

	for (i = 0; i < desc->nargs; i++) {
		switch (desc->args[i].src) {
		case UPROBE_PTW_SRC_REG:
			PTW_NEED(5);
			p += ptwrite_emit_reg(p, desc->args[i].reg);
			break;
		case UPROBE_PTW_SRC_IMM:
			if (imm_idx >= ARRAY_SIZE(imm_off))
				return -E2BIG;
			PTW_NEED(9);
			imm_off[imm_idx++] = p - code;
			p += ptwrite_emit_riprel(p, 0);
			break;
		case UPROBE_PTW_SRC_MEM: {
			u8 reg = desc->args[i].reg;
			bool wide = desc->args[i].size == 8;
			unsigned int arg_len = (wide ? 9 : 8) +
				((reg & 7) == 4) + (!wide && (reg & 8));

			PTW_NEED(arg_len);
			*p++ = 0xf3;
			if (wide)
				*p++ = (reg & 8) ? 0x49 : 0x48; /* REX.W */
			else if (reg & 8)
				*p++ = 0x41; /* REX.B only (32-bit operand) */
			*p++ = 0x0f;
			*p++ = 0xae;
			*p++ = 0xa0 | (reg & 7); /* mod 10, reg /4, rm reg */
			if ((reg & 7) == 4) /* SIB escape: base rsp/esp/r12 */
				*p++ = 0x24;
			p += 4;
			break;
		}
		}
		if (paced && i + 1 < desc->nargs) {
			PTW_NEED(UPROBE_PTWRITE_SERIALIZE_LFENCES *
				 UPROBE_PTWRITE_LFENCE_SIZE);
			p += ptwrite_emit_lfences(p);
		}
	}

	/* the out-of-line original-instruction copy slot (patched per-mm) */
	PTW_NEED(UPROBE_PTWRITE_COPY_SIZE);
	if (p - code > U8_MAX)
		return -E2BIG;
	ptw->copy_off = p - code;
	p += UPROBE_PTWRITE_COPY_SIZE;

	/* final jmp back to probe+len; rel32 patched per-mm at install */
	PTW_NEED(5);
	*p++ = 0xe9;
	if (p - code > U8_MAX)
		return -E2BIG;
	ptw->jmp_off = p - code;
	p += 4;

	data_off = (p - code + 7) & ~7UL;
	if (data_off + 8 * (1 + n_imm) > sizeof(ptw->stub))
		return -E2BIG;

	/* data slots: header, then imm values in emission order */
	hdr = ((u64)desc->event_id << 48) | ((u64)desc->nargs << 40) |
	      UPROBE_PTW_HDR_MAGIC;
	*(u64 *)(code + data_off) = hdr;

	/* patch the header's disp32: hdr slot - end of header insn */
	*(s32 *)(code + hdr_off + 5) = (s32)(data_off - (hdr_off + 9));

	imm_idx = 0;
	for (i = 0; i < desc->nargs; i++) {
		if (desc->args[i].src != UPROBE_PTW_SRC_IMM)
			continue;
		*(s32 *)(code + imm_off[imm_idx] + 5) =
			(s32)((data_off + 8 * (1 + imm_idx)) - (imm_off[imm_idx] + 9));
		*(u64 *)(code + data_off + 8 * (1 + imm_idx)) = desc->args[i].val;
		imm_idx++;
	}

	ptw->stub_len = data_off + 8 * (1 + n_imm);
	ptw->ndata = 1 + n_imm;


	ret = pun_decode_site(inode, file, offset, code + ptw->copy_off,
				  &ptw->disp_off, &ptw->disp,
				  ptw->allow_nop_run);
	if (ret < 0)
		return ret;
	ptw->len = ret;
	memset(code + ptw->copy_off + ptw->len, 0x90,
	       UPROBE_PTWRITE_COPY_SIZE - ptw->len);
	return 0;
}
#undef PTW_NEED

/*
 * Find a free PAGE_SIZE area in @mm within +/-2GB of the probe (so the jmp
 * rel32 at the probe can reach the stub). Caller holds mmap_write_lock(mm).
 * Returns an address or a negative errno encoded as unsigned long.
 */
static unsigned long find_ptwrite_page_area(struct mm_struct *mm,
					    unsigned long vaddr)
{
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *vma;
	unsigned long low, high, prev, call_end;
	const unsigned long call_range = (unsigned long)INT_MAX + 1;

	mmap_assert_write_locked(mm);
	if (check_add_overflow(vaddr, 5UL, &call_end))
		return -ENOMEM;
	if (call_end < call_range)
		low = PAGE_SIZE;
	else
		low = call_end - call_range;
	if (low < PAGE_SIZE)
		low = PAGE_SIZE;
	if (low > ULONG_MAX - (PAGE_SIZE - 1))
		return -ENOMEM;
	low = PAGE_ALIGN(low);

	if (check_add_overflow(call_end, (unsigned long)INT_MAX, &high))
		high = ULONG_MAX;
	high = min(high, TASK_SIZE_MAX);
	if (low >= high)
		return -ENOMEM;

	prev = low;
	for_each_vma(vmi, vma) {
		if (vma->vm_start >= high)
			break;
		if (vma->vm_end <= prev)
			continue;
		if (vma->vm_start > prev && vma->vm_start - prev >= PAGE_SIZE)
			return prev;
		if (vma->vm_end > prev) {
			if (vma->vm_end > ULONG_MAX - (PAGE_SIZE - 1))
				return -ENOMEM;
			prev = PAGE_ALIGN(vma->vm_end);
			if (prev >= high)
				return -ENOMEM;
		}
	}
	if (prev < high && high - prev >= PAGE_SIZE)
		return prev;
	return -ENOMEM;
}

static struct uprobe_ptwrite_page *
create_uprobe_ptwrite_page_at(struct mm_struct *mm, unsigned long area)
{
	struct uprobe_ptwrite_page *ptw;
	struct vm_area_struct *vma;

	mmap_assert_write_locked(mm);

	ptw = kzalloc_obj(*ptw, GFP_KERNEL);
	if (!ptw)
		return NULL;

	ptw->page = alloc_page(GFP_HIGHUSER | __GFP_ZERO);
	if (!ptw->page) {
		kfree(ptw);
		return NULL;
	}
	ptw->vaddr = area;

	vma = install_uprobe_ptwrite_vma(mm, area);
	if (IS_ERR(vma)) {
		__free_page(ptw->page);
		kfree(ptw);
		return NULL;
	}
	return ptw;
}

static struct uprobe_ptwrite_page *
create_uprobe_ptwrite_page(struct mm_struct *mm, unsigned long vaddr)
{
	unsigned long area = find_ptwrite_page_area(mm, vaddr);

	if (IS_ERR_VALUE(area) || security_mmap_addr(area))
		return NULL;
	return create_uprobe_ptwrite_page_at(mm, area);
}

static struct uprobe_ptwrite_page *
get_uprobe_ptwrite_page(struct mm_struct *mm, unsigned long vaddr,
			unsigned int len)
{
	struct uprobes_state *state = &mm->uprobes_state;
	struct uprobe_ptwrite_page *ptw;
	mmap_assert_write_locked(mm);

	/* a block larger than a page can never be placed */
	if (len > PAGE_SIZE)
		return NULL;

	/* Both helpers use the signed 32-bit range of the generated jump. */
	hlist_for_each_entry(ptw, &state->head_ptwrite, node)
		if (is_reachable_by_call(ptw->vaddr + ptw->cursor, vaddr) &&
		    ptw->cursor + len <= PAGE_SIZE)
			return ptw;

	/* no reachable page with room: allocate a fresh one (cursor 0) */
	ptw = create_uprobe_ptwrite_page(mm, vaddr);
	if (!ptw)
		return NULL;
	/* Order page initialization before publishing the page on the RCU list. */
	smp_wmb();

	hlist_add_head_rcu(&ptw->node, &state->head_ptwrite);
	return ptw;
}

/*
 * A run of short NOPs is accepted only when requested. It is patched with
 * an aligned eight-byte read-modify-write, preserving the following bytes;
 * code is not expected to change concurrently.
 */
static bool ptwrite_is_nop_run(const u8 *orig)
{
	return !memchr_inv(orig, 0x90, 5);
}

static bool pun_site_is_nop(const u8 *orig, bool allow_nop_run)
{
	struct insn insn;
	int ret;

	ret = insn_decode(&insn, orig, 5, INSN_MODE_64);
	if (ret < 0)
		return false;
	if (insn.length == 5 && insn_is_nop(&insn))
		return true;
	if (!allow_nop_run)
		return false;
	return ptwrite_is_nop_run(orig);
}

/* Identify the explicitly opted-in run of five one-byte NOPs. */
static bool ptwrite_site_is_multinop(const u8 *orig, bool allow_nop_run)
{
	return allow_nop_run && ptwrite_is_nop_run(orig);
}

/*
 * Classify the site's single instruction for out-of-line execution.
 * Returns the length, or a negative errno when it cannot run safely out of
 * line.
 */
static int pun_classify_insn(struct insn *insn, u8 *disp_off, s32 *disp)
{
	u8 op = insn->opcode.bytes[0];

	switch (op) {
	case 0xcc:	/* int3 */
	case 0xcd:	/* int imm8 */
	case 0xce:	/* into */
	case 0xcf:	/* iret */
	case 0xf1:	/* int1 */
	case 0xea:	/* jmp far */
	case 0x9a:	/* call far */
	/* Could be handled with special case code. */
	case 0xe8:	/* call rel32 */
	case 0xe0:	/* loopne rel8: cannot run out of line */
	case 0xe1:	/* loope rel8 */
	case 0xe2:	/* loop rel8 */
	case 0xe3:	/* jecxz/jrcxz */
	/* These two could be handled if the offsets fit */
	case 0xe9:	/* jmp rel32 */
	case 0xeb:	/* jmp rel8 */
	case 0x70 ... 0x7f:	/* jcc rel8 */
		return -EOPNOTSUPP;
	}
	/* XBEGIN's rel32 abort target is IP-relative, not RIP-relative. */
	if (op == 0xc7 && insn->modrm.nbytes &&
	    X86_MODRM_MOD(insn->modrm.value) == 3 &&
	    X86_MODRM_REG(insn->modrm.value) == 7 &&
	    X86_MODRM_RM(insn->modrm.value) == 0)
		return -EOPNOTSUPP;
	if (op == 0x0f) {
		switch (insn->opcode.bytes[1]) {
		case 0x05:	/* syscall */
		case 0x34:	/* sysenter */
		case 0x35:	/* sysexit */
			return -EOPNOTSUPP;
		}
		/* jcc rel32: could be handled if offsets fit */
		if (insn->opcode.bytes[1] >= 0x80 &&
		    insn->opcode.bytes[1] <= 0x8f)
			return -EOPNOTSUPP;
		/* Allow endbranch because this is incompatible with CET anyways */
	}
	if (op == 0xff) {
		u8 reg = X86_MODRM_REG(insn->modrm.value);

		/* call/lcall/jmp-far indirect */
		if (reg == 2 || reg == 3 || reg == 5)
			return -EOPNOTSUPP;
	}

	if (insn_rip_relative(insn)) {
		*disp_off = insn_offset_displacement(insn);
		insn_get_displacement(insn);
		*disp = insn->displacement.value;
	}
	return insn->length;
}

/*
 * Read the site's instruction bytes from the file and classify them.
 * The bytes are identical in every mm, so the copy is mm-independent.
 */
static int pun_decode_site(struct inode *inode, struct file *file,
			       loff_t offset, u8 *copy,
			       u8 *disp_off, s32 *disp, bool allow_nop_run)
{
	u8 buf[MAX_UINSN_BYTES] = {};
	struct insn insn;
	int ret;

	ret = uprobe_copy_from_file(inode, file, offset, buf,
				    MAX_UINSN_BYTES);
	if (ret < 0)
		return ret;
	if (!ret)
		return -EIO;

	if (pun_site_is_nop(buf, allow_nop_run))
		return 0;

	/* Check single instruction */
	if (insn_decode(&insn, buf, MAX_UINSN_BYTES, INSN_MODE_64))
		return -EINVAL;
	if (insn.length < 1 || insn.length > MAX_UINSN_BYTES)
		return -EINVAL;

	/* the original bytes verbatim; classify only validates them */
	memcpy(copy, buf, insn.length);
	return pun_classify_insn(&insn, disp_off, disp);
}

static bool ptwrite_rel32(unsigned long from, unsigned long to, s32 *rel)
{
	s64 delta = (s64)to - (s64)from;

	if (delta < INT_MIN || delta > INT_MAX)
		return false;
	*rel = (s32)delta;
	return true;
}

static bool ptwrite_is_installed(struct mm_struct *mm, unsigned long vaddr,
				 const u8 *insn5)
{
	struct __packed __arch_relative_insn {
		u8 op;
		s32 raddr;
	} *jmp = (struct __arch_relative_insn *)insn5;
	s64 target;

	if (jmp->op != 0xe9)
		return false;
	target = (s64)vaddr + 5 + (s64)jmp->raddr;
	if (target < PAGE_SIZE || target >= TASK_SIZE_MAX)
		return false;
	return __in_uprobe_ptwrite(mm, (unsigned long)target);
}

/*
 * Install a JMP rel32 at the probe site using the 3-phase SMP-safe poke.
 * On failure, restores the original instruction so the site is never
 * left half-poked.
 */
static int ptwrite_text_poke(struct arch_uprobe *auprobe,
			     struct vm_area_struct *vma, unsigned long vaddr,
			     unsigned long stub_addr)
{
	u8 jmp5[5] = { 0xe9, 0, 0, 0, 0 };
	bool first_phase_done;
	s32 rel;
	int err;

	if (!ptwrite_rel32(vaddr + 5, stub_addr, &rel))
		return -ERANGE;
	memcpy(jmp5 + 1, &rel, 4);

	err = text_poke_5byte(auprobe, vma, vaddr, jmp5,
			      auprobe->ptwrite.orig[0], false, true, true,
			      false, &first_phase_done);
	if (err && first_phase_done) {
		int restore_err;

		/* Restore only after INT3 was successfully installed. */
		restore_err = text_poke_5byte(auprobe, vma, vaddr,
				auprobe->ptwrite.orig, UPROBE_SWBP_INSN,
				true, true, true, false, NULL);
		if (restore_err)
			return restore_err;
	}
	return err;
}

/*
 * Replace an aligned five-byte NOP run with a JMP in one eight-byte store.
 * The trailing three bytes are read from the existing text. We assume
 * nobody else is changing it. This is covered by the Intel/AMD "aligned store"
 * cross modifying guarantee.
 */
static int ptwrite_multinop_text_poke(struct arch_uprobe *auprobe,
				      struct vm_area_struct *vma,
				      unsigned long vaddr,
				      unsigned long stub_addr)
{
	struct mm_struct *mm = vma->vm_mm;
	struct write_opcode_ctx ctx = {
		.base = vaddr,
		.expect = EXPECT_BYTE,
		.expect_byte = 0x90,
	};
	u8 patch[sizeof(u64)];
	s32 rel;
	int err;

	if (!IS_ALIGNED(vaddr, sizeof(u64)))
		return -EINVAL;
	if (!ptwrite_rel32(vaddr + 5, stub_addr, &rel))
		return -ERANGE;
	err = copy_from_vaddr(mm, vaddr, patch, sizeof(patch));
	if (err)
		return err;
	patch[0] = 0xe9;
	memcpy(&patch[1], &rel, sizeof(rel));
	err = uprobe_write(auprobe, vma, vaddr, patch, sizeof(patch),
			   verify_insn, true, false, &ctx);
	if (!err)
		smp_text_poke_sync_each_cpu();
	return err;
}
static int pun_text_poke(struct arch_uprobe *auprobe,
				 struct vm_area_struct *vma,
				 unsigned long vaddr, u8 e9,
				 struct write_opcode_ctx *ctx)
{
	int err;

	err = uprobe_write(auprobe, vma, vaddr, &e9, 1, verify_insn,
			   true, false, ctx);
	if (err)
		return err;
	smp_text_poke_sync_each_cpu();
	return 0;
}

static int pun_install(struct arch_uprobe *auprobe,
			       struct vm_area_struct *vma, unsigned long vaddr,
			       const u8 *orig)
{
	struct mm_struct *mm = vma->vm_mm;
	struct uprobe_ptwrite_page *ptw;
	struct uprobe_ptwrite_arch *ptw_a = &auprobe->ptwrite;
	struct uprobes_state *state = &mm->uprobes_state;
	struct write_opcode_ctx ctx = {
		.base = vaddr,
		.expect = EXPECT_BYTE,
		.expect_byte = orig[0],
	};
	unsigned long t, page_base, block_off, stub_addr;
	s64 site_delta, target;
	s32 jump_rel, disp32, orig_rel;
	bool found = false;
	u8 *kaddr;
	int b, ret;

	mmap_assert_write_locked(mm);
	memcpy(&orig_rel, orig + 1, sizeof(orig_rel));
	target = (s64)vaddr + 5 + (s64)orig_rel;
	if (target < PAGE_SIZE || target >= TASK_SIZE_MAX)
		return -EADDRNOTAVAIL;
	t = (unsigned long)target;
	page_base = t & PAGE_MASK;
	ret = security_mmap_addr(page_base);
	if (ret)
		return ret;
	block_off = t & (PAGE_SIZE - 1);
	if (block_off + ptw_a->stub_len > PAGE_SIZE)
		return -ENOSPC;

	/* Reuse an existing ptwrite page at the target, else map a new one. */
	hlist_for_each_entry(ptw, &state->head_ptwrite, node) {
		if (ptw->vaddr == page_base) {
			found = true;
			break;
		}
	}
	if (!found) {
		if (vma_lookup(mm, page_base))
			return -EADDRNOTAVAIL;
		ptw = create_uprobe_ptwrite_page_at(mm, page_base);
		if (!ptw)
			return -ENOMEM;
		/* Publish initialized page fields before fault readers find it. */
		smp_wmb();
		hlist_add_head_rcu(&ptw->node, &state->head_ptwrite);
	}

	site_delta = (s64)vaddr - (s64)ptw->vaddr;
	if (site_delta < INT_MIN || site_delta > INT_MAX)
		return -ERANGE;

	for (b = 0; b < ptw->nblocks; b++) {
		u16 old_off = ptw->index[b].off;
		u16 old_len = ptw->index[b].len;

		if (block_off + ptw_a->stub_len <= old_off ||
		    old_off + old_len <= block_off)
			continue;
		if (old_off == block_off && ptw->index[b].pun &&
		    old_len == ptw_a->stub_len &&
		    ptw->index[b].site_off == (s32)site_delta &&
		    ptw->index[b].site_len == ptw_a->len &&
		    !memcmp(ptw->index[b].site_insn, ptw_a->orig,
			    ptw_a->len))
			return pun_text_poke(auprobe, vma, vaddr, 0xe9, &ctx);
		return -EADDRNOTAVAIL;
	}
	if (ptw->nblocks >= ARRAY_SIZE(ptw->index))
		return -ENOMEM;

	stub_addr = ptw->vaddr + block_off;
	if (!ptwrite_rel32(stub_addr + ptw_a->jmp_off + 4,
			   vaddr + (ptw_a->len ? ptw_a->len : 5), &jump_rel))
		return -ERANGE;
	if (ptw_a->len && ptw_a->disp_off) {
		s64 d = (s64)ptw_a->disp + (s64)vaddr -
			(s64)(stub_addr + ptw_a->copy_off);

		if (d < INT_MIN || d > INT_MAX)
			return -ERANGE;
		disp32 = (s32)d;
	}

	ptw->index[ptw->nblocks].off = block_off;
	ptw->index[ptw->nblocks].len = ptw_a->stub_len;
	ptw->index[ptw->nblocks].pun = 1;
	ptw->index[ptw->nblocks].orig0 = orig[0];
	ptw->index[ptw->nblocks].site_len = ptw_a->len;
	ptw->index[ptw->nblocks].site_off = (s32)site_delta;
	memcpy(ptw->index[ptw->nblocks].site_insn, ptw_a->orig, ptw_a->len);

	kaddr = kmap_local_page(ptw->page);
	memcpy(kaddr + block_off, ptw_a->stub, ptw_a->stub_len);
	memcpy(kaddr + block_off + ptw_a->jmp_off, &jump_rel, sizeof(jump_rel));
	if (ptw_a->len && ptw_a->disp_off)
		memcpy(kaddr + block_off + ptw_a->copy_off + ptw_a->disp_off,
		       &disp32, sizeof(disp32));
	kunmap_local(kaddr);
	/* Publish initialized metadata before exposing the probe jump. */
	smp_store_release(&ptw->nblocks, ptw->nblocks + 1);

	ret = pun_text_poke(auprobe, vma, vaddr, 0xe9, &ctx);
	if (ret) {
		/* Publish rollback before readers observe the reduced block count. */
		smp_store_release(&ptw->nblocks, ptw->nblocks - 1);
		return ret;
	}

	if (block_off + ptw_a->stub_len > ptw->cursor)
		ptw->cursor = block_off + ptw_a->stub_len;
	return 0;
}

int arch_uprobe_install_ptwrite(struct arch_uprobe *auprobe,
		struct vm_area_struct *vma, unsigned long vaddr)
{
	struct mm_struct *mm = vma->vm_mm;
	struct uprobes_state *state = &mm->uprobes_state;
	struct uprobe_ptwrite_page *ptw;
	struct uprobe_ptwrite_arch *ptw_a = &auprobe->ptwrite;
	unsigned long block_off, stub_addr;
	u8 *kaddr, orig[5];
	s64 site_delta;
	s32 rel;
	int ret;
	int b;

	if (!is_64bit_mm(mm))
		return -EOPNOTSUPP;
	/* A three-phase poke and this single-page read both require one page. */
	if (PAGE_SIZE - (vaddr & ~PAGE_MASK) < 5)
		return -EINVAL;
	mmap_assert_write_locked(mm);

	ret = copy_from_vaddr(mm, vaddr, orig, sizeof(orig));
	if (ret)
		return ret;
	if (ptwrite_site_is_multinop(orig, ptw_a->allow_nop_run) &&
	    !IS_ALIGNED(vaddr, sizeof(u64)))
		return -EINVAL;
	if (ptwrite_is_installed(mm, vaddr, orig))
		return 0;

	if (!pun_site_is_nop(orig, ptw_a->allow_nop_run))
		return pun_install(auprobe, vma, vaddr, orig);

	hlist_for_each_entry(ptw, &state->head_ptwrite, node) {
		site_delta = (s64)vaddr - (s64)ptw->vaddr;
		if (site_delta < INT_MIN || site_delta > INT_MAX)
			continue;
		/* Acquire the published count before reading block metadata. */
		for (b = 0; b < smp_load_acquire(&ptw->nblocks); b++)
			if (!ptw->index[b].pun &&
			    ptw->index[b].site_off == (s32)site_delta &&
			    ptw->index[b].site_len == sizeof(orig) &&
			    !memcmp(ptw->index[b].site_insn, orig, sizeof(orig)))
				break;
		/* Recheck the published count with acquire ordering. */
		if (b >= smp_load_acquire(&ptw->nblocks))
			continue;
		if (!__in_uprobe_ptwrite(mm, ptw->vaddr))
			continue;
		if (ptwrite_site_is_multinop(orig, ptw_a->allow_nop_run))
			ret = ptwrite_multinop_text_poke(auprobe, vma, vaddr,
							ptw->vaddr + ptw->index[b].off);
		else
			ret = ptwrite_text_poke(auprobe, vma, vaddr,
						ptw->vaddr + ptw->index[b].off);
		return ret;
	}
	ptw = get_uprobe_ptwrite_page(mm, vaddr, ptw_a->stub_len);
	if (!ptw)
		return -ENOMEM;

	block_off = ptw->cursor;
	if (block_off > PAGE_SIZE ||
	    ptw_a->stub_len > PAGE_SIZE - block_off)
		return -ENOMEM;
	stub_addr = ptw->vaddr + block_off;
	if (!ptwrite_rel32(stub_addr + ptw_a->jmp_off + 4,
			   vaddr + 5, &rel))
		return -ERANGE;
	site_delta = (s64)vaddr - (s64)ptw->vaddr;
	if (site_delta < INT_MIN || site_delta > INT_MAX)
		return -ERANGE;

	ptw->index[ptw->nblocks].off = block_off;
	ptw->index[ptw->nblocks].len = ptw_a->stub_len;
	ptw->index[ptw->nblocks].pun = 0;
	ptw->index[ptw->nblocks].orig0 = orig[0];
	ptw->index[ptw->nblocks].site_len = sizeof(orig);
	ptw->index[ptw->nblocks].site_off = (s32)site_delta;
	memcpy(ptw->index[ptw->nblocks].site_insn, orig, sizeof(orig));
	/* Publish initialized metadata before exposing the probe jump. */
	smp_store_release(&ptw->nblocks, ptw->nblocks + 1);

	kaddr = kmap_local_page(ptw->page);
	memcpy(kaddr + block_off, ptw_a->stub, ptw_a->stub_len);
	/* ptwrite_mapping rejects mremap, so this per-mm rel32 remains valid. */
	memcpy(kaddr + block_off + ptw_a->jmp_off, &rel, sizeof(rel));
	kunmap_local(kaddr);

	if (ptwrite_site_is_multinop(orig, ptw_a->allow_nop_run))
		ret = ptwrite_multinop_text_poke(auprobe, vma, vaddr, stub_addr);
	else
		ret = ptwrite_text_poke(auprobe, vma, vaddr, stub_addr);
	if (ret) {
		/* Publish rollback before readers use the reduced block count. */
		smp_store_release(&ptw->nblocks, ptw->nblocks - 1);
		return ret;
	}
	ptw->cursor = block_off + ptw_a->stub_len;
	return 0;
}

int arch_uprobe_uninstall_ptwrite(struct arch_uprobe *auprobe,
		struct vm_area_struct *vma, unsigned long vaddr)
{
	struct mm_struct *mm = vma->vm_mm;
	struct uprobe_ptwrite_arch *ptw_a = &auprobe->ptwrite;
	struct uprobes_state *state = &mm->uprobes_state;
	u8 cur[5];
	struct uprobe_ptwrite_page *ptw, *found_page = NULL;
	s32 rel;
	s64 target, site_delta;
	unsigned long page_base, boff;
	int b, ret;
	struct write_opcode_ctx ctx = {
		.base = vaddr,
		.expect = EXPECT_BYTE,
		.expect_byte = 0xe9,
	};

	mmap_assert_write_locked(mm);

	ret = copy_from_vaddr(mm, vaddr, cur, sizeof(cur));
	if (ret)
		return ret;
	if (!ptwrite_is_installed(mm, vaddr, cur))
		return 0;

	memcpy(&rel, cur + 1, sizeof(rel));
	target = (s64)vaddr + 5 + (s64)rel;
	if (target < PAGE_SIZE || target >= TASK_SIZE_MAX)
		return text_poke_5byte(auprobe, vma, vaddr, ptw_a->orig,
				0xe9, false, false, false, false, NULL);
	page_base = (unsigned long)target & PAGE_MASK;
	boff = (unsigned long)target & (PAGE_SIZE - 1);
	hlist_for_each_entry(ptw, &state->head_ptwrite, node)
		if (ptw->vaddr == page_base) {
			found_page = ptw;
			break;
		}
	if (!found_page)
		return 0;
	/* Acquire the published count before reading block metadata. */
	for (b = 0; b < smp_load_acquire(&found_page->nblocks); b++)
		if (found_page->index[b].off == boff)
			break;
	if (b >= smp_load_acquire(&found_page->nblocks))
		return 0;
	site_delta = (s64)vaddr - (s64)found_page->vaddr;
	if (site_delta < INT_MIN || site_delta > INT_MAX)
		return 0;
	if (found_page->index[b].site_off != (s32)site_delta ||
	    found_page->index[b].site_len !=
	    (found_page->index[b].pun ? ptw_a->len : sizeof(cur)) ||
	    memcmp(found_page->index[b].site_insn, ptw_a->orig,
		   found_page->index[b].site_len))
		return 0;
	if (found_page->index[b].pun) {
		u8 orig0 = found_page->index[b].orig0;

		ret = uprobe_write(auprobe, vma, vaddr, &orig0, 1,
				   verify_insn, false, false, &ctx);
		if (ret)
			return ret;
		smp_text_poke_sync_each_cpu();
		return 0;
	}
	return text_poke_5byte(auprobe, vma, vaddr, ptw_a->orig,
			0xe9, false, false, false, false, NULL);
}

static bool __is_optimized(struct mm_struct *mm, uprobe_opcode_t *insn, unsigned long vaddr)
{
	struct __packed __arch_relative_insn {
		u8 op;
		s32 raddr;
	} *call = (struct __arch_relative_insn *)(insn + LEA_INSN_SIZE);

	if (!is_opt_insns(insn))
		return false;
	return __in_uprobe_trampoline(mm, vaddr + OPT_INSN_SIZE + call->raddr);
}

static int is_optimized(struct mm_struct *mm, unsigned long vaddr)
{
	uprobe_opcode_t insn[OPT_INSN_SIZE];
	int err;

	err = copy_from_vaddr(mm, vaddr, &insn, OPT_INSN_SIZE);
	if (err)
		return err;
	return __is_optimized(mm, (uprobe_opcode_t *)&insn, vaddr);
}

static bool should_optimize(struct arch_uprobe *auprobe)
{
	return !test_bit(ARCH_UPROBE_FLAG_OPTIMIZE_FAIL, &auprobe->flags) &&
		test_bit(ARCH_UPROBE_FLAG_CAN_OPTIMIZE, &auprobe->flags);
}

int set_swbp(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
	     unsigned long vaddr)
{
	if (should_optimize(auprobe)) {
		/*
		 * We could race with another thread that already optimized the probe,
		 * so let's not overwrite it with int3 again in this case.
		 */
		int ret = is_optimized(vma->vm_mm, vaddr);
		if (ret < 0)
			return ret;
		if (ret)
			return 0;
	}
	return uprobe_write_opcode(auprobe, vma, vaddr, UPROBE_SWBP_INSN,
				   true /* is_register */);
}

int set_orig_insn(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
		  unsigned long vaddr)
{
	if (test_bit(ARCH_UPROBE_FLAG_CAN_OPTIMIZE, &auprobe->flags)) {
		int ret = is_optimized(vma->vm_mm, vaddr);
		if (ret < 0)
			return ret;
		if (ret) {
			ret = swbp_unoptimize(auprobe, vma, vaddr);
			WARN_ON_ONCE(ret);
			return ret;
		}
	}
	return uprobe_write_opcode(auprobe, vma, vaddr, *(uprobe_opcode_t *)&auprobe->insn,
				   false /* is_register */);
}

static int __arch_uprobe_optimize(struct arch_uprobe *auprobe, struct mm_struct *mm,
				  unsigned long vaddr)
{
	struct pt_regs *regs = task_pt_regs(current);
	struct vm_area_struct *vma, *tramp;
	bool new_mapping;
	int ret;

	if (!user_64bit_mode(regs))
		return -EINVAL;
	vma = find_vma(mm, vaddr);
	if (!vma)
		return -EINVAL;
	tramp = get_uprobe_trampoline(mm, vaddr, &new_mapping);
	if (IS_ERR(tramp))
		return PTR_ERR(tramp);
	ret = swbp_optimize(auprobe, vma, vaddr, tramp->vm_start);
	if (WARN_ON_ONCE(ret) && new_mapping)
		WARN_ON_ONCE(do_munmap(mm, tramp->vm_start, PAGE_SIZE, NULL));
	return ret;
}

void arch_uprobe_optimize(struct arch_uprobe *auprobe, unsigned long vaddr)
{
	struct mm_struct *mm = current->mm;
	uprobe_opcode_t insn[OPT_INSN_SIZE];

	if (!should_optimize(auprobe))
		return;

	mmap_write_lock(mm);

	/*
	 * Check if some other thread already optimized the uprobe for us,
	 * if it's the case just go away silently.
	 */
	if (copy_from_vaddr(mm, vaddr, &insn, OPT_INSN_SIZE))
		goto unlock;
	if (!is_swbp_insn((uprobe_opcode_t*) &insn))
		goto unlock;

	/*
	 * If we fail to optimize the uprobe we set the fail bit so the
	 * above should_optimize will fail from now on.
	 */
	if (__arch_uprobe_optimize(auprobe, mm, vaddr))
		set_bit(ARCH_UPROBE_FLAG_OPTIMIZE_FAIL, &auprobe->flags);

unlock:
	mmap_write_unlock(mm);
}

static bool is_optimizable_nop10(struct insn *insn)
{
	static const u8 nop10_prefix[] = {
		0x66, 0x2e, 0x0f, 0x1f, 0x84
	};

	/*
	 * Restrict this to the 10-byte NOP form whose last 5 bytes are
	 * SIB/displacement operands. Unoptimization keeps the call opcode and
	 * displacement in those bytes, so other NOP encodings are not safe.
	 */
	return insn->length == OPT_INSN_SIZE &&
	       insn_is_nop(insn) &&
	       !memcmp(insn->kaddr, nop10_prefix, ARRAY_SIZE(nop10_prefix));
}

static bool can_optimize(struct insn *insn, unsigned long vaddr)
{
	if (!insn->x86_64)
		return false;

	if (!is_optimizable_nop10(insn))
		return false;

	/* We can't do cross page atomic writes yet. */
	return PAGE_SIZE - (vaddr & ~PAGE_MASK) >= OPT_INSN_SIZE;
}
#else /* 32-bit: */
/*
 * No RIP-relative addressing on 32-bit
 */
static void riprel_analyze(struct arch_uprobe *auprobe, struct insn *insn)
{
}
static void riprel_pre_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
}
static void riprel_post_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
}
static bool can_optimize(struct insn *insn, unsigned long vaddr)
{
	return false;
}
#endif /* CONFIG_X86_64 */

struct uprobe_xol_ops {
	bool	(*emulate)(struct arch_uprobe *, struct pt_regs *);
	int	(*pre_xol)(struct arch_uprobe *, struct pt_regs *);
	int	(*post_xol)(struct arch_uprobe *, struct pt_regs *);
	void	(*abort)(struct arch_uprobe *, struct pt_regs *);
};

static inline int sizeof_long(struct pt_regs *regs)
{
	/*
	 * Check registers for mode as in_xxx_syscall() does not apply here.
	 */
	return user_64bit_mode(regs) ? 8 : 4;
}

static int default_pre_xol_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	riprel_pre_xol(auprobe, regs);
	return 0;
}

static int emulate_push_stack(struct pt_regs *regs, unsigned long val)
{
	unsigned long new_sp = regs->sp - sizeof_long(regs);

	if (copy_to_user((void __user *)new_sp, &val, sizeof_long(regs)))
		return -EFAULT;

	regs->sp = new_sp;
	return 0;
}

/*
 * We have to fix things up as follows:
 *
 * Typically, the new ip is relative to the copied instruction.  We need
 * to make it relative to the original instruction (FIX_IP).  Exceptions
 * are return instructions and absolute or indirect jump or call instructions.
 *
 * If the single-stepped instruction was a call, the return address that
 * is atop the stack is the address following the copied instruction.  We
 * need to make it the address following the original instruction (FIX_CALL).
 *
 * If the original instruction was a rip-relative instruction such as
 * "movl %edx,0xnnnn(%rip)", we have instead executed an equivalent
 * instruction using a scratch register -- e.g., "movl %edx,0xnnnn(%rsi)".
 * We need to restore the contents of the scratch register
 * (FIX_RIP_reg).
 */
static int default_post_xol_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	riprel_post_xol(auprobe, regs);
	if (auprobe->defparam.fixups & UPROBE_FIX_IP) {
		long correction = utask->vaddr - utask->xol_vaddr;
		regs->ip += correction;
	} else if (auprobe->defparam.fixups & UPROBE_FIX_CALL) {
		unsigned long retaddr = utask->vaddr + auprobe->defparam.ilen;
		int err;

		regs->sp += sizeof_long(regs); /* Pop incorrect return address */
		if (emulate_push_stack(regs, retaddr))
			return -ERESTART;
		err = shstk_update_last_frame(retaddr);
		if (err)
			return err;
	}
	/* popf; tell the caller to not touch TF */
	if (auprobe->defparam.fixups & UPROBE_FIX_SETF)
		utask->autask.saved_tf = true;

	return 0;
}

static void default_abort_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	riprel_post_xol(auprobe, regs);
}

static const struct uprobe_xol_ops default_xol_ops = {
	.pre_xol  = default_pre_xol_op,
	.post_xol = default_post_xol_op,
	.abort	  = default_abort_op,
};

static bool branch_is_call(struct arch_uprobe *auprobe)
{
	return auprobe->branch.opc1 == 0xe8;
}

#define CASE_COND					\
	COND(70, 71, XF(OF))				\
	COND(72, 73, XF(CF))				\
	COND(74, 75, XF(ZF))				\
	COND(78, 79, XF(SF))				\
	COND(7a, 7b, XF(PF))				\
	COND(76, 77, XF(CF) || XF(ZF))			\
	COND(7c, 7d, XF(SF) != XF(OF))			\
	COND(7e, 7f, XF(ZF) || XF(SF) != XF(OF))

#define COND(op_y, op_n, expr)				\
	case 0x ## op_y: DO((expr) != 0)		\
	case 0x ## op_n: DO((expr) == 0)

#define XF(xf)	(!!(flags & X86_EFLAGS_ ## xf))

static bool is_cond_jmp_opcode(u8 opcode)
{
	switch (opcode) {
	#define DO(expr)	\
		return true;
	CASE_COND
	#undef	DO

	default:
		return false;
	}
}

static bool check_jmp_cond(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	unsigned long flags = regs->flags;

	switch (auprobe->branch.opc1) {
	#define DO(expr)	\
		return expr;
	CASE_COND
	#undef	DO

	default:	/* not a conditional jmp */
		return true;
	}
}

#undef	XF
#undef	COND
#undef	CASE_COND

static bool branch_emulate_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	unsigned long new_ip = regs->ip += auprobe->branch.ilen;
	unsigned long offs = (long)auprobe->branch.offs;

	if (branch_is_call(auprobe)) {
		/*
		 * If it fails we execute this (mangled, see the comment in
		 * branch_clear_offset) insn out-of-line. In the likely case
		 * this should trigger the trap, and the probed application
		 * should die or restart the same insn after it handles the
		 * signal, arch_uprobe_post_xol() won't be even called.
		 *
		 * But there is corner case, see the comment in ->post_xol().
		 */
		if (emulate_push_stack(regs, new_ip))
			return false;
		if (shstk_push(new_ip) == -EFAULT) {
			regs->sp += sizeof_long(regs);
			return false;
		}
	} else if (!check_jmp_cond(auprobe, regs)) {
		offs = 0;
	}

	regs->ip = new_ip + offs;
	return true;
}

static bool push_emulate_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	unsigned long *src_ptr = (void *)regs + auprobe->push.reg_offset;

	if (emulate_push_stack(regs, *src_ptr))
		return false;
	regs->ip += auprobe->push.ilen;
	return true;
}

static int branch_post_xol_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	BUG_ON(!branch_is_call(auprobe));
	/*
	 * We can only get here if branch_emulate_op() failed to push the ret
	 * address _and_ another thread expanded our stack before the (mangled)
	 * "call" insn was executed out-of-line. Just restore ->sp and restart.
	 * We could also restore ->ip and try to call branch_emulate_op() again.
	 */
	regs->sp += sizeof_long(regs);
	return -ERESTART;
}

static void branch_clear_offset(struct arch_uprobe *auprobe, struct insn *insn)
{
	/*
	 * Turn this insn into "call 1f; 1:", this is what we will execute
	 * out-of-line if ->emulate() fails. We only need this to generate
	 * a trap, so that the probed task receives the correct signal with
	 * the properly filled siginfo.
	 *
	 * But see the comment in ->post_xol(), in the unlikely case it can
	 * succeed. So we need to ensure that the new ->ip can not fall into
	 * the non-canonical area and trigger #GP.
	 *
	 * We could turn it into (say) "pushf", but then we would need to
	 * divorce ->insn[] and ->ixol[]. We need to preserve the 1st byte
	 * of ->insn[] for set_orig_insn().
	 */
	memset(auprobe->insn + insn_offset_immediate(insn),
		0, insn->immediate.nbytes);
}

static const struct uprobe_xol_ops branch_xol_ops = {
	.emulate  = branch_emulate_op,
	.post_xol = branch_post_xol_op,
};

static const struct uprobe_xol_ops push_xol_ops = {
	.emulate  = push_emulate_op,
};

/* Returns -ENOSYS if branch_xol_ops doesn't handle this insn */
static int branch_setup_xol_ops(struct arch_uprobe *auprobe, struct insn *insn)
{
	u8 opc1 = OPCODE1(insn);
	insn_byte_t p;

	if (insn_is_nop(insn))
		goto setup;

	switch (opc1) {
	case 0xeb:	/* jmp 8 */
	case 0xe9:	/* jmp 32 */
		break;

	case 0xe8:	/* call relative */
		branch_clear_offset(auprobe, insn);
		break;

	case 0x0f:
		if (insn->opcode.nbytes != 2)
			return -ENOSYS;
		/*
		 * If it is a "near" conditional jmp, OPCODE2() - 0x10 matches
		 * OPCODE1() of the "short" jmp which checks the same condition.
		 */
		opc1 = OPCODE2(insn) - 0x10;
		fallthrough;
	default:
		if (!is_cond_jmp_opcode(opc1))
			return -ENOSYS;
	}

	/*
	 * 16-bit overrides such as CALLW (66 e8 nn nn) are not supported.
	 * Intel and AMD behavior differ in 64-bit mode: Intel ignores 66 prefix.
	 * No one uses these insns, reject any branch insns with such prefix.
	 */
	for_each_insn_prefix(insn, p) {
		if (p == 0x66)
			return -ENOTSUPP;
	}

setup:
	auprobe->branch.opc1 = opc1;
	auprobe->branch.ilen = insn->length;
	auprobe->branch.offs = insn->immediate.value;

	auprobe->ops = &branch_xol_ops;
	return 0;
}

/* Returns -ENOSYS if push_xol_ops doesn't handle this insn */
static int push_setup_xol_ops(struct arch_uprobe *auprobe, struct insn *insn)
{
	u8 opc1 = OPCODE1(insn), reg_offset = 0;

	if (opc1 < 0x50 || opc1 > 0x57)
		return -ENOSYS;

	if (insn->length > 2)
		return -ENOSYS;
	if (insn->length == 2) {
		/* only support rex_prefix 0x41 (x64 only) */
#ifdef CONFIG_X86_64
		if (insn->rex_prefix.nbytes != 1 ||
		    insn->rex_prefix.bytes[0] != 0x41)
			return -ENOSYS;

		switch (opc1) {
		case 0x50:
			reg_offset = offsetof(struct pt_regs, r8);
			break;
		case 0x51:
			reg_offset = offsetof(struct pt_regs, r9);
			break;
		case 0x52:
			reg_offset = offsetof(struct pt_regs, r10);
			break;
		case 0x53:
			reg_offset = offsetof(struct pt_regs, r11);
			break;
		case 0x54:
			reg_offset = offsetof(struct pt_regs, r12);
			break;
		case 0x55:
			reg_offset = offsetof(struct pt_regs, r13);
			break;
		case 0x56:
			reg_offset = offsetof(struct pt_regs, r14);
			break;
		case 0x57:
			reg_offset = offsetof(struct pt_regs, r15);
			break;
		}
#else
		return -ENOSYS;
#endif
	} else {
		switch (opc1) {
		case 0x50:
			reg_offset = offsetof(struct pt_regs, ax);
			break;
		case 0x51:
			reg_offset = offsetof(struct pt_regs, cx);
			break;
		case 0x52:
			reg_offset = offsetof(struct pt_regs, dx);
			break;
		case 0x53:
			reg_offset = offsetof(struct pt_regs, bx);
			break;
		case 0x54:
			reg_offset = offsetof(struct pt_regs, sp);
			break;
		case 0x55:
			reg_offset = offsetof(struct pt_regs, bp);
			break;
		case 0x56:
			reg_offset = offsetof(struct pt_regs, si);
			break;
		case 0x57:
			reg_offset = offsetof(struct pt_regs, di);
			break;
		}
	}

	auprobe->push.reg_offset = reg_offset;
	auprobe->push.ilen = insn->length;
	auprobe->ops = &push_xol_ops;
	return 0;
}

/**
 * arch_uprobe_analyze_insn - instruction analysis including validity and fixups.
 * @auprobe: the probepoint information.
 * @mm: the probed address space.
 * @addr: virtual address at which to install the probepoint
 * Return 0 on success or a -ve number on error.
 */
int arch_uprobe_analyze_insn(struct arch_uprobe *auprobe, struct mm_struct *mm, unsigned long addr)
{
	enum insn_mode m = is_64bit_mm(mm) ? INSN_MODE_64 : INSN_MODE_32;
	u8 fix_ip_or_call = UPROBE_FIX_IP;
	struct insn insn;
	int ret;

	ret = insn_decode(&insn, auprobe->insn, sizeof(auprobe->insn), m);
	if (ret < 0)
		return -ENOEXEC;

	/*
	 * No need to check instruction in uprobe_init_insn in case we
	 * are on top of optimizable nop10.
	 */
	if (can_optimize(&insn, addr)) {
		set_bit(ARCH_UPROBE_FLAG_CAN_OPTIMIZE, &auprobe->flags);
	} else {
		ret = uprobe_init_insn(auprobe, &insn);
		if (ret)
			return ret;
	}

	ret = branch_setup_xol_ops(auprobe, &insn);
	if (ret != -ENOSYS)
		return ret;

	ret = push_setup_xol_ops(auprobe, &insn);
	if (ret != -ENOSYS)
		return ret;

	/*
	 * Figure out which fixups default_post_xol_op() will need to perform,
	 * and annotate defparam->fixups accordingly.
	 */
	switch (OPCODE1(&insn)) {
	case 0x9d:		/* popf */
		auprobe->defparam.fixups |= UPROBE_FIX_SETF;
		break;
	case 0xc3:		/* ret or lret -- ip is correct */
	case 0xcb:
	case 0xc2:
	case 0xca:
	case 0xea:		/* jmp absolute -- ip is correct */
		fix_ip_or_call = 0;
		break;
	case 0x9a:		/* call absolute - Fix return addr, not ip */
		fix_ip_or_call = UPROBE_FIX_CALL;
		break;
	case 0xff:
		switch (MODRM_REG(&insn)) {
		case 2: case 3:			/* call or lcall, indirect */
			fix_ip_or_call = UPROBE_FIX_CALL;
			break;
		case 4: case 5:			/* jmp or ljmp, indirect */
			fix_ip_or_call = 0;
			break;
		}
		fallthrough;
	default:
		riprel_analyze(auprobe, &insn);
	}

	auprobe->defparam.ilen = insn.length;
	auprobe->defparam.fixups |= fix_ip_or_call;

	auprobe->ops = &default_xol_ops;
	return 0;
}

/*
 * arch_uprobe_pre_xol - prepare to execute out of line.
 * @auprobe: the probepoint information.
 * @regs: reflects the saved user state of current task.
 */
int arch_uprobe_pre_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	if (auprobe->ops->pre_xol) {
		int err = auprobe->ops->pre_xol(auprobe, regs);
		if (err)
			return err;
	}

	regs->ip = utask->xol_vaddr;
	utask->autask.saved_trap_nr = current->thread.trap_nr;
	current->thread.trap_nr = UPROBE_TRAP_NR;

	utask->autask.saved_tf = !!(regs->flags & X86_EFLAGS_TF);
	regs->flags |= X86_EFLAGS_TF;
	if (test_tsk_thread_flag(current, TIF_BLOCKSTEP))
		set_task_blockstep(current, false);

	return 0;
}

/*
 * If xol insn itself traps and generates a signal(Say,
 * SIGILL/SIGSEGV/etc), then detect the case where a singlestepped
 * instruction jumps back to its own address. It is assumed that anything
 * like do_page_fault/do_trap/etc sets thread.trap_nr != -1.
 *
 * arch_uprobe_pre_xol/arch_uprobe_post_xol save/restore thread.trap_nr,
 * arch_uprobe_xol_was_trapped() simply checks that ->trap_nr is not equal to
 * UPROBE_TRAP_NR == -1 set by arch_uprobe_pre_xol().
 */
bool arch_uprobe_xol_was_trapped(struct task_struct *t)
{
	if (t->thread.trap_nr != UPROBE_TRAP_NR)
		return true;

	return false;
}

/*
 * Called after single-stepping. To avoid the SMP problems that can
 * occur when we temporarily put back the original opcode to
 * single-step, we single-stepped a copy of the instruction.
 *
 * This function prepares to resume execution after the single-step.
 */
int arch_uprobe_post_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;
	bool send_sigtrap = utask->autask.saved_tf;
	int err = 0;

	WARN_ON_ONCE(current->thread.trap_nr != UPROBE_TRAP_NR);
	current->thread.trap_nr = utask->autask.saved_trap_nr;

	if (auprobe->ops->post_xol) {
		err = auprobe->ops->post_xol(auprobe, regs);
		if (err) {
			/*
			 * Restore ->ip for restart or post mortem analysis.
			 * ->post_xol() must not return -ERESTART unless this
			 * is really possible.
			 */
			regs->ip = utask->vaddr;
			if (err == -ERESTART)
				err = 0;
			send_sigtrap = false;
		}
	}
	/*
	 * arch_uprobe_pre_xol() doesn't save the state of TIF_BLOCKSTEP
	 * so we can get an extra SIGTRAP if we do not clear TF. We need
	 * to examine the opcode to make it right.
	 */
	if (send_sigtrap)
		send_sig(SIGTRAP, current, 0);

	if (!utask->autask.saved_tf)
		regs->flags &= ~X86_EFLAGS_TF;

	return err;
}

/* callback routine for handling exceptions. */
int arch_uprobe_exception_notify(struct notifier_block *self, unsigned long val, void *data)
{
	struct die_args *args = data;
	struct pt_regs *regs = args->regs;
	int ret = NOTIFY_DONE;

	/* We are only interested in userspace traps */
	if (regs && !user_mode(regs))
		return NOTIFY_DONE;

	switch (val) {
	case DIE_INT3:
		if (uprobe_pre_sstep_notifier(regs))
			ret = NOTIFY_STOP;

		break;

	case DIE_DEBUG:
		if (uprobe_post_sstep_notifier(regs))
			ret = NOTIFY_STOP;

		break;

	default:
		break;
	}

	return ret;
}

/*
 * This function gets called when XOL instruction either gets trapped or
 * the thread has a fatal signal. Reset the instruction pointer to its
 * probed address for the potential restart or for post mortem analysis.
 */
void arch_uprobe_abort_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	if (auprobe->ops->abort)
		auprobe->ops->abort(auprobe, regs);

	current->thread.trap_nr = utask->autask.saved_trap_nr;
	regs->ip = utask->vaddr;
	/* clear TF if it was set by us in arch_uprobe_pre_xol() */
	if (!utask->autask.saved_tf)
		regs->flags &= ~X86_EFLAGS_TF;
}

static bool __skip_sstep(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	if (auprobe->ops->emulate)
		return auprobe->ops->emulate(auprobe, regs);
	return false;
}

bool arch_uprobe_skip_sstep(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	bool ret = __skip_sstep(auprobe, regs);
	if (ret && (regs->flags & X86_EFLAGS_TF))
		send_sig(SIGTRAP, current, 0);
	return ret;
}

unsigned long
arch_uretprobe_hijack_return_addr(unsigned long trampoline_vaddr, struct pt_regs *regs)
{
	int rasize = sizeof_long(regs), nleft;
	unsigned long orig_ret_vaddr = 0; /* clear high bits for 32-bit apps */

	if (copy_from_user(&orig_ret_vaddr, (void __user *)regs->sp, rasize))
		return -1;

	/* check whether address has been already hijacked */
	if (orig_ret_vaddr == trampoline_vaddr)
		return orig_ret_vaddr;

	nleft = copy_to_user((void __user *)regs->sp, &trampoline_vaddr, rasize);
	if (likely(!nleft)) {
		if (shstk_update_last_frame(trampoline_vaddr)) {
			force_sig(SIGSEGV);
			return -1;
		}
		return orig_ret_vaddr;
	}

	if (nleft != rasize) {
		pr_err("return address clobbered: pid=%d, %%sp=%#lx, %%ip=%#lx\n",
		       current->pid, regs->sp, regs->ip);

		force_sig(SIGSEGV);
	}

	return -1;
}

bool arch_uretprobe_is_alive(struct return_instance *ret, enum rp_check ctx,
				struct pt_regs *regs)
{
	if (ctx == RP_CHECK_CALL) /* sp was just decremented by "call" insn */
		return regs->sp < ret->stack;
	else
		return regs->sp <= ret->stack;
}

/*
 * Heuristic-based check if uprobe is installed at the function entry.
 *
 * Under assumption of user code being compiled with frame pointers,
 * `push %rbp/%ebp` is a good indicator that we indeed are.
 *
 * Similarly, `endbr64` (assuming 64-bit mode) is also a common pattern.
 * If we get this wrong, captured stack trace might have one extra bogus
 * entry, but the rest of stack trace will still be meaningful.
 */
bool is_uprobe_at_func_entry(struct pt_regs *regs)
{
	struct arch_uprobe *auprobe;

	if (!current->utask)
		return false;

	auprobe = current->utask->auprobe;
	if (!auprobe)
		return false;

	/* push %rbp/%ebp */
	if (auprobe->insn[0] == 0x55)
		return true;

	/* endbr64 (64-bit only) */
	if (user_64bit_mode(regs) && is_endbr((u32 *)auprobe->insn))
		return true;

	return false;
}

#ifdef CONFIG_IA32_EMULATION
unsigned long arch_uprobe_get_xol_area(void)
{
	struct thread_info *ti = current_thread_info();
	unsigned long vaddr;

	/*
	 * HACK: we are not in a syscall, but x86 get_unmapped_area() paths
	 * ignore TIF_ADDR32 and rely on in_32bit_syscall() to calculate
	 * vm_unmapped_area_info.high_limit.
	 *
	 * The #ifdef above doesn't cover the CONFIG_X86_X32_ABI=y case,
	 * but in this case in_32bit_syscall() -> in_x32_syscall() always
	 * (falsely) returns true because ->orig_ax == -1.
	 */
	if (test_thread_flag(TIF_ADDR32))
		ti->status |= TS_COMPAT;
	vaddr = get_unmapped_area(NULL, TASK_SIZE - PAGE_SIZE, PAGE_SIZE, 0, 0);
	ti->status &= ~TS_COMPAT;

	return vaddr;
}
#endif
