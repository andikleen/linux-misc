/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_UPROBES_H
#define _ASM_UPROBES_H
/*
 * User-space Probes (UProbes) for x86
 *
 * Copyright (C) IBM Corporation, 2008-2011
 * Authors:
 *	Srikar Dronamraju
 *	Jim Keniston
 */

#include <linux/notifier.h>

typedef u8 uprobe_opcode_t;

#define MAX_UINSN_BYTES			  16
#define UPROBE_XOL_SLOT_BYTES		 128	/* to keep it cache aligned */

#define UPROBE_SWBP_INSN		0xcc
#define UPROBE_SWBP_INSN_SIZE		   1

enum {
	ARCH_UPROBE_FLAG_CAN_OPTIMIZE   = 0,
	ARCH_UPROBE_FLAG_OPTIMIZE_FAIL  = 1,
	ARCH_UPROBE_FLAG_PTWRITE        = 2,
};

struct uprobe_xol_ops;

/*
 * ptwrite probe state. The stub template (code + data slots) is built
 * once at registration (mm-independent except the final jmp's rel32, patched
 * per-mm at install). Block layout:
 *   [ptwriteq hdr(%rip)] [arg emissions] [jmp probe+5] [u64 slots: header, imms]
 */
struct uprobe_ptwrite_arch {
	u8	stub[256];
	u8	stub_len;	/* code + data, whole block */
	u8	jmp_off;	/* offset of the final jmp's rel32 field */
	u8	ndata;		/* number of u64 data slots */
	u8	orig[MAX_UINSN_BYTES];	/* pristine file bytes, before generic analysis */
};

/* Per-mm page holding generated ptwrite stub blocks (mirrors trampolines). */
struct uprobe_ptwrite_page {
	struct hlist_node	node;
	struct page		*page;		/* stub blocks written via kmap */
	unsigned long		vaddr;		/* mapping base */
	u16			cursor;		/* next free block offset */
};

struct arch_uprobe {
	union {
		u8			insn[MAX_UINSN_BYTES];
		u8			ixol[MAX_UINSN_BYTES];
	};

	const struct uprobe_xol_ops	*ops;

	union {
		struct {
			s32	offs;
			u8	ilen;
			u8	opc1;
		}			branch;
		struct {
			u8	fixups;
			u8	ilen;
		} 			defparam;
		struct {
			u8	reg_offset;	/* to the start of pt_regs */
			u8	ilen;
		}			push;
	};

	struct uprobe_ptwrite_arch	ptwrite;
	unsigned long flags;
};

struct arch_uprobe_task {
#ifdef CONFIG_X86_64
	unsigned long			saved_scratch_register;
#endif
	unsigned int			saved_trap_nr;
	unsigned int			saved_tf;
};

#ifdef CONFIG_UPROBES
extern bool is_uprobe_at_func_entry(struct pt_regs *regs);
#else
static bool is_uprobe_at_func_entry(struct pt_regs *regs)
{
	return false;
}
#endif /* CONFIG_UPROBES */

#endif	/* _ASM_UPROBES_H */
