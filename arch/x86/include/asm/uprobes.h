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
 * Stub block size. Conservative worst case is 298 bytes: 9-byte header,
 * one lead fence, eight 21-byte memory forms with one 3-byte fence each,
 * a 16-byte original-instruction copy, a 5-byte return jump, alignment,
 * and 66 bytes of data/fault metadata. 384 leaves room. A static_assert in
 * arch/x86/kernel/uprobes.c checks the bound; prepare() also checks it with
 * -E2BIG.
 */
#define UPROBE_PTWRITE_STUB_SIZE	384

/* the out-of-line original-instruction copy slot (x86 max insn length) */
#define UPROBE_PTWRITE_COPY_SIZE	MAX_UINSN_BYTES

/*
 * Word pacing: insert this many LFENCEs between emitted ptwrite words and
 * before the first word, unless UPROBE_PTWRITE_FL_NO_LEAD_PACE is requested.
 */
#define UPROBE_PTWRITE_SERIALIZE_LFENCES	1	/* LFENCEs per word gap */

/*
 * ptwrite probe state. The stub template (code + data slots) is built
 * once at registration. Only the final jmp's rel32 and the copy's
 * disp/rel fields are patched per-mm at install. Block layout:
 *   [ptwriteq hdr(%rip)] [arg emissions] [orig-insn copy]
 *   [jmp probe+len] [u64 slots: header, imms]
 */
struct uprobe_ptwrite_arch {
	u8	stub[UPROBE_PTWRITE_STUB_SIZE];
	u16	stub_len;	/* code + data + fault table, whole block */
	u8	jmp_off;	/* offset of the final jmp's rel32 field */
	u8	copy_off;	/* offset of the out-of-line instruction copy */
	u8	len;		/* copy length (0 = drop); back-jmp = vaddr+len */
	u8	disp_off;	/* rip-relative disp32 offset in the copy (0 = none) */
	s32	disp;		/* original disp32 (delta-patched per-mm) */
	u8	ndata;		/* number of u64 data slots */
	u8	orig[MAX_UINSN_BYTES];	/* pristine file bytes, before generic analysis */
	u16	ft_off;	/* fault table offset within the block (0 if none) */
	u8	nft;		/* number of fault entries */
	u8	allow_nop_run;	/* accept a five-byte run of 0x90 */
};

/* Per-mm page holding generated ptwrite stub blocks (mirrors trampolines). */
struct uprobe_ptwrite_page {
	struct hlist_node	node;
	struct page		*page;		/* stub blocks written via kmap */
	unsigned long		vaddr;		/* mapping base */
	u16			cursor;		/* next free block offset */
	u16			nblocks;
	struct {
		u16 off;	/* block offset in the page */
		u16 len;	/* generated block length */
		u16 ft_off;	/* fault table offset within the block */
		u8  orig0;	/* original site byte 0 (pun restore) */
		u8  pun;	/* instruction-pun mechanism (single-byte poke) */
		u8  site_len;	/* original instruction length (pun identity) */
		s32 site_off;	/* probe site - page base (idempotent reinstall) */
		u8  site_insn[MAX_UINSN_BYTES];	/* original bytes (pun identity) */
	} index[PAGE_SIZE / 32];	/* exact: min block = 32 B (nargs >= 1), */
					/* so <= 128 blocks fit a page */
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
