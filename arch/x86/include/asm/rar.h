/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_RAR_H
#define _ASM_X86_RAR_H

/*
 * RAR payload types
 */
#define RAR_TYPE_INVPG		0
#define RAR_TYPE_INVPG_NO_CR3	1
#define RAR_TYPE_INVPCID	2
#define RAR_TYPE_INVEPT		3
#define RAR_TYPE_INVVPID	4
#define RAR_TYPE_WRMSR		5

/*
 * Subtypes for RAR_TYPE_INVLPG
 */
#define RAR_INVPG_ADDR			0 /* address specific */
#define RAR_INVPG_ALL			2 /* all, include global */
#define RAR_INVPG_ALL_NO_GLOBAL		3 /* all, exclude global */

/*
 * Subtypes for RAR_TYPE_INVPCID
 */
#define RAR_INVPCID_ADDR		0 /* address specific */
#define RAR_INVPCID_PCID		1 /* all of PCID */
#define RAR_INVPCID_ALL			2 /* all, include global */
#define RAR_INVPCID_ALL_NO_GLOBAL	3 /* all, exclude global */

/*
 * Page size for RAR_TYPE_INVLPG
 */
#define RAR_INVLPG_PAGE_SIZE_4K		0
#define RAR_INVLPG_PAGE_SIZE_2M		1
#define RAR_INVLPG_PAGE_SIZE_1G		2

/*
 * Max number of pages per payload
 */
#define RAR_INVLPG_MAX_PAGES 63

struct rar_payload {
	u64 for_sw		: 8;
	u64 type		: 8;
	u64 must_be_zero_1	: 16;
	u64 subtype		: 3;
	u64 page_size		: 2;
	u64 num_pages		: 6;
	u64 must_be_zero_2	: 21;

	u64 must_be_zero_3;

	/*
	 * Starting address
	 */
	union {
		u64 initiator_cr3;
		struct {
			u64 pcid	: 12;
			u64 ignored	: 52;
		};
	};
	u64 linear_address;

	/*
	 * Padding
	 */
	u64 padding[4];
};

void rar_cpu_init(void);
void rar_boot_cpu_init(void);
void smp_call_rar_many(const struct cpumask *mask, u16 pcid,
		       unsigned long start, unsigned long end);

#endif /* _ASM_X86_RAR_H */
