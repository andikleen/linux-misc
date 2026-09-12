// SPDX-License-Identifier: GPL-2.0
/*
 * manual_ptw.c - decoder test: raw ptwrite instructions mixed with a
 * ptwrite uprobe.
 *
 * target() carries a 5-byte NOP (nopl 0(%rax,%rax,1) = 0f 1f 44 00 00)
 * at its entry to allow a ptwrite uprobe be installed there.
 */
#include <stdio.h>
#include <stdint.h>

static inline void ptwriteq(uint64_t v)
{
	__asm__ volatile("ptwrite %0" : : "r"(v));
}

__attribute__((noinline)) static unsigned long
target(unsigned long a, unsigned long b)
{
	/* 5-byte NOP: nopl 0(%rax,%rax,1) = 0f 1f 44 00 00.
	 * Emitted as raw bytes: the assembler would otherwise shrink
	 * "nopl (%rax,%rax,1)" to the 4-byte form (0f 1f 04 00), which
	 * the probe site validation rejects (jmp rel32 needs 5 bytes).
	 */
	asm volatile(".byte 0x0f, 0x1f, 0x44, 0x00, 0x00");
	return a * 31 + b;
}

int main(void)
{
	unsigned long i, acc = 0;

	for (i = 0; i < 100; i++) {
		acc += target(i, i + 1);
		ptwriteq(0xfeed0000ULL | (uint32_t)i);
		__asm__ volatile("lfence");
	}
	ptwriteq(0xcafebabeULL);
	printf("acc=%lu\n", acc);
	return 0;
}
