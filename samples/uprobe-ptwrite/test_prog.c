// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_prog - userspace target for the ptwrite uprobe test.
 *
 * target() carries a 5-byte NOP (nopl 0(%rax,%rax,1) = 0f 1f 44 00 00) at
 * its entry. A probe installed at that file offset emits rdi/rsi (a, b)
 * via PTWRITE. In the test loop a == i and b == i + 1.
 */
#ifndef noinline
#define noinline __attribute__((noinline))
#endif

#include <stdio.h>

static noinline unsigned long
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

	for (i = 0; i < 2000; i++)
		acc += target(i, i + 1);
	printf("acc=%lu\n", acc);
	return 0;
}
