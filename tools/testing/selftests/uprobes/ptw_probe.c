// SPDX-License-Identifier: GPL-2.0
/*
 * ptw_probe - ptwrite uprobe selftest target.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static __attribute__((noipa)) uint64_t
punfn(uint64_t a)
{
	uint32_t v;

	asm volatile("mov $0xfff10000, %%eax\n\tmovl %%eax, %0"
		     : "=r"(v) : : "rax");
	return v ^ (a * 0x9e3779b97f4a7c15ULL);
}

static __attribute__((noipa)) uint64_t
jcc8(uint64_t a)
{
	asm volatile("jne 1f\n\tmovabs $0x1111111111111111, %%rax\n\t"
		     "1:" : "+a"(a) : : "cc");
	return a;
}

static __attribute__((noipa)) uint64_t
nopfn(uint64_t a)
{
	asm volatile("nop\n\t"
		     ".p2align 3, 0x90\n\t"
		     ".globl nopfn_site\n\t"
		     "nopfn_site:\n\t"
		     "nop\n\tnop\n\tnop\n\tnop\n\tnop" ::: "memory");
	return a * 31 + 7;
}

/* These symbols are labels defined by the inline assembly above. */
extern const uint8_t nopfn_site[];
extern const uint8_t nopfn_unaligned_site[];

static __attribute__((noipa)) uint64_t
unaligned_nopfn(uint64_t a)
{
	asm volatile(".p2align 3, 0x90\n\t"
		     "nop\n\t"
		     ".globl nopfn_unaligned_site\n\t"
		     "nopfn_unaligned_site:\n\t"
		     "nop\n\tnop\n\tnop\n\tnop\n\tnop" ::: "memory");
	return a * 13 + 5;
}

static __attribute__((noipa)) uint64_t
nop5(uint64_t a)
{
	asm volatile(".byte 0x0f, 0x1f, 0x44, 0x00, 0x00" ::: "memory");
	return a * 7 + 3;
}

static __attribute__((noipa)) uint64_t
rzfn(uint64_t a)
{
	uint64_t v;

	asm volatile("movq %0, -8(%%rsp)" : : "r"(a) : "memory");
	asm volatile(".globl rz_probe_site\n\t"
		     "rz_probe_site:\n\t"
		     "nop\n\tnop\n\tnop\n\tnop\n\tnop" ::: "memory");
	asm volatile("movq -8(%%rsp), %0" : "=r"(v) : : "memory");
	return v ^ 0x55;
}

static uint8_t load_site_byte(const uint8_t *p)
{
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

static void dump_site(const char *name, const uint8_t *p)
{
	printf("SITE %s %02x%02x%02x%02x%02x\n", name,
	       load_site_byte(p + 0), load_site_byte(p + 1),
	       load_site_byte(p + 2), load_site_byte(p + 3),
	       load_site_byte(p + 4));
}

static int check_installed(const char *name, const uint8_t *p, uint64_t vaddr)
{
	uint32_t rel_u;
	int32_t rel;
	unsigned long long target, s, e;
	FILE *f;
	char line[256];
	int found = 0;

	if (load_site_byte(p + 0) != 0xe9)
		return 1;	/* not installed */
	rel_u = (uint32_t)load_site_byte(p + 1) |
		((uint32_t)load_site_byte(p + 2) << 8) |
		((uint32_t)load_site_byte(p + 3) << 16) |
		((uint32_t)load_site_byte(p + 4) << 24);
	rel = (int32_t)rel_u;
	target = vaddr + 5 + (int64_t)rel;
	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!strstr(line, "[uprobes-ptwrite]"))
			continue;
		if (sscanf(line, "%llx-%llx", &s, &e) == 2 &&
		    target >= s && target < e) {
			found = 1;
			break;
		}
	}
	fclose(f);
	printf("INSTALL %s %s (target %llx)\n", name,
	       found ? "ok" : "BAD-TARGET", (unsigned long long)target);
	return found ? 0 : 2;
}

int main(int argc, char **argv)
{
	uint64_t acc = 0x1122334455667788ULL;
	int i, r, bad = 0;


	for (i = 0; i < 100; i++)
		acc = nopfn(acc + i);
	for (i = 0; i < 100; i++)
		acc = unaligned_nopfn(acc + i);
	for (i = 0; i < 100; i++)
		acc = nop5(acc + i);
	for (i = 0; i < 100; i++)
		acc = rzfn(acc + i);
	for (i = 0; i < 100; i++)
		acc = punfn(acc + i);
	for (i = 0; i < 100; i++)
		acc = jcc8(acc + i);

	dump_site("punfn", (const uint8_t *)&punfn);
	dump_site("jcc8", (const uint8_t *)&jcc8);
	dump_site("nopfn", nopfn_site);
	dump_site("unaligned_nopfn", nopfn_unaligned_site);
	dump_site("nop5", (const uint8_t *)&nop5);

	r = check_installed("punfn", (const uint8_t *)&punfn, (uint64_t)&punfn);
	bad |= r == 2;
	r = check_installed("nopfn", nopfn_site, (uint64_t)nopfn_site);
	bad |= r == 2;
	r = check_installed("nop5", (const uint8_t *)&nop5, (uint64_t)&nop5);
	bad |= r == 2;

	printf("PTW-PROBE acc=%llx %s\n", (unsigned long long)acc,
	       bad ? "INSTALL-BAD" : "ok");
	return bad ? 1 : 0;
}
