// SPDX-License-Identifier: GPL-2.0-only
/*
 * Shared helpers for the Intel PT / hybrid-PMU selftests.
 */
#ifndef SELFTEST_X86_HYBRID_UTIL_H
#define SELFTEST_X86_HYBRID_UTIL_H

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kvm_util.h"
#include "processor.h"

#define RTIT_STATUS_ERROR	BIT(3)

/*
 * Parse a Linux CPU-range list ("0-3", "4-11", "0,2-3") into a cpu_set_t.
 * Returns the number of CPUs added, or 0 on an empty/invalid input.
 */
static inline int parse_cpu_range(const char *s, cpu_set_t *set)
{
	char *copy = strdup(s);
	char *tok, *p;
	int n = 0;

	if (!copy)
		return 0;
	CPU_ZERO(set);
	for (tok = strtok_r(copy, ",", &p); tok; tok = strtok_r(NULL, ",", &p)) {
		int lo = -1, hi = -1, i, r;

		r = sscanf(tok, "%d-%d", &lo, &hi);
		if (r == 1)
			hi = lo;
		if (r < 1 || hi < lo || hi >= CPU_SETSIZE) {
			free(copy);
			return 0;
		}
		for (i = lo; i <= hi; i++) {
			CPU_SET(i, set);
			n++;
		}
	}
	free(copy);
	return n;
}

/*
 * Read one hybrid perf PMU's CPU range from sysfs ("cpu_core" or
 * "cpu_atom").  Returns false when the node is absent (non-hybrid host).
 */
static inline bool hybrid_range(const char *pmu, cpu_set_t *set)
{
	char path[128], buf[256];
	FILE *f;

	snprintf(path, sizeof(path),
		 "/sys/bus/event_source/devices/%s/cpus", pmu);
	f = fopen(path, "r");
	if (!f)
		return false;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return false;
	}
	fclose(f);
	buf[strcspn(buf, "\n")] = '\0';
	return parse_cpu_range(buf, set) > 0;
}

/* Read the online CPU list ("0-3,7") from sysfs into a cpu_set_t. */
static inline void read_online_cpus(cpu_set_t *set)
{
	char buf[256];
	FILE *f;

	f = fopen("/sys/devices/system/cpu/online", "r");
	TEST_ASSERT(f, "open /sys/devices/system/cpu/online: %s", strerror(errno));
	TEST_ASSERT(fgets(buf, sizeof(buf), f), "read /sys/devices/system/cpu/online");
	fclose(f);
	buf[strcspn(buf, "\n")] = '\0';
	TEST_ASSERT(parse_cpu_range(buf, set), "parse online CPUs '%s'", buf);
}

/*
 * Add a dedicated memslot and identity-map (gva == gpa) the first @npages
 * of it, for Intel PT ToPA output whose entries carry guest-physical
 * addresses.  Returns the base gpa; *hva is the host-side mapping.
 */
static inline gpa_t alloc_identity(struct kvm_vm *vm, u32 memslot,
				   gpa_t base, size_t npages, void **hva)
{
	gpa_t gpa;
	size_t i;

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, base, memslot,
				    npages, 0);
	gpa = vm_phy_pages_alloc(vm, npages, base, memslot);
	TEST_ASSERT(gpa, "vm_phy_pages_alloc failed");
	for (i = 0; i < npages; i++)
		virt_pg_map(vm, gpa + i * vm->page_size, gpa + i * vm->page_size);
	*hva = addr_gpa2hva(vm, gpa);
	return gpa;
}

/* Guest busy loop: run for ~cycles TSC ticks (dense NOP stream for PT). */
static inline void busy_loop(u64 cycles)
{
	u64 t0 = rdtsc();

	while (rdtsc() - t0 < cycles) {
		asm volatile("nop;nop;nop;nop;nop;nop;nop;nop;"
			     "nop;nop;nop;nop;nop;nop;nop;nop;");
	}
}

#endif
