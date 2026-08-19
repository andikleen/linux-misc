/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared helpers for the Intel PT / hybrid-PMU selftests.
 */
#ifndef SELFTEST_X86_HYBRID_UTIL_H
#define SELFTEST_X86_HYBRID_UTIL_H

#define _GNU_SOURCE 1
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"


/*
 * Parse a Linux CPU-range list ("0-3", "4-11", "0,2-3") into a cpu_set_t.
 * Returns the CPU count, or 0 for empty/invalid input.
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
 * Read a hybrid perf PMU's CPU range from sysfs ("cpu_core" or
 * "cpu_atom").  Returns false if the node is absent (non-hybrid host).
 */
static inline bool hybrid_range(const char *pmu, cpu_set_t *set)
{
	char path[128], *line = NULL;
	size_t len = 0;
	ssize_t n;
	FILE *f;

	snprintf(path, sizeof(path),
		 "/sys/bus/event_source/devices/%s/cpus", pmu);
	f = fopen(path, "r");
	if (!f)
		return false;
	n = getline(&line, &len, f);
	fclose(f);
	if (n < 0) {
		free(line);
		return false;
	}
	line[strcspn(line, "\n")] = '\0';
	n = parse_cpu_range(line, set);
	free(line);
	return n > 0;
}

/* Read the online CPU list ("0-3,7") from sysfs into a cpu_set_t. */
static inline void read_online_cpus(cpu_set_t *set)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t n;
	FILE *f;

	f = fopen("/sys/devices/system/cpu/online", "r");
	TEST_ASSERT(f, "open /sys/devices/system/cpu/online: %s", strerror(errno));
	n = getline(&line, &len, f);
	fclose(f);
	TEST_ASSERT(n >= 0, "read /sys/devices/system/cpu/online");
	line[strcspn(line, "\n")] = '\0';
	TEST_ASSERT(parse_cpu_range(line, set), "parse online CPUs '%s'", line);
	free(line);
}

/*
 * Identity-map @npages of a new memslot for PT ToPA output, whose entries
 * carry guest-physical addresses.  Returns the base gpa; *hva the host map.
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

/*
 * vCPU migration helpers: run the vCPU on one thread while a second moves
 * it across the online CPUs every 100 ms.
 */
struct vcpu_migrate_ctx {
	struct kvm_vcpu *vcpu;
	pid_t tid;
	int iters;
	int ncpus;
	int cpus[CPU_SETSIZE];
};

static inline void *vcpu_run_thread(void *arg)
{
	struct vcpu_migrate_ctx *ctx = arg;

	ctx->tid = syscall(SYS_gettid);
	vcpu_run(ctx->vcpu);
	return NULL;
}

static inline void *vcpu_migrator_thread(void *arg)
{
	struct vcpu_migrate_ctx *ctx = arg;
	cpu_set_t set;
	int i;

	for (i = 0; i < ctx->iters; i++) {
		CPU_ZERO(&set);
		CPU_SET(ctx->cpus[i % ctx->ncpus], &set);
		syscall(SYS_sched_setaffinity, ctx->tid, sizeof(set), &set);
		usleep(100 * 1000);
	}
	return NULL;
}

/* Fill @ctx->cpus with the online CPUs; returns the count. */
static inline int vcpu_migrate_ctx_init(struct vcpu_migrate_ctx *ctx)
{
	cpu_set_t online;
	int i, n = 0;

	read_online_cpus(&online);
	for (i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &online))
			ctx->cpus[n++] = i;
	ctx->ncpus = n;
	return n;
}

#endif
