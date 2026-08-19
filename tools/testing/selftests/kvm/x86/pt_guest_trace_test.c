// SPDX-License-Identifier: GPL-2.0-only
/*
 * pt_guest_trace_test - guest Intel PT end-to-end trace: enable a
 * chained ToPA trace, busy-loop, disable, and check packets were
 * produced.  Requires pt_mode=1; SKIPs otherwise.  --stress N traces
 * while the vCPU migrates across all online CPUs.
 */
#include <asm/msr-index.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "hybrid_util.h"


#define TOPA_TABLE_PAGES	1
#define TOPA_REGION_PAGES	32	/* 128 KiB per output region */
#define TOPA_REGIONS		8	/* 1 MiB total */
#define TOPA_SIZE_CODE		5	/* 2^(5+12) = 128 KiB */

#define DEFAULT_CYCLES		(3ULL * 1000 * 1000 * 1000)	/* ~1 s of invariant TSC (~3 GHz) */

struct pt_guest_results {
	u32 caps0[4];		/* CPUID.0x14.0 as seen by the guest */
	u32 caps1[4];		/* CPUID.0x14.1 */
	u32 pt_present;		/* leaf 0x14 EAX != 0 */
	u32 gp_msr;		/* #GP fired on an RTIT MSR write */
	u64 status;		/* IA32_RTIT_STATUS after disable */
	u64 offset;		/* OUTPUT_MASK_PTRS after disable */
	u64 rb_ctl, rb_mask, rb_status;	/* read back right after enable */
	u32 done;
};

static struct pt_guest_results *res;

static void guest_gp_handler(struct ex_regs *regs)
{
	res->gp_msr = 1;
	regs->rip += 2;		/* skip the WRMSR that faulted */
}

static void guest_main(struct pt_guest_results *r, u64 topa, u64 buf, u64 cycles)
{
	u64 *te = (u64 *)topa;	/* identity-mapped: gva == gpa */
	u32 a, b, c, d;
	int i;

	res = r;

	__cpuid(0x14, 0, &a, &b, &c, &d);
	res->caps0[0] = a; res->caps0[1] = b; res->caps0[2] = c; res->caps0[3] = d;
	__cpuid(0x14, 1, &a, &b, &c, &d);
	res->caps1[0] = a; res->caps1[1] = b; res->caps1[2] = c; res->caps1[3] = d;
	res->pt_present = !!res->caps0[0];

	if (!res->pt_present)
		GUEST_DONE();

	/* Chained ToPA table; the last entry ends the table. */
	for (i = 0; i < TOPA_REGIONS; i++) {
		u64 base = buf + (u64)i * (1ULL << (TOPA_SIZE_CODE + 12));

		te[i] = (base & PHYSICAL_PAGE_MASK) |
			((u64)TOPA_SIZE_CODE << 6) |
			(i == TOPA_REGIONS - 1 ? BIT(0) : 0);	/* END */
		/*
		 * Touch each region so its EPT entries exist before the trace
		 * starts; PT output to an unmapped page is dropped.
		 */
		*(volatile u8 *)(unsigned long)base = 0;
	}

	wrmsr(MSR_IA32_RTIT_OUTPUT_BASE, topa);
	wrmsr(MSR_IA32_RTIT_OUTPUT_MASK, 0x7f);	/* entry 0, offset 0 */
	wrmsr(MSR_IA32_RTIT_STATUS, 0);
	wrmsr(MSR_IA32_RTIT_CTL,
	      RTIT_CTL_TRACEEN | RTIT_CTL_OS | RTIT_CTL_USR |
	      RTIT_CTL_TSC_EN | RTIT_CTL_TOPA);

	/* Read back the MSRs after enabling. */
	res->rb_ctl = rdmsr(MSR_IA32_RTIT_CTL);
	res->rb_mask = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK);
	res->rb_status = rdmsr(MSR_IA32_RTIT_STATUS);

	busy_loop(cycles);

	wrmsr(MSR_IA32_RTIT_CTL, 0);
	res->status = rdmsr(MSR_IA32_RTIT_STATUS);
	res->offset = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK);
	res->done = 1;
	GUEST_DONE();
}

static void check_guest(struct kvm_vcpu *vcpu, struct kvm_vm *vm,
			struct pt_guest_results *res_hva, void *topa_hva,
			u8 *buf, size_t buf_sz)
{
	struct ucall uc;
	size_t i, nonzero = 0;

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		if (vcpu->run->exit_reason == KVM_EXIT_INTERNAL_ERROR) {
			u64 *table = (u64 *)topa_hva;
			size_t nz = 0, i;

			for (i = 0; i < buf_sz; i++)
				nz += !!buf[i];
			printf("internal error suberror=%u data=%x:%x:%x:%x "
			       "res: done=%u gp=%u pt=%u status=%lx offset=%lu "
			       "rb_ctl=%lx rb_mask=%lx rb_status=%lx "
			       "topa0=%lx nonzero=%zu\n",
			       vcpu->run->internal.suberror,
			       vcpu->run->internal.data[0],
			       vcpu->run->internal.data[1],
			       vcpu->run->internal.data[2],
			       vcpu->run->internal.data[3],
			       res_hva->done, res_hva->gp_msr, res_hva->pt_present,
			       res_hva->status, res_hva->offset,
			       res_hva->rb_ctl, res_hva->rb_mask,
			       res_hva->rb_status, table[0], nz);
		}
		TEST_ASSERT(false, "Unexpected exit: %s",
			    exit_reason_str(vcpu->run->exit_reason));
	}

	TEST_ASSERT(res_hva->done, "guest did not finish");
	TEST_ASSERT(!res_hva->gp_msr, "#GP on RTIT MSR write");
	TEST_ASSERT(!(res_hva->status & RTIT_STATUS_ERROR),
		    "PT error status: %lx", res_hva->status);
	for (i = 0; i < buf_sz; i++)
		nonzero += !!buf[i];
	TEST_ASSERT(nonzero,
		    "no trace data in ToPA buffers (mask %lx status %lx)",
		    res_hva->offset, res_hva->status);
	printf("guest PT trace: %zu nonzero bytes, mask %lx (off %lu), status %lx\n",
	       nonzero, res_hva->offset, res_hva->offset >> 32, res_hva->status);
}

static void *vcpu_thread(void *arg)
{
	return vcpu_run_thread(arg);
}

static void *migrator_thread(void *arg)
{
	return vcpu_migrator_thread(arg);
}

int main(int argc, char *argv[])
{
	struct pt_guest_results *res_hva;
	const struct kvm_cpuid2 *supported;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t res_gva, topa_gva, buf_gva;
	void *topa_hva, *buf_hva;
	u64 trace_cycles = DEFAULT_CYCLES;
	bool stress = false;
	int stress_secs = 12, i;
	size_t buf_sz = TOPA_REGION_PAGES * TOPA_REGIONS * 4096;

	if (argc > 1 && !strcmp(argv[1], "--stress")) {
		stress = true;
		if (argc > 2)
			stress_secs = atoi(argv[2]);
		trace_cycles = (stress_secs + 5) * 3ULL * 1000 * 1000 * 1000;
	}

	TEST_REQUIRE(get_kvm_intel_param_integer("pt_mode") == 1);

	supported = kvm_get_supported_cpuid();
	for (i = 0; i < supported->nent; i++)
		if (supported->entries[i].function == 0x14 &&
		    supported->entries[i].index == 0)
			break;
	if (i == supported->nent || !supported->entries[i].eax) {
		printf("SKIP: host exposes no guest PT (kvm_intel pt_mode=1 required)\n");
		exit(KSFT_SKIP);
	}

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);

	res_gva = vm_alloc(vm, sizeof(*res_hva), KVM_UTIL_MIN_VADDR);
	res_hva = addr_gva2hva(vm, res_gva);
	memset(res_hva, 0, sizeof(*res_hva));

	/*
	 * ToPA table + buffers in a dedicated identity-mapped memslot; the
	 * first output region must be aligned to the region size.
	 */
	{
		u64 region_sz = 1ULL << (TOPA_SIZE_CODE + 12);
		u64 buf_end;

		topa_gva = alloc_identity(vm, 1, 0x20000000,
					  TOPA_TABLE_PAGES +
					  TOPA_REGION_PAGES * TOPA_REGIONS +
					  region_sz / 4096, &topa_hva);
		buf_gva = (topa_gva + 4096 + region_sz - 1) & ~(region_sz - 1);
		buf_end = buf_gva + TOPA_REGION_PAGES * TOPA_REGIONS * 4096;
		TEST_ASSERT(buf_end <= topa_gva +
			    (TOPA_TABLE_PAGES + TOPA_REGION_PAGES * TOPA_REGIONS +
			     region_sz / 4096) * 4096,
			    "ToPA buffer exceeds dedicated memslot");
		buf_hva = (u8 *)topa_hva + (buf_gva - topa_gva);
	}
	memset(topa_hva, 0, TOPA_TABLE_PAGES * 4096);
	memset(buf_hva, 0, buf_sz);

	vm_install_exception_handler(vm, GP_VECTOR, guest_gp_handler);
	vcpu_args_set(vcpu, 4, res_gva, topa_gva, buf_gva, trace_cycles);

	if (stress) {
		struct vcpu_migrate_ctx ctx = { .vcpu = vcpu, .iters = stress_secs * 10 };
		pthread_t th, mth;

		TEST_ASSERT(vcpu_migrate_ctx_init(&ctx), "no online CPUs");
		pthread_create(&th, NULL, vcpu_thread, &ctx);
		while (!ctx.tid)
			usleep(1000);
		pthread_create(&mth, NULL, migrator_thread, &ctx);
		pthread_join(mth, NULL);
		pthread_join(th, NULL);
	} else {
		vcpu_run(vcpu);
	}

	check_guest(vcpu, vm, res_hva, topa_hva, buf_hva, buf_sz);

	kvm_vm_free(vm);
	return 0;
}
