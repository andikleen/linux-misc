// SPDX-License-Identifier: GPL-2.0-only
/*
 * pt_hybrid_caps_test - guest PT caps must be present and match with
 * the vCPU pinned to P-cores vs E-cores (equal by construction, so the
 * real check is that PT works on E-cores).  Requires pt_mode=1 and a
 * hybrid host; SKIPs otherwise.
 */
#include <asm/msr-index.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "hybrid_util.h"

struct pt_caps_results {
	u32 caps0[4];		/* CPUID.0x14.0 */
	u32 caps1[4];		/* CPUID.0x14.1 */
	u32 pt_present;
};

static void guest_main(struct pt_caps_results *r)
{
	u32 a, b, c, d;

	__cpuid(0x14, 0, &a, &b, &c, &d);
	r->caps0[0] = a; r->caps0[1] = b; r->caps0[2] = c; r->caps0[3] = d;
	__cpuid(0x14, 1, &a, &b, &c, &d);
	r->caps1[0] = a; r->caps1[1] = b; r->caps1[2] = c; r->caps1[3] = d;
	r->pt_present = !!r->caps0[0];

	GUEST_DONE();
}

static void run_pinned(cpu_set_t *set, struct pt_caps_results *out)
{
	struct pt_caps_results *res_hva;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t res_gva;
	struct ucall uc;

	TEST_ASSERT(!sched_setaffinity(0, sizeof(*set), set),
		    "sched_setaffinity: %s", strerror(errno));

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);
	res_gva = vm_alloc(vm, sizeof(*res_hva), KVM_UTIL_MIN_VADDR);
	res_hva = addr_gva2hva(vm, res_gva);
	memset(res_hva, 0, sizeof(*res_hva));
	vcpu_args_set(vcpu, 1, res_gva);

	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_ASSERT(false, "Unexpected exit: %s",
			    exit_reason_str(vcpu->run->exit_reason));
	}

	memcpy(out, res_hva, sizeof(*out));
	kvm_vm_free(vm);
}

int main(void)
{
	struct pt_caps_results p, e;
	cpu_set_t p_set, e_set, all;

	TEST_REQUIRE(get_kvm_intel_param_integer("pt_mode") == 1);
	if (!hybrid_range("cpu_atom", &e_set)) {
		printf("SKIP: not a hybrid host (no cpu_atom PMU node)\n");
		exit(KSFT_SKIP);
	}
	if (!hybrid_range("cpu_core", &p_set)) {
		printf("SKIP: hybrid host has no cpu_core PMU node\n");
		exit(KSFT_SKIP);
	}

	run_pinned(&p_set, &p);
	run_pinned(&e_set, &e);

	/* Restore affinity for the rest of the process. */
	read_online_cpus(&all);
	sched_setaffinity(0, sizeof(all), &all);

	TEST_ASSERT(p.pt_present, "no guest PT caps on the P-core run");
	TEST_ASSERT(e.pt_present, "no guest PT caps on the E-core run");
	TEST_ASSERT(!memcmp(p.caps0, e.caps0, sizeof(p.caps0)) &&
		    !memcmp(p.caps1, e.caps1, sizeof(p.caps1)),
		    "PT caps differ between core types: "
		    "P 0x14.0 %x:%x:%x:%x 0x14.1 %x:%x:%x:%x, "
		    "E 0x14.0 %x:%x:%x:%x 0x14.1 %x:%x:%x:%x",
		    p.caps0[0], p.caps0[1], p.caps0[2], p.caps0[3],
		    p.caps1[0], p.caps1[1], p.caps1[2], p.caps1[3],
		    e.caps0[0], e.caps0[1], e.caps0[2], e.caps0[3],
		    e.caps1[0], e.caps1[1], e.caps1[2], e.caps1[3]);
	printf("PT caps (P==E): 0x14.0 %x:%x:%x:%x  0x14.1 %x:%x:%x:%x\n",
	       p.caps0[0], p.caps0[1], p.caps0[2], p.caps0[3],
	       p.caps1[0], p.caps1[1], p.caps1[2], p.caps1[3]);
	return 0;
}
