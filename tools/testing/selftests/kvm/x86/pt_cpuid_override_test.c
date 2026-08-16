// SPDX-License-Identifier: GPL-2.0-only
/*
 * pt_cpuid_override_test - verify KVM sanitizes guest CPUID leaf 0x14
 * (Intel PT) against host capabilities.
 *
 * A VMM can over-enumerate leaf 0x14 via KVM_SET_CPUID2 (e.g.
 * more address ranges than any CPU supports).  Un-sanitized, that makes KVM
 * save/load and passthrough non-existent RTIT MSRs (host #GP / WARNs) and
 * lets the guest program MSRs that are not on the hardware.
 *
 * Test:
 *  1. Inflate leaf 0x14 (subleaves 0 and 1, all registers all-ones, i.e.
 *     num_address_ranges = 7) and request INTEL_PT (leaf 7 EBX bit 25)
 *     via KVM_SET_CPUID2.
 *  2. Host side: KVM_GET_CPUID2 must show the caps bounded to the host's
 *     supported set - update_intel_pt_cfg() intersects with the host common
 *     subset (vmx_pt_host_caps) and writes the result back into the vCPU
 *     CPUID.  No bit may be set that the host CPU does not support.
 *  3. Guest side: read back CPUID 0x14, then write the RTIT_ADDRn MSR at
 *     the first out-of-range index (n = guest_ranges) - must #GP.  An
 *     in-range write (ADDR0) must not fault.
 *
 * Requires host-guest PT mode (kvm_intel pt_mode=1).  SKIPs otherwise: in
 * SYSTEM mode KVM reports leaf 0x14 zeroed in KVM_GET_SUPPORTED_CPUID.
 */
#include <stdint.h>
#include <asm/msr-index.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#ifndef GP_VECTOR
#define GP_VECTOR 13
#endif

struct pt_guest_results {
	u32 caps0[4];	/* CPUID.0x14.0 eax ebx ecx edx as seen by the guest */
	u32 caps1[4];	/* CPUID.0x14.1 ... */
	u32 ranges;	/* caps1[0] & 0x7 */
	int gp_inrange;	/* 1 if #GP fired on the in-range ADDR0 write */
	int gp_oor;	/* 1 if #GP fired on the out-of-range ADDRn write */
};

static struct pt_guest_results *res;
static bool expect_gp;

static void guest_gp_handler(struct ex_regs *regs)
{
	if (expect_gp)
		res->gp_oor = 1;
	else
		res->gp_inrange = 1;
	/* skip the 2-byte WRMSR that faulted */
	regs->rip += 2;
}

static void guest_main(struct pt_guest_results *r)
{
	u32 a, b, c, d;

	res = r;

	__cpuid(0x14, 0, &a, &b, &c, &d);
	res->caps0[0] = a; res->caps0[1] = b; res->caps0[2] = c; res->caps0[3] = d;

	__cpuid(0x14, 1, &a, &b, &c, &d);
	res->caps1[0] = a; res->caps1[1] = b; res->caps1[2] = c; res->caps1[3] = d;
	res->ranges = a & 0x7;

	if (res->ranges) {
		expect_gp = false;
		wrmsr(MSR_IA32_RTIT_ADDR0_A, 0x1000);

		expect_gp = true;
		wrmsr(MSR_IA32_RTIT_ADDR0_A + 2 * res->ranges, 0x1000);
	}

	GUEST_DONE();
}

static struct kvm_cpuid_entry2 *find_entry(struct kvm_cpuid2 *cpuid,
					   u32 function, u32 index)
{
	int i;

	for (i = 0; i < cpuid->nent; i++)
		if (cpuid->entries[i].function == function &&
		    cpuid->entries[i].index == index)
			return &cpuid->entries[i];
	return NULL;
}

static void check_subset(const struct kvm_cpuid_entry2 *guest,
			 const struct kvm_cpuid_entry2 *host, int subleaf)
{
	TEST_ASSERT(guest && host,
		    "leaf 0x14.%d missing after KVM_SET_CPUID2", subleaf);
	TEST_ASSERT(!(guest->eax & ~host->eax) && !(guest->ebx & ~host->ebx) &&
		    !(guest->ecx & ~host->ecx) && !(guest->edx & ~host->edx),
		    "guest PT caps over-enumerate host: 0x14.%d "
		    "guest %x:%x:%x:%x host %x:%x:%x:%x",
		    subleaf,
		    guest->eax, guest->ebx, guest->ecx, guest->edx,
		    host->eax, host->ebx, host->ecx, host->edx);
}

int main(void)
{
	struct pt_guest_results *res_hva;
	const struct kvm_cpuid_entry2 *host_pt0, *host_pt1, *e;
	struct kvm_cpuid_entry2 *new_pt0, *new_pt1, *e7;
	struct kvm_cpuid2 *cpuid;
	const struct kvm_cpuid2 *supported;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t res_gva;
	struct ucall uc;
	u32 host_ranges;
	int i;

	/*
	 * SYSTEM mode (or a pre-fix kernel) reports leaf 0x14 all-zero in
	 * KVM_GET_SUPPORTED_CPUID; the sanitization path under test only
	 * exists with pt_mode=1 (host-guest).  SKIP, don't fail.  Scan the
	 * entries manually - get_cpuid_entry() asserts when the leaf is gone.
	 */
	supported = kvm_get_supported_cpuid();
	host_pt0 = NULL;
	for (i = 0; i < supported->nent; i++)
		if (supported->entries[i].function == 0x14 &&
		    supported->entries[i].index == 0)
			host_pt0 = &supported->entries[i];
	if (!host_pt0 || !host_pt0->eax) {
		printf("SKIP: host exposes no guest PT (kvm_intel pt_mode=1 required)\n");
		exit(KSFT_SKIP);
	}
	host_pt1 = get_cpuid_entry(supported, 0x14, 1);
	host_ranges = host_pt1->eax & 0x7;
	printf("host PT caps: 0x14.0 %x:%x:%x:%x  0x14.1 %x:%x:%x:%x  ranges=%u\n",
	       host_pt0->eax, host_pt0->ebx, host_pt0->ecx, host_pt0->edx,
	       host_pt1->eax, host_pt1->ebx, host_pt1->ecx, host_pt1->edx,
	       host_ranges);

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);

	/* Build the inflated CPUID: default entries + leaf 7 INTEL_PT, then
	 * inflate the existing leaf 0x14 entries in place (the default CPUID
	 * already carries them, and KVM + get_cpuid_entry() use first-match,
	 * so appended duplicates would never be seen). */
	cpuid = allocate_kvm_cpuid2(vcpu->cpuid->nent);
	memcpy(cpuid, vcpu->cpuid,
	       sizeof(*cpuid) + vcpu->cpuid->nent * sizeof(cpuid->entries[0]));
	cpuid->nent = vcpu->cpuid->nent;

	e7 = find_entry(cpuid, 7, 0);
	TEST_ASSERT(e7, "leaf 7 missing from default CPUID");
	e7->ebx |= BIT(25);	/* X86_FEATURE_INTEL_PT */

	/* Inflate: every register all-ones (num_address_ranges = 7, etc.). */
	new_pt0 = find_entry(cpuid, 0x14, 0);
	new_pt1 = find_entry(cpuid, 0x14, 1);
	TEST_ASSERT(new_pt0 && new_pt1, "leaf 0x14 missing from default CPUID");
	for (i = 0; i < 2; i++) {
		struct kvm_cpuid_entry2 *n = i ? new_pt1 : new_pt0;

		n->eax = n->ebx = n->ecx = n->edx = 0xffffffff;
	}

	/* Set; vcpu_set_cpuid() refreshes the cache via KVM_GET_CPUID2. */
	free(vcpu->cpuid);
	vcpu->cpuid = cpuid;
	vcpu_set_cpuid(vcpu);

	/* Host-side sanitization checks on the refreshed vCPU CPUID. */
	e = get_cpuid_entry(vcpu->cpuid, 0x14, 0);
	check_subset(e, host_pt0, 0);
	e = get_cpuid_entry(vcpu->cpuid, 0x14, 1);
	check_subset(e, host_pt1, 1);
	TEST_ASSERT((e->eax & 0x7) <= host_ranges,
		    "sanitized address ranges %u exceed host's %u",
		    e->eax & 0x7, host_ranges);
	if (host_ranges < 7)
		TEST_ASSERT((e->eax & 0x7) < 7,
			    "inflated ranges (7) not bounded; sanitization did not run");
	printf("sanitized guest PT caps: 0x14.0 %x:%x:%x:%x  0x14.1 %x:%x:%x:%x  ranges=%u\n",
	       get_cpuid_entry(vcpu->cpuid, 0x14, 0)->eax,
	       get_cpuid_entry(vcpu->cpuid, 0x14, 0)->ebx,
	       get_cpuid_entry(vcpu->cpuid, 0x14, 0)->ecx,
	       get_cpuid_entry(vcpu->cpuid, 0x14, 0)->edx,
	       e->eax, e->ebx, e->ecx, e->edx, e->eax & 0x7);

	/* Guest-side behavioral check: out-of-range ADDRn write must #GP. */
	res_gva = vm_alloc(vm, sizeof(*res_hva), KVM_UTIL_MIN_VADDR);
	res_hva = addr_gva2hva(vm, res_gva);
	memset(res_hva, 0, sizeof(*res_hva));
	vm_install_exception_handler(vm, GP_VECTOR, guest_gp_handler);
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

	/* Guest's own CPUID view must match the sanitized vCPU CPUID. */
	TEST_ASSERT(res_hva->caps0[0] == get_cpuid_entry(vcpu->cpuid, 0x14, 0)->eax &&
		    res_hva->caps1[0] == e->eax,
		    "guest saw different caps than KVM_GET_CPUID2: "
		    "guest %x:%x vs %x:%x",
		    res_hva->caps0[0], res_hva->caps1[0],
		    get_cpuid_entry(vcpu->cpuid, 0x14, 0)->eax, e->eax);
	TEST_ASSERT(res_hva->ranges == (e->eax & 0x7),
		    "guest ranges %u != sanitized ranges %u",
		    res_hva->ranges, e->eax & 0x7);
	TEST_ASSERT(!res_hva->gp_inrange,
		    "#GP on in-range ADDR0 write (ranges=%u)", res_hva->ranges);
	TEST_ASSERT(res_hva->gp_oor,
		    "no #GP on out-of-range RTIT_ADDR write: non-existent "
		    "MSR reachable");

	kvm_vm_free(vm);
	return 0;
}
