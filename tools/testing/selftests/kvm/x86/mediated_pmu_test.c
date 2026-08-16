// SPDX-License-Identifier: GPL-2.0-only
/*
 * mediated_pmu_test - the mediated vPMU: host-side refusal checks and
 * guest direct counter access on both hybrid core types.
 *
 * Host side: with the mediated PMU enabled, KVM refuses vCPU creation while
 * a host perf event without exclude_guest exists (PERF_MEDIATED_PMU_MSG,
 * -EBUSY); releasing the event unblocks it.  The nmi_watchdog variant is
 * checked when the watchdog is on, or toggled when running as root.
 *
 * Guest side: the guest reads CPUID 0xA and programs GP counter 0 via
 * direct MSR writes.  With the vCPU pinned to P-cores and to E-cores the
 * counter must increment on both, and the CPUID caps must match.
 *
 * --migrate: count while the host migrates the vCPU thread across all
 * online CPUs (hybrid core-type crossings).  Works under either module
 * state: with the mediated PMU the passthrough counters survive the
 * put/load across migrations; without it the emulated counters are
 * dropped and recreated for the new core type (hybrid_rebind).
 *
 * SKIPs when the mediated PMU is not enabled (default mode only).
 */
#include <asm/msr-index.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "hybrid_util.h"

#ifndef GP_VECTOR
#define GP_VECTOR 13
#endif

#define COUNT_CYCLES	(2ULL * 1000 * 1000 * 1000)	/* ~0.7 s */
#define MIGRATE_CYCLES	(2ULL * 1000 * 1000 * 1000)	/* ~0.7 s */

struct pmu_guest_results {
	u32 eax, ebx, ecx, edx;	/* CPUID.0xA */
	u32 gp_msr;		/* #GP on a PMU MSR write */
	u32 gp_msr_index;	/* ECX of the faulting WRMSR */
	u64 count;		/* GP counter 0 after the busy loop */
	u32 done;
};

static struct pmu_guest_results *res;

static void guest_gp_handler(struct ex_regs *regs)
{
	res->gp_msr = 1;
	res->gp_msr_index = regs->rcx;
	regs->rip += 2;		/* skip the WRMSR that faulted */
}

static void guest_main(struct pmu_guest_results *r, u64 cycles)
{
	u32 a, b, c, d;

	res = r;

	__cpuid(0xA, 0, &a, &b, &c, &d);
	res->eax = a; res->ebx = b; res->ecx = c; res->edx = d;

	/* General-purpose counter 0 (core cycles): program the event
	 * select, clear the counter, enable via GLOBAL_CTRL.  GP counters
	 * are passed through under the mediated PMU. */
	wrmsr(MSR_IA32_PERFCTR0, 0);
	wrmsr(MSR_P6_EVNTSEL0, 0x3c | (1ULL << 22) | (1ULL << 17) | (1ULL << 16));
	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, BIT(0));

	/* The mediated PMU applies the emulated event select at the next
	 * vcpu_run boundary (kvm_mediated_pmu_load); force an exit so the
	 * counter is actually enabled before the busy loop.  Note: with the
	 * freestanding direct-MSR path the count reflects only a short run
	 * segment (the emulated EVNTSEL is re-applied at each run boundary);
	 * the assertion is that the passthrough counter increments, not that
	 * it tracks the full loop. */
	GUEST_SYNC(1);

	busy_loop(cycles);

	res->count = rdmsr(MSR_IA32_PERFCTR0);
	res->done = 1;
	GUEST_DONE();
}

/*
 * Create a VM with an in-kernel irqchip and one vCPU; the mediated-PMU
 * creation check only applies to in-kernel-irqchip VMs.  Returns 0 or -errno.
 */
static int create_vcpu(void)
{
	int kvm_fd = open("/dev/kvm", O_RDWR);
	int vmfd, r;

	TEST_ASSERT(kvm_fd >= 0, "open /dev/kvm: %s", strerror(errno));
	vmfd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	TEST_ASSERT(vmfd >= 0, "KVM_CREATE_VM: %s", strerror(errno));
	TEST_ASSERT(!ioctl(vmfd, KVM_CREATE_IRQCHIP, 0),
		    "KVM_CREATE_IRQCHIP: %s", strerror(errno));
	r = ioctl(vmfd, KVM_CREATE_VCPU, 0);
	if (r < 0) {
		int e = errno;

		close(vmfd);
		close(kvm_fd);
		return -e;
	}
	close(vmfd);
	close(kvm_fd);
	return 0;
}

static int nmi_watchdog_get(void)
{
	char buf[8];
	int fd = open("/proc/sys/kernel/nmi_watchdog", O_RDONLY);
	ssize_t r;

	TEST_ASSERT(fd >= 0, "open nmi_watchdog: %s", strerror(errno));
	r = read(fd, buf, sizeof(buf) - 1);
	TEST_ASSERT(r > 0, "read nmi_watchdog");
	close(fd);
	buf[r] = '\0';
	return atoi(buf);
}

static bool nmi_watchdog_set(int v)
{
	char buf[2];
	int fd = open("/proc/sys/kernel/nmi_watchdog", O_WRONLY);
	ssize_t r;

	if (fd < 0)
		return false;
	buf[0] = '0' + v;
	buf[1] = '\0';
	r = write(fd, buf, 1);
	close(fd);
	return r == 1;
}

static int wd_saved = -1;

static void restore_nmi_watchdog(void)
{
	if (wd_saved >= 0)
		nmi_watchdog_set(wd_saved);
}

static void test_host_creation_checks(void)
{
	struct perf_event_attr attr = { 0 };
	int fd, r;

	/*
	 * The mediated PMU is unusable while the host NMI watchdog is on:
	 * its include_guest events keep nr_include_guest_events > 0, so every
	 * mediated vCPU creation fails with -EBUSY.  If root, toggle it off
	 * for the tests below and restore on exit; otherwise skip.
	 */
	wd_saved = nmi_watchdog_get();
	atexit(restore_nmi_watchdog);
	if (wd_saved == 1) {
		if (geteuid() != 0 || !nmi_watchdog_set(0)) {
			printf("SKIP: nmi_watchdog on; the mediated PMU needs it off (run as root)\n");
			exit(KSFT_SKIP);
		}
	}

	/* A host perf event without exclude_guest must block the first
	 * mediated VM's vCPU creation; releasing it must unblock. */
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
	if (fd < 0) {
		printf("SKIP: perf_event_open: %s (perf_event_paranoid?)\n",
		       strerror(errno));
		exit(KSFT_SKIP);
	}
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	usleep(100 * 1000);

	r = create_vcpu();
	TEST_ASSERT(r == -EBUSY,
		    "vCPU creation with include_guest event: got %d (want -EBUSY)", r);

	close(fd);
	usleep(100 * 1000);
	r = create_vcpu();
	TEST_ASSERT(r == 0,
		    "vCPU creation after event release: got %d (want 0)", r);

	/* Watchdog case: vCPU creation must be refused with -EBUSY while the
	 * watchdog is on (root). */
	if (geteuid() == 0 && nmi_watchdog_set(1)) {
		r = create_vcpu();
		TEST_ASSERT(r == -EBUSY,
			    "vCPU creation with nmi_watchdog on: got %d (want -EBUSY)", r);
		nmi_watchdog_set(0);
		r = create_vcpu();
		TEST_ASSERT(r == 0,
			    "vCPU creation after watchdog off: got %d (want 0)", r);
	} else {
		printf("watchdog-on check skipped (needs root)\n");
	}
}

static void run_guest_pinned(cpu_set_t *set, struct pmu_guest_results *out)
{
	struct pmu_guest_results *res_hva;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t res_gva;
	struct ucall uc;

	TEST_ASSERT(!sched_setaffinity(0, sizeof(*set), set),
		    "sched_setaffinity: %s", strerror(errno));

	/* __vm_create() already installs an in-kernel irqchip (x86
	 * kvm_arch_vm_post_create), which the mediated-PMU path requires. */
	vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
	vcpu = vm_vcpu_add(vm, 0, guest_main);

	res_gva = vm_alloc(vm, sizeof(*res_hva), KVM_UTIL_MIN_VADDR);
	res_hva = addr_gva2hva(vm, res_gva);
	memset(res_hva, 0, sizeof(*res_hva));
	vm_install_exception_handler(vm, GP_VECTOR, guest_gp_handler);
	vcpu_args_set(vcpu, 2, res_gva, COUNT_CYCLES);

	vcpu_run(vcpu);
	for (;;) {
		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			vcpu_run(vcpu);
			break;
		case UCALL_DONE:
			goto done;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		default:
			TEST_ASSERT(false, "Unexpected exit: %s",
				    exit_reason_str(vcpu->run->exit_reason));
		}
	}
done:

	memcpy(out, res_hva, sizeof(*out));
	kvm_vm_free(vm);
}

/* Count while the host migrates the vCPU thread between a P-core and an
 * E-core (alternating, one hop per 100 ms).  Works under either module
 * state: mediated passthrough counters survive the put/load, emulated
 * counters are rebound to the new core type. */
static void run_guest_migrating(void)
{
	struct pmu_guest_results *res_hva, res;
	struct vcpu_migrate_ctx ctx = { .iters = 14 };
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	pthread_t th, mth;
	cpu_set_t p_set, e_set;
	gva_t res_gva;
	struct ucall uc;
	int i, n = 0;

	/* Two CPUs suffice for the coverage: one of each core type. */
	if (hybrid_range("cpu_core", &p_set) && hybrid_range("cpu_atom", &e_set)) {
		for (i = 0; i < CPU_SETSIZE && !CPU_ISSET(i, &p_set); i++)
			;
		if (i < CPU_SETSIZE) {
			ctx.cpus[n++] = i;
			for (i = 0; i < CPU_SETSIZE && !CPU_ISSET(i, &e_set); i++)
				;
			if (i < CPU_SETSIZE)
				ctx.cpus[n++] = i;
		}
	}
	if (n < 2)
		n = vcpu_migrate_ctx_init(&ctx);
	ctx.ncpus = n;

	vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
	vcpu = vm_vcpu_add(vm, 0, guest_main);
	res_gva = vm_alloc(vm, sizeof(*res_hva), KVM_UTIL_MIN_VADDR);
	res_hva = addr_gva2hva(vm, res_gva);
	memset(res_hva, 0, sizeof(*res_hva));
	vm_install_exception_handler(vm, GP_VECTOR, guest_gp_handler);
	vcpu_args_set(vcpu, 2, res_gva, MIGRATE_CYCLES);

	ctx.vcpu = vcpu;
	pthread_create(&th, NULL, vcpu_run_thread, &ctx);
	while (!ctx.tid)
		usleep(1000);
	pthread_create(&mth, NULL, vcpu_migrator_thread, &ctx);
	pthread_join(mth, NULL);
	pthread_join(th, NULL);

	for (;;) {
		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			vcpu_run(vcpu);
			break;
		case UCALL_DONE:
			goto done;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		default:
			TEST_ASSERT(false, "Unexpected exit: %s",
				    exit_reason_str(vcpu->run->exit_reason));
		}
	}
done:
	memcpy(&res, res_hva, sizeof(res));
	kvm_vm_free(vm);

	TEST_ASSERT(res.done, "guest did not finish");
	TEST_ASSERT(!res.gp_msr,
		    "#GP on guest PMU MSR write (ECX=%x)", res.gp_msr_index);
	TEST_ASSERT(res.count > 1000000,
		    "count %lu across migration (want > 1000000)",
		    res.count);
	printf("guest PMU count across migration: %lu\n", res.count);
}

int main(int argc, char *argv[])
{
	struct pmu_guest_results p, e;
	cpu_set_t p_set, e_set, all;
	bool migrate = argc > 1 && !strcmp(argv[1], "--migrate");
	bool hybrid;

	TEST_REQUIRE(kvm_is_pmu_enabled());
	if (!migrate)
		TEST_REQUIRE(get_kvm_intel_param_bool("enable_mediated_pmu"));
	TEST_REQUIRE(this_cpu_is_intel());

	if (migrate) {
		run_guest_migrating();
		return 0;
	}

	test_host_creation_checks();

	if (!hybrid_range("cpu_core", &p_set)) {
		printf("no cpu_core PMU node; using all online CPUs for the P-core run\n");
		read_online_cpus(&p_set);
	}
	hybrid = hybrid_range("cpu_atom", &e_set);

	run_guest_pinned(&p_set, &p);
	if (hybrid)
		run_guest_pinned(&e_set, &e);

	read_online_cpus(&all);
	sched_setaffinity(0, sizeof(all), &all);

	printf("guest PMU caps P: CPUID.0xA %x:%x:%x:%x count %lu\n",
	       p.eax, p.ebx, p.ecx, p.edx, p.count);
	TEST_ASSERT(p.done, "guest did not finish");
	TEST_ASSERT(!p.gp_msr,
		    "#GP on guest PMU MSR write (ECX=%x)", p.gp_msr_index);
	TEST_ASSERT(p.count > 0, "no count with vCPU on P-cores");

	if (hybrid) {
		printf("guest PMU caps E: CPUID.0xA %x:%x:%x:%x count %lu\n",
		       e.eax, e.ebx, e.ecx, e.edx, e.count);
		TEST_ASSERT(!memcmp(&p.eax, &e.eax, 16),
			    "guest PMU caps differ P vs E");
		TEST_ASSERT(!e.gp_msr, "#GP on guest PMU MSR write (E)");
		TEST_ASSERT(e.count > 0,
			    "no count with vCPU on E-cores (mediated direct access)");
	} else {
		printf("not hybrid; E-core run skipped\n");
	}
	return 0;
}
