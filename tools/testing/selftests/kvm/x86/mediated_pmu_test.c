// SPDX-License-Identifier: GPL-2.0-only
/*
 * mediated_pmu_test - mediated vPMU: host refusal checks and guest
 * direct counter access on P/E cores.  vCPU creation fails -EBUSY while
 * a host event without exclude_guest (or the NMI watchdog) is active.
 * Guest counters must increment, incl. --migrate; SKIPs if PMU is off.
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

#define COUNT_CYCLES	(2ULL * 1000 * 1000 * 1000)	/* ~0.7 s of ~2.9 GHz TSC */
#define MIGRATE_CYCLES	(2ULL * 1000 * 1000 * 1000)	/* dito. */

struct pmu_guest_results {
	u32 eax, ebx, ecx, edx;	/* CPUID.0xA */
	u32 gp_msr;		/* #GP on a PMU MSR write */
	u32 gp_msr_index;	/* ECX of the faulting WRMSR */
	u64 count;		/* GP counter 0 after the busy loop */
	u64 fixed_count;	/* fixed counter 1 after the busy loop */
	u64 rb_fixed_ctrl, rb_global;	/* read back after the sync */
	u64 hw_evtsel0, hw_evtsel0_rb;	/* EVNTSEL0 read-XOR-write-read-back */
	u64 hw_perfctr0, hw_perfctr0_rb;/* PERFCTR0 read-XOR-write-read-back */
	u64 hw_fixed_ctrl;		/* FIXED_CTR_CTRL read */
	u32 hw_evtsel0_match, hw_perfctr0_match, hw_fixed_match;
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

	/*
	 * Guest-kernel check_hw_exists() round-trips (read, XOR 0xffff,
	 * write back, re-read); a T10 E-core mismatch broke PMU init.
	 */
	{
		u64 v;

		res->hw_evtsel0 = rdmsr(MSR_P6_EVNTSEL0);
		v = res->hw_evtsel0 ^ 0xffff;
		wrmsr(MSR_P6_EVNTSEL0, v);
		res->hw_evtsel0_rb = rdmsr(MSR_P6_EVNTSEL0);
		res->hw_evtsel0_match = (res->hw_evtsel0_rb == v);

		res->hw_perfctr0 = rdmsr(MSR_IA32_PERFCTR0);
		v = res->hw_perfctr0 ^ 0xffff;
		wrmsr(MSR_IA32_PERFCTR0, v);
		res->hw_perfctr0_rb = rdmsr(MSR_IA32_PERFCTR0);
		res->hw_perfctr0_match = (res->hw_perfctr0_rb == v);

		res->hw_fixed_ctrl = rdmsr(MSR_CORE_PERF_FIXED_CTR_CTRL);
		res->hw_fixed_match = !(res->hw_fixed_ctrl & 0x3);
	}

	/*
	 * GP counter 0 (core cycles): program event select, clear, enable
	 * via GLOBAL_CTRL.  GP counters pass through the mediated PMU.
	 */
	wrmsr(MSR_IA32_PERFCTR0, 0);
	wrmsr(MSR_P6_EVNTSEL0, 0x3c | (1ULL << 22) | (1ULL << 17) | (1ULL << 16));

	/*
	 * Fixed counter 1 (core cycles): EN|OS in FIXED_CTR_CTRL, clear,
	 * enable via GLOBAL_CTRL bit 32+1 (fixed counters are bits 32..).
	 */
	wrmsr(MSR_CORE_PERF_FIXED_CTR_CTRL, (1ULL << 4) | (1ULL << 5));
	wrmsr(MSR_CORE_PERF_FIXED_CTR1, 0);
	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, BIT(0) | BIT(33));

	/*
	 * Force an exit so the mediated PMU applies the event select before
	 * the busy loop; the count only needs to show an increment.
	 */
	GUEST_SYNC(1);

	/* Read back the MSRs after the sync. */
	res->rb_fixed_ctrl = rdmsr(MSR_CORE_PERF_FIXED_CTR_CTRL);
	res->rb_global = rdmsr(MSR_CORE_PERF_GLOBAL_CTRL);

	busy_loop(cycles);

	res->count = rdmsr(MSR_IA32_PERFCTR0);
	res->fixed_count = rdmsr(MSR_CORE_PERF_FIXED_CTR1);
	res->done = 1;
	GUEST_DONE();
}

/*
 * Create a VM with an in-kernel irqchip and one vCPU; the mediated-PMU
 * creation check only applies to such VMs.  Returns 0 or -errno.
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
	 * The NMI watchdog's include_guest events block mediated vCPU
	 * creation; toggle it off (root), restore on exit, else skip.
	 */
	wd_saved = nmi_watchdog_get();
	atexit(restore_nmi_watchdog);
	if (wd_saved == 1) {
		if (geteuid() != 0 || !nmi_watchdog_set(0)) {
			printf("SKIP: nmi_watchdog on; the mediated PMU needs it off (run as root)\n");
			exit(KSFT_SKIP);
		}
	}

	/*
	 * A host perf event without exclude_guest must block the first
	 * mediated VM's vCPU creation; releasing it must unblock.
	 */
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

	/* vCPU creation must fail -EBUSY while the watchdog is on (root). */
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

	/* __vm_create() installs the in-kernel irqchip the mediated PMU needs. */
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

/*
 * Count while migrating the vCPU between a P-core and an E-core (one hop
 * per 100 ms); passthrough counters survive put/load, emulated rebind.
 */
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
	TEST_ASSERT(res.fixed_count > 0,
		    "no fixed-counter count across migration");
	printf("guest PMU count across migration: %lu (fixed %lu)\n",
	       res.count, res.fixed_count);
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

	printf("guest PMU caps P: CPUID.0xA %x:%x:%x:%x count %lu fixed %lu (ctrl %lx global %lx)\n",
	       p.eax, p.ebx, p.ecx, p.edx, p.count, p.fixed_count,
	       p.rb_fixed_ctrl, p.rb_global);
	printf("check_hw_exists P: evtsel0 %lx->%lx match=%u perfctr0 %lx->%lx match=%u fixed %lx match=%u\n",
	       p.hw_evtsel0, p.hw_evtsel0_rb, p.hw_evtsel0_match,
	       p.hw_perfctr0, p.hw_perfctr0_rb, p.hw_perfctr0_match,
	       p.hw_fixed_ctrl, p.hw_fixed_match);
	TEST_ASSERT(p.done, "guest did not finish");
	TEST_ASSERT(!p.gp_msr,
		    "#GP on guest PMU MSR write (ECX=%x)", p.gp_msr_index);
	TEST_ASSERT(p.count > 0, "no count with vCPU on P-cores");
	TEST_ASSERT(p.fixed_count > 0, "no fixed-counter count with vCPU on P-cores");
	TEST_ASSERT(p.hw_evtsel0_match && p.hw_perfctr0_match && p.hw_fixed_match,
		    "check_hw_exists-style round-trip mismatch on P (evtsel %lx->%lx perfctr %lx->%lx fixed %lx)",
		    p.hw_evtsel0, p.hw_evtsel0_rb,
		    p.hw_perfctr0, p.hw_perfctr0_rb, p.hw_fixed_ctrl);

	if (hybrid) {
		printf("guest PMU caps E: CPUID.0xA %x:%x:%x:%x count %lu fixed %lu\n",
		       e.eax, e.ebx, e.ecx, e.edx, e.count, e.fixed_count);
		printf("check_hw_exists E: evtsel0 %lx->%lx match=%u perfctr0 %lx->%lx match=%u fixed %lx match=%u\n",
		       e.hw_evtsel0, e.hw_evtsel0_rb, e.hw_evtsel0_match,
		       e.hw_perfctr0, e.hw_perfctr0_rb, e.hw_perfctr0_match,
		       e.hw_fixed_ctrl, e.hw_fixed_match);
		TEST_ASSERT(!memcmp(&p.eax, &e.eax, 16),
			    "guest PMU caps differ P vs E");
		TEST_ASSERT(!e.gp_msr, "#GP on guest PMU MSR write (E)");
		TEST_ASSERT(e.count > 0,
			    "no count with vCPU on E-cores (mediated direct access)");
		TEST_ASSERT(e.fixed_count > 0,
			    "no fixed-counter count with vCPU on E-cores");
		TEST_ASSERT(e.hw_evtsel0_match && e.hw_perfctr0_match && e.hw_fixed_match,
			    "check_hw_exists-style round-trip mismatch on E (evtsel %lx->%lx perfctr %lx->%lx fixed %lx)",
			    e.hw_evtsel0, e.hw_evtsel0_rb,
			    e.hw_perfctr0, e.hw_perfctr0_rb, e.hw_fixed_ctrl);
	} else {
		printf("not hybrid; E-core run skipped\n");
	}
	return 0;
}
