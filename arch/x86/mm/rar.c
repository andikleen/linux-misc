/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RAR TLB shootdown
 */
#include <linux/sched.h>
#include <linux/bug.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/sync_bitops.h>
#include <asm/rar.h>
#include <asm/tlbflush.h>

static DEFINE_PER_CPU(struct cpumask, rar_cpu_mask);

#define RAR_SUCCESS	0x00
#define RAR_PENDING	0x01
#define RAR_FAILURE	0x80

#define RAR_MAX_PAYLOADS 64UL

/* How many RAR payloads are supported by this CPU */
static int rar_max_payloads __ro_after_init = RAR_MAX_PAYLOADS;

/*
 * RAR payloads telling CPUs what to do. This table is shared between
 * all CPUs; it is possible to have multiple payload tables shared between
 * different subsets of CPUs, but that adds a lot of complexity.
 */
static struct rar_payload rar_payload[RAR_MAX_PAYLOADS] __page_aligned_bss;

/*
 * Reduce contention for the RAR payloads by having a small number of
 * CPUs share a RAR payload entry, instead of a free for all with all CPUs.
 */
struct rar_lock {
	union {
		raw_spinlock_t lock;
		char __padding[SMP_CACHE_BYTES];
	};
};

static struct rar_lock rar_locks[RAR_MAX_PAYLOADS] __cacheline_aligned;

/*
 * The action vector tells each CPU which payload table entries
 * have work for that CPU.
 */
static DEFINE_PER_CPU_ALIGNED(u8[RAR_MAX_PAYLOADS], rar_action);

/*
 * TODO: group CPUs together based on locality in the system instead
 * of CPU number, to further reduce the cost of contention.
 */
static int cpu_rar_payload_number(void)
{
	int cpu = raw_smp_processor_id();
	return cpu % rar_max_payloads;
}

static int get_payload_slot(void)
{
	int payload_nr = cpu_rar_payload_number();
	raw_spin_lock(&rar_locks[payload_nr].lock);
	return payload_nr;
}

static void free_payload_slot(unsigned long payload_nr)
{
	raw_spin_unlock(&rar_locks[payload_nr].lock);
}

static void set_payload(struct rar_payload *p, u16 pcid, unsigned long start,
			long pages)
{
	p->must_be_zero_1	= 0;
	p->must_be_zero_2	= 0;
	p->must_be_zero_3	= 0;
	p->page_size		= RAR_INVLPG_PAGE_SIZE_4K;
	p->type			= RAR_TYPE_INVPCID;
	p->pcid			= pcid;
	p->linear_address	= start;

	if (pcid) {
		/* RAR invalidation of the mapping of a specific process. */
		if (pages < RAR_INVLPG_MAX_PAGES) {
			p->num_pages = pages;
			p->subtype = RAR_INVPCID_ADDR;
		} else {
			p->subtype = RAR_INVPCID_PCID;
		}
	} else {
		/*
		 * Unfortunately RAR_INVPCID_ADDR excludes global translations.
		 * Always do a full flush for kernel invalidations.
		 */
		p->subtype = RAR_INVPCID_ALL;
	}

	/* Ensure all writes are visible before the action entry is set. */
	smp_wmb();
}

static void set_action_entry(unsigned long payload_nr, int target_cpu)
{
	u8 *bitmap = per_cpu(rar_action, target_cpu);

	/*
	 * Given a remote CPU, "arm" its action vector to ensure it handles
	 * the request at payload_nr when it receives a RAR signal.
	 * The remote CPU will overwrite RAR_PENDING when it handles
	 * the request.
	 */
	WRITE_ONCE(bitmap[payload_nr], RAR_PENDING);
}

static void wait_for_action_done(unsigned long payload_nr, int target_cpu)
{
	u8 status;
	u8 *rar_actions = per_cpu(rar_action, target_cpu);

	status = READ_ONCE(rar_actions[payload_nr]);

	while (status == RAR_PENDING) {
		cpu_relax();
		status = READ_ONCE(rar_actions[payload_nr]);
	}

	WARN_ON_ONCE(rar_actions[payload_nr] != RAR_SUCCESS);
}

void rar_cpu_init(void)
{
	u8 *bitmap;
	u64 r;

	/* Check if this CPU was already initialized. */
	rdmsrl(MSR_IA32_RAR_PAYLOAD_BASE, r);
	if (r == (u64)virt_to_phys(rar_payload))
		return;

	bitmap = this_cpu_ptr(rar_action);
	memset(bitmap, 0, RAR_MAX_PAYLOADS);
	wrmsrl(MSR_IA32_RAR_ACT_VEC, (u64)virt_to_phys(bitmap));
	wrmsrl(MSR_IA32_RAR_PAYLOAD_BASE, (u64)virt_to_phys(rar_payload));

	/*
	 * Allow RAR events to be processed while interrupts are disabled on
	 * a target CPU. This prevents "pileups" where many CPUs are waiting
	 * on one CPU that has IRQs blocked for too long, and should reduce
	 * contention on the rar_payload table.
	 */
	wrmsrl(MSR_IA32_RAR_CTRL, RAR_CTRL_ENABLE | RAR_CTRL_IGNORE_IF);
}

void rar_boot_cpu_init(void)
{
	int max_payloads;
	u64 r;

	/* The MSR contains N defining the max [0-N] rar payload slots. */
	rdmsrl(MSR_IA32_RAR_INFO, r);
	max_payloads = (r >> 32) + 1;

	/* If this CPU supports less than RAR_MAX_PAYLOADS, lower our limit. */
	if (max_payloads < rar_max_payloads)
		rar_max_payloads = max_payloads;
	pr_info("RAR: support %d payloads\n", max_payloads);

	for (r = 0; r < rar_max_payloads; r++)
		rar_locks[r].lock = __RAW_SPIN_LOCK_UNLOCKED(rar_lock);

	/* Initialize the boot CPU early to handle early boot flushes. */
	rar_cpu_init();
}

/*
 * Inspired by smp_call_function_many(), but RAR requires a global payload
 * table rather than per-CPU payloads in the CSD table, because the action
 * handler is microcode rather than software.
 */
void smp_call_rar_many(const struct cpumask *mask, u16 pcid,
		       unsigned long start, unsigned long end)
{
	unsigned long pages = (end - start + PAGE_SIZE) / PAGE_SIZE;
	int cpu, this_cpu = smp_processor_id();
	cpumask_t *dest_mask;
	unsigned long payload_nr;

	/* Catch the "end - start + PAGE_SIZE" overflow above. */
	if (end == TLB_FLUSH_ALL)
		pages = RAR_INVLPG_MAX_PAGES + 1;

	/*
	 * Can deadlock when called with interrupts disabled.
	 * Allow CPUs that are not yet online though, as no one else can
	 * send smp call function interrupt to this CPU and as such deadlocks
	 * can't happen.
	 */
	if (cpu_online(this_cpu) && !oops_in_progress && !early_boot_irqs_disabled) {
		lockdep_assert_irqs_enabled();
		lockdep_assert_preemption_disabled();
	}

	/*
	 * A CPU needs to be initialized in order to process RARs.
	 * Skip offline CPUs.
	 *
	 * TODO:
	 * - Skip RAR to CPUs that are in a deeper C-state, with an empty TLB
	 *
	 * This code cannot use the should_flush_tlb() logic here because
	 * RAR flushes do not update the tlb_gen, resulting in unnecessary
	 * flushes at context switch time.
	 */
	dest_mask = this_cpu_ptr(&rar_cpu_mask);
	cpumask_and(dest_mask, mask, cpu_online_mask);

	/* Some callers race with other CPUs changing the passed mask */
	if (unlikely(!cpumask_weight(dest_mask)))
		return;

	payload_nr = get_payload_slot();
	set_payload(&rar_payload[payload_nr], pcid, start, pages);

	for_each_cpu(cpu, dest_mask)
		set_action_entry(payload_nr, cpu);

	/* Send a message to all CPUs in the map */
	native_send_rar_ipi(dest_mask);

	for_each_cpu(cpu, dest_mask)
		wait_for_action_done(payload_nr, cpu);

	free_payload_slot(payload_nr);
}
EXPORT_SYMBOL(smp_call_rar_many);
