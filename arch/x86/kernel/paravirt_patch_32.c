// SPDX-License-Identifier: GPL-2.0
#include <asm/paravirt.h>

#ifdef CONFIG_PARAVIRT_XXL
static const unsigned char patch_irq_irq_disable[] = { 0xfa }; 	  	/* cli */
static const unsigned char patch_irq_irq_enable[] = { 0xfb };  	  	/* sti */
static const unsigned char patch_irq_restore_fl[] =  { 0x50, 0x9d }; 	/* push %eax; popf */
static const unsigned char patch_irq_save_fl[] = { 0x9c, 0x58 };  	/* pushf; pop %eax */
static const unsigned char patch_cpu_iret[] = { 0xcf };		  	/* iret */
static const unsigned char patch_mmu_read_cr2[] = { 0x0f, 0x20, 0xd0 }; /* mov %cr2, %eax */
static const unsigned char patch_mmu_write_cr3[] = { 0x0f, 0x22, 0xd8 };/* mov %eax, %cr3 */
static const unsigned char patch_mmu_read_cr3[] = { 0x0f, 0x20, 0xd8 }; /* mov %cr3, %eax */

unsigned paravirt_patch_ident_64(void *insnbuf, unsigned len)
{
	/* arg in %edx:%eax, return in %edx:%eax */
	return 0;
}
#endif

#if defined(CONFIG_PARAVIRT_SPINLOCKS)
static const unsigned char patch_lock_queued_spin_unlock[] = { 0xc6, 0x00, 0x00 }; /* movb $0, (%eax) */
static const unsigned char patch_lock_vcpu_is_preempted[] =  { 0x31, 0xc0 }; 	 /* xor %eax, %eax */
#endif

extern bool pv_is_native_spin_unlock(void);
extern bool pv_is_native_vcpu_is_preempted(void);

unsigned native_patch(u8 type, void *ibuf, unsigned long addr, unsigned len)
{
#define PATCH_SITE(ops, x)					\
	case PARAVIRT_PATCH(ops.x):				\
		return paravirt_patch_insns(ibuf, len, 		\
				patch_##ops##_##x, patch_##ops##_##x+sizeof(patch_##ops##_x));

	switch (type) {
#ifdef CONFIG_PARAVIRT_XXL
		PATCH_SITE(irq, irq_disable);
		PATCH_SITE(irq, irq_enable);
		PATCH_SITE(irq, restore_fl);
		PATCH_SITE(irq, save_fl);
		PATCH_SITE(cpu, iret);
		PATCH_SITE(mmu, read_cr2);
		PATCH_SITE(mmu, read_cr3);
		PATCH_SITE(mmu, write_cr3);
#endif
#if defined(CONFIG_PARAVIRT_SPINLOCKS)
	case PARAVIRT_PATCH(lock.queued_spin_unlock):
		if (pv_is_native_spin_unlock())
			return paravirt_patch_insns(ibuf, len,
						    patch_lock_queued_spin_unlock,
						    patch_lock_queued_spin_unlock +
						    sizeof(patch_lock_queued_spin_unlock));
		break;

	case PARAVIRT_PATCH(lock.vcpu_is_preempted):
		if (pv_is_native_vcpu_is_preempted())
			return paravirt_patch_insns(ibuf, len,
						    patch_lock_vcpu_is_preempted,
						    patch_lock_vcpu_is_preempted +
						    sizeof(patch_lock_vcpu_is_preempted));
		break;
#endif

	default:
		break;
	}
#undef PATCH_SITE
	return paravirt_patch_default(type, ibuf, addr, len);
}
