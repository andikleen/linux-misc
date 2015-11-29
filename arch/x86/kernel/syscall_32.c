/* System call table for i386. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/syscalls.h>
#include <asm/syscalls.h>
#include <asm/asm-offsets.h>

#ifdef CONFIG_IA32_EMULATION
#include <linux/compat.h>
#include <asm/sys_ia32.h>
#define SYM(sym, compat) compat
#else
#define SYM(sym, compat) sym
#define ia32_sys_call_table sys_call_table
#define __NR_ia32_syscall_max __NR_syscall_max
#endif

#define __SYSCALL_I386(nr, sym, compat) [nr] = (sys_call_ptr_t)SYM(sym, compat),

typedef asmlinkage long int (*sys_call_ptr_t)(void);

extern asmlinkage long int sys_ni_syscall(void);

__visible const sys_call_ptr_t ia32_sys_call_table[__NR_ia32_syscall_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_ia32_syscall_max] = &sys_ni_syscall,
#include <asm/syscalls_32.h>
};
