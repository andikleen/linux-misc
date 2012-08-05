#ifndef _ASM_GENERIC_SECTIONS_H_
#define _ASM_GENERIC_SECTIONS_H_

/* References to section boundaries */

extern __visible char _text[], _stext[], _etext[];
extern __visible char _data[], _sdata[], _edata[];
extern __visible char __bss_start[], __bss_stop[];
extern __visible char __init_begin[], __init_end[];
extern __visible char _sinittext[], _einittext[];
extern __visible char _end[];
extern __visible char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];
extern __visible char __kprobes_text_start[], __kprobes_text_end[];
extern __visible char __entry_text_start[], __entry_text_end[];
extern __visible char __initdata_begin[], __initdata_end[];
extern __visible char __start_rodata[], __end_rodata[];

/* Start and end of .ctors section - used for constructor calls. */
extern __visible char __ctors_start[], __ctors_end[];

/* function descriptor handling (if any).  Override
 * in asm/sections.h */
#ifndef dereference_function_descriptor
#define dereference_function_descriptor(p) (p)
#endif

/* random extra sections (if any).  Override
 * in asm/sections.h */
#ifndef arch_is_kernel_text
static inline int arch_is_kernel_text(unsigned long addr)
{
	return 0;
}
#endif

#ifndef arch_is_kernel_data
static inline int arch_is_kernel_data(unsigned long addr)
{
	return 0;
}
#endif

#endif /* _ASM_GENERIC_SECTIONS_H_ */
