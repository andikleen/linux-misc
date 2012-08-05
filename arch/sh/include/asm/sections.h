#ifndef __ASM_SH_SECTIONS_H
#define __ASM_SH_SECTIONS_H

#include <asm-generic/sections.h>

extern __visible long __nosave_begin, __nosave_end;
extern __visible long __machvec_start, __machvec_end;
extern __visible char __uncached_start, __uncached_end;
extern __visible char _ebss[];
extern __visible char __start_eh_frame[], __stop_eh_frame[];

#endif /* __ASM_SH_SECTIONS_H */

