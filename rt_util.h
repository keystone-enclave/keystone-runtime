#ifndef _RT_UTIL_H_
#define _RT_UTIL_H_

#include "regs.h"
#include <stddef.h>
#include "vm.h"

#define FATAL_DEBUG

size_t rt_util_getrandom(void* vaddr, size_t buflen);
void not_implemented_fatal(struct encl_ctx_t* ctx);
void rt_util_misc_fatal();

extern unsigned char rt_copy_buffer_1[RISCV_PAGE_SIZE];
extern unsigned char rt_copy_buffer_2[RISCV_PAGE_SIZE];

#endif /* _RT_UTIL_H_ */
