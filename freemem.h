#include "vm.h"

#ifdef USE_FREEMEM

#ifndef __FREEMEM_H__
#define __FREEMEM_H__

#define NEXT_PAGE(page) *((uintptr_t*)page)
#define LIST_EMPTY(list) ((list).count == 0 || (list).head == 0)
#define LIST_INIT(list) { (list).count = 0; (list).head = 0; (list).tail = 0; }

// FIXME: see the comment above the usage of this function in freemem.c
extern void map_physical_memory(uintptr_t dram_base, uintptr_t dram_size);
void extend_physical_memory(uintptr_t pa, size_t size);

typedef struct pg_list_t
{
	uintptr_t head;
	uintptr_t tail;
	unsigned int count;
} pg_list_t;

/* freemem */
uintptr_t freemem_va_start;
size_t freemem_size;

void spa_init(uintptr_t base, size_t size);
uintptr_t spa_get(void);
void spa_put(uintptr_t page);
void spa_extend(uintptr_t base, size_t size);

#endif
#endif
