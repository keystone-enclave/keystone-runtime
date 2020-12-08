#ifndef _MM_H_
#define _MM_H_
#include <stdint.h>
#include <stddef.h>


extern int victimized;
uintptr_t remap_physical_page(uintptr_t vpn, uintptr_t ppn, int flags);
size_t remap_physical_pages(uintptr_t vpn, uintptr_t ppn, size_t count, int flags);
uintptr_t translate(uintptr_t va);

uintptr_t alloc_page(uintptr_t vpn, int flags);
void free_page(uintptr_t vpn);
size_t alloc_pages(uintptr_t vpn, size_t count, int flags);
void free_pages(uintptr_t vpn, size_t count);
size_t test_va_range(uintptr_t vpn, size_t count);

uintptr_t get_program_break();
void set_program_break(uintptr_t new_break);
uintptr_t get_program_break_rt();
void set_program_break_rt(uintptr_t new_break);

uintptr_t* __walk_create(uintptr_t* root, uintptr_t addr);
//--------------my definitions--------------------

uintptr_t* get_root_page_table_addr();
//uintptr_t* __walk_during_page_fault(uintptr_t* root, uintptr_t addr);// delete this incase of failure
uintptr_t* __walk(uintptr_t* root, uintptr_t addr);// delete this incase of failure and make __walk in mm.c to static



#endif /* _MM_H_ */
