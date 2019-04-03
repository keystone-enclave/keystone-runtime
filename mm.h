#ifndef _MM_H_
#define _MM_H_

uintptr_t remap_physical_page(uintptr_t vpn, uintptr_t ppn, int flags);
size_t remap_physical_pages(uintptr_t vpn, uintptr_t ppn, size_t count, int flags);
uintptr_t translate(uintptr_t va);

uintptr_t alloc_page(uintptr_t vpn, int flags);
size_t alloc_pages(uintptr_t vpn, size_t count, int flags);
size_t try_alloc_pages_unused_only(uintptr_t vpn, size_t count, int flags);

uintptr_t get_program_break();
void set_program_break(uintptr_t new_break);
#endif /* _MM_H_ */
