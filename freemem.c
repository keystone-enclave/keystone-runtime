#ifdef USE_FREEMEM
#include "common.h"
#include "vm.h"
#include "freemem.h"
#include "sbi.h"

/* This file implements a simple page allocator (SPA)
 * which stores the pages based on a linked list.
 * Each of the element of linked list is stored in the header of each free page.

 * SPA does not use any additional data structure (e.g., linked list).
 * Instead, it uses the pages themselves to store the linked list pointer.
 * Thus, each of the free pages contains the pointer to the next free page
 * which can be dereferenced by NEXT_PAGE() macro.
 * spa_free_pages will only hold the head and the tail pages so that
 * SPA can allocate/free a page in constant time. */

static pg_list_t spa_free_pages;

/* extend the size of DRAM */
// TODO: currently, this function does not fail.
// we need to handle error (make it return size of memory that was actually extended)
void extend_physical_memory(uintptr_t pa, size_t size)
{
  //size_t extended = 0;

  /* See if the physical address does not overlap */
  assert((pa + size) <= load_pa_start &&
          pa >= (load_pa_start + load_pa_size));

  // TODO: need to also check with UTM

  // FIXME: we only allow extending the current EPM tail at this moment
  assert( pa == (load_pa_start + load_pa_size));

  // extend the physical memory
  load_pa_size += size;

  /* FIXME: we borrow and reuse exactly the same function
   * that we used during boot.
   * This is not a good idea, because the boot code
   * can never fail (i.e., it exits the enclave if it fails).
   * we need to have one that handles error case */
  map_physical_memory(load_pa_start, load_pa_size);

  freemem_size += size;

  /* extend the SPA free memory */
  spa_extend(__va(pa), size);
}

/* FIXME: just simulate allocating 1 page */
#define DEFAULT_FREEMEM_REQUEST_SIZE  4096

/* get a free page from the simple page allocator */
uintptr_t
spa_get(void)
{
  uintptr_t free_page;

  if (LIST_EMPTY(spa_free_pages)) {
    printf("eyrie simple page allocator runs out of free pages %s","\n");

    // FIXME: this code assumes that it NEVER fails
    printf("requesting one more page... \n");
    sbi_increase_freemem(DEFAULT_FREEMEM_REQUEST_SIZE);
    extend_physical_memory(__pa(freemem_va_start + freemem_size),
        DEFAULT_FREEMEM_REQUEST_SIZE);
    printf("extended the freemem\n");
    // FIXME return 0 if it fails,
    //return 0;

    // Otherwise, just move on
    assert(!LIST_EMPTY(spa_free_pages));
  }

  free_page = spa_free_pages.head;
  assert(free_page);

  /* update list head */
  uintptr_t next = NEXT_PAGE(spa_free_pages.head);
  spa_free_pages.head = next;
  spa_free_pages.count--;

  return free_page;
}

/* put a page to the simple page allocator */
void
spa_put(uintptr_t page_addr)
{
  uintptr_t prev;

  assert(IS_ALIGNED(page_addr, RISCV_PAGE_BITS));

  if (!LIST_EMPTY(spa_free_pages)) {
    prev = spa_free_pages.tail;
    assert(prev);
    NEXT_PAGE(prev) = page_addr;
  } else {
    spa_free_pages.head = page_addr;
  }

  NEXT_PAGE(page_addr) = 0;
  spa_free_pages.tail = page_addr;

  spa_free_pages.count++;
  return;
}

void
spa_init(uintptr_t base, size_t size)
{
  LIST_INIT(spa_free_pages);

  spa_extend(base, size);
}

/* extend the free memory */
void
spa_extend(uintptr_t base, size_t size)
{
  uintptr_t cur;

  // both base and size must be page-aligned
  assert(IS_ALIGNED(base, RISCV_PAGE_BITS));
  assert(IS_ALIGNED(size, RISCV_PAGE_BITS));

  /* put all free pages in freemem (base) into spa_free_pages */
  for(cur = base;
      cur < base + size;
      cur += RISCV_PAGE_SIZE) {
    spa_put(cur);
  }
}

#endif // USE_FREEMEM
