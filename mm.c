#include "rt_util.h"
#include "common.h"
#include "syscall.h"
#include "mm.h"
#include "freemem.h"
#include "paging.h"

#ifdef USE_FREEMEM

/* Page table utilities */
static pte*
__walk_create(pte* root, uintptr_t addr);

/* Hacky storage of current u-mode break */
static uintptr_t current_program_break;

uintptr_t get_program_break(){
  return current_program_break;
}

void set_program_break(uintptr_t new_break){
  current_program_break = new_break;
}

static pte*
__continue_walk_create(pte* root, uintptr_t addr, pte* pte)
{
  uintptr_t new_page = spa_get_zero();
  assert(new_page);

  unsigned long free_ppn = ppn(__pa(new_page));
  *pte = ptd_create(free_ppn);
  return __walk_create(root, addr);
}


extern void copy_physical_page(uintptr_t dst, uintptr_t src, uintptr_t helper);
extern void __copy_physical_page_switch_to_pa();
  static pte*
__walk_internal(pte* root, uintptr_t addr, int create)
{
  pte* t = root;
  int i;
  for (i = 1; i < RISCV_PT_LEVELS; i++)
  {
    size_t idx = RISCV_GET_PT_INDEX(addr, i);

    if (!(t[idx] & PTE_V))
      return create ? __continue_walk_create(root, addr, &t[idx]) : 0;

    /* mega or giga page */
    if (t[idx] & (PTE_R | PTE_W | PTE_X))
      break;

    uintptr_t pa = pte_ppn(t[idx]) << RISCV_PAGE_BITS;
    /* if the page is outside of the EPM, relocate */
    if (pa < load_pa_start || pa >= load_pa_start + load_pa_size)
    {
      uintptr_t new_page = spa_get_zero();
      assert(new_page);
      debug("PA 0x%lx is outside of EPM! Moving to 0x%lx", pa, __pa(new_page));
      copy_physical_page(
          __pa(new_page), pa,
          kernel_va_to_pa(__copy_physical_page_switch_to_pa));

      unsigned long free_ppn = ppn(__pa(new_page));
      t[idx] = pte_create(free_ppn, t[idx]);
    }

    t = (pte*) __va(pte_ppn(t[idx]) << RISCV_PAGE_BITS);
  }

  return &t[RISCV_GET_PT_INDEX(addr, i)];
}

/* walk the page table and return PTE
 * return 0 if no mapping exists */
static pte*
__walk(pte* root, uintptr_t addr)
{
  return __walk_internal(root, addr, 0);
}

/* walk the page table and return PTE
 * create the mapping if non exists */
static pte*
__walk_create(pte* root, uintptr_t addr)
{
  return __walk_internal(root, addr, 1);
}


/* allocate a new page to a given vpn
 * returns VA of the page, (returns 0 if fails) */
uintptr_t
alloc_page(uintptr_t vpn, int flags)
{
  uintptr_t page;
  pte* pte = __walk_create(root_page_table, vpn << RISCV_PAGE_BITS);

  assert(flags & PTE_U);

  if (!pte)
    return 0;

	/* if the page has been already allocated, return the page */
  if(*pte & PTE_V) {
    return __va(*pte << RISCV_PAGE_BITS);
  }

	/* otherwise, allocate one from the freemem */
  page = spa_get();
  assert(page);

  *pte = pte_create(ppn(__pa(page)), flags | PTE_V);
#ifdef USE_PAGING
  paging_inc_user_page();
#endif

  return page;
}

void
free_page(uintptr_t vpn){

  pte* pte = __walk(root_page_table, vpn << RISCV_PAGE_BITS);

  // No such PTE, or invalid
  if(!pte || !(*pte & PTE_V))
    return;

  assert(*pte & PTE_U);

  uintptr_t ppn = pte_ppn(*pte);
  // Mark invalid
  // TODO maybe do more here
  *pte = 0;

#ifdef USE_PAGING
  paging_dec_user_page();
#endif
  // Return phys page

  // if pa is outside of EPM, skip
  uintptr_t pa = ppn << RISCV_PAGE_BITS;
  if (pa >= load_pa_start && pa < load_pa_start + load_pa_size)
    spa_put(__va(ppn << RISCV_PAGE_BITS));

  return;

}

/* allocate n new pages from a given vpn
 * returns the number of pages allocated */
size_t
alloc_pages(uintptr_t vpn, size_t count, int flags)
{
  unsigned int i;
  for (i = 0; i < count; i++) {
    if(!alloc_page(vpn + i, flags))
      break;
  }

  return i;
}

void
free_pages(uintptr_t vpn, size_t count){
  unsigned int i;
  for (i = 0; i < count; i++) {
    free_page(vpn + i);
  }

}

/*
 * Check if a range of VAs contains any allocated pages, starting with
 * the given VA. Returns the number of sequential pages that meet the
 * conditions.
 */
size_t
test_va_range(uintptr_t vpn, size_t count){

  unsigned int i;
  /* Validate the region */
  for (i = 0; i < count; i++) {
    pte* pte = __walk_internal(root_page_table, (vpn+i) << RISCV_PAGE_BITS, 0);
    // If the page exists and is valid then we cannot use it
    if(pte && *pte){
      break;
    }
  }
  return i;
}

/* get a mapped physical address for a VA */
uintptr_t
translate(uintptr_t va)
{
  pte* pte = __walk(root_page_table, va);

  if(pte && (*pte & PTE_V))
    return (pte_ppn(*pte) << RISCV_PAGE_BITS) | (RISCV_PAGE_OFFSET(va));
  else
    return 0;
}

/* try to retrieve PTE for a VA, return 0 if fail */
pte*
pte_of_va(uintptr_t va)
{
  pte* pte = __walk(root_page_table, va);
  return pte;
}


void
__map_with_reserved_page_table_32(uintptr_t dram_base,
                               uintptr_t dram_size,
                               uintptr_t ptr,
                               pte* l2_pt)
{
  uintptr_t offset = 0;
  uintptr_t leaf_level = 2;
  pte* leaf_pt = l2_pt;
  unsigned long dram_max =  RISCV_GET_LVL_PGSIZE(leaf_level - 1);

  /* use megapage if l2_pt is null */
  if (!l2_pt) {
    leaf_level = 1;
    leaf_pt = root_page_table;
    dram_max = -1UL;
  }

  assert(dram_size <= dram_max);
  assert(IS_ALIGNED(dram_base, RISCV_GET_LVL_PGSIZE_BITS(leaf_level)));
  assert(IS_ALIGNED(ptr, RISCV_GET_LVL_PGSIZE_BITS(leaf_level - 1)));

  if(l2_pt) {
       /* set root page table entry */
       root_page_table[RISCV_GET_PT_INDEX(ptr, 1)] =
       ptd_create(ppn(kernel_va_to_pa(l2_pt)));
  }

  for (offset = 0;
       offset < dram_size;
       offset += RISCV_GET_LVL_PGSIZE(leaf_level))
  {
        leaf_pt[RISCV_GET_PT_INDEX(ptr + offset, leaf_level)] =
        pte_create(ppn(dram_base + offset),
                 PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);
  }

}

void
__map_with_reserved_page_table_64(uintptr_t dram_base,
                               uintptr_t dram_size,
                               uintptr_t ptr,
                               pte* l2_pt,
                               pte* l3_pt)
{
  uintptr_t offset = 0;
  uintptr_t leaf_level = 3;
  pte* leaf_pt = l3_pt;
  /* use megapage if l3_pt is null */
  if (!l3_pt) {
    leaf_level = 2;
    leaf_pt = l2_pt;
  }
  assert(dram_size <= RISCV_GET_LVL_PGSIZE(leaf_level - 1));
  assert(IS_ALIGNED(dram_base, RISCV_GET_LVL_PGSIZE_BITS(leaf_level)));
  assert(IS_ALIGNED(ptr, RISCV_GET_LVL_PGSIZE_BITS(leaf_level - 1)));

  /* set root page table entry */
  root_page_table[RISCV_GET_PT_INDEX(ptr, 1)] =
    ptd_create(ppn(kernel_va_to_pa(l2_pt)));

  /* set L2 if it's not leaf */
  if (leaf_pt != l2_pt) {
    l2_pt[RISCV_GET_PT_INDEX(ptr, 2)] =
      ptd_create(ppn(kernel_va_to_pa(l3_pt)));
  }

  /* set leaf level */
  for (offset = 0;
       offset < dram_size;
       offset += RISCV_GET_LVL_PGSIZE(leaf_level))
  {
    leaf_pt[RISCV_GET_PT_INDEX(ptr + offset, leaf_level)] =
      pte_create(ppn(dram_base + offset),
          PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);
  }

}

void
map_with_reserved_page_table(uintptr_t dram_base,
                             uintptr_t dram_size,
                             uintptr_t ptr,
                             pte* l2_pt,
                             pte* l3_pt)
{
  #if __riscv_xlen == 64
  if (dram_size > RISCV_GET_LVL_PGSIZE(2))
    __map_with_reserved_page_table_64(dram_base, dram_size, ptr, l2_pt, 0);
  else
    __map_with_reserved_page_table_64(dram_base, dram_size, ptr, l2_pt, l3_pt);
  #elif __riscv_xlen == 32
  if (dram_size > RISCV_GET_LVL_PGSIZE(1))
    __map_with_reserved_page_table_32(dram_base, dram_size, ptr, 0);
  else
    __map_with_reserved_page_table_32(dram_base, dram_size, ptr, l2_pt);
  #endif
}

uintptr_t
enclave_map(uintptr_t base_addr, size_t base_size, uintptr_t ptr) {
  int pte_flags = PTE_W | PTE_D | PTE_R | PTE_U | PTE_A;

  // Find a continuous VA space that will fit the req. size
  int req_pages = vpn(PAGE_UP(base_size));

  if (test_va_range(vpn(ptr), req_pages) != req_pages) {
    return 0;
  }

  if (map_pages(vpn(ptr), ppn(base_addr), req_pages, pte_flags) != req_pages) {
    return 0;
  }

  return ptr;
}

uintptr_t
map_page(uintptr_t vpn, uintptr_t phys_ppn, int flags) {
  pte* pte = __walk_create(root_page_table, vpn << RISCV_PAGE_BITS);
  assert(flags & PTE_U);
  if (!pte) return 0;

  if (*pte & PTE_V) return __va(*pte << RISCV_PAGE_BITS);

  *pte = pte_create(phys_ppn, flags | PTE_V);
#ifdef USE_PAGING
  paging_inc_user_page();
#endif
  return phys_ppn << RISCV_PAGE_BITS;
}

size_t
map_pages(uintptr_t vpn, uintptr_t phys_ppn, size_t count, int flags) {
  unsigned int i;
  for (i = 0; i < count; i++) {
    if (!map_page(vpn + i, phys_ppn + i, flags)) break;
  }

  return i;
}

void
map_untrusted_memory(uintptr_t base,
                     uintptr_t size)
{
  uintptr_t ptr = EYRIE_UNTRUSTED_START;

  /* untrusted memory is smaller than a megapage (2 MB in RV64, 4MB in RV32) */
  #if __riscv_xlen == 64
  assert(size <= RISCV_GET_LVL_PGSIZE(2));
  #elif __riscv_xlen == 32
  assert(size <= RISCV_GET_LVL_PGSIZE(1));
  #endif

  map_with_reserved_page_table(base, size,
      ptr, utm_l2_page_table, utm_l3_page_table);

  shared_buffer = ptr;
  shared_buffer_size = size;
}

void
copy_root_page_table()
{
  /* the old table lives in the first page */
  pte* old_root_page_table = (pte*) EYRIE_LOAD_START;
  int i;

  /* copy all valid entries of the old root page table */
  for (i = 0; i < BIT(RISCV_PT_INDEX_BITS); i++) {
    if (old_root_page_table[i] & PTE_V &&
        !(root_page_table[i] & PTE_V)) {
      root_page_table[i] = old_root_page_table[i];
    }
  }
}

void
remap_kernel_space(uintptr_t runtime_base,
                   uintptr_t runtime_size)
{
  /* eyrie runtime is supposed to be smaller than a megapage */

  #if __riscv_xlen == 64
  assert(runtime_size <= RISCV_GET_LVL_PGSIZE(2));
  #elif __riscv_xlen == 32
  assert(runtime_size <= RISCV_GET_LVL_PGSIZE(1));
  #endif

  map_with_reserved_page_table(runtime_base, runtime_size,
     runtime_va_start, kernel_l2_page_table, kernel_l3_page_table);
}

#endif /* USE_FREEMEM */
