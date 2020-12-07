#include "common.h"
#include "syscall.h"
#include "mm.h"
#include "freemem.h"
#include "vm.h"
int ff=1;

/* Page table utilities */


/* Hacky storage of current u-mode break */
static uintptr_t current_program_break;
static uintptr_t current_program_break_rt;

uintptr_t get_program_break(){
  return current_program_break;
}

void set_program_break(uintptr_t new_break){
  current_program_break = new_break;
}

uintptr_t get_program_break_rt(){
  return current_program_break_rt;
}

void set_program_break_rt(uintptr_t new_break){
  current_program_break_rt = new_break;
}

static pte_t*
__continue_walk_create(pte_t* root, uintptr_t addr, pte_t* pte)
{
  uintptr_t new_page = spa_get();
  unsigned long free_ppn = ppn(__pa(new_page));
  *pte = ptd_create(free_ppn);
  return __walk_create(root, addr);
}

static pte_t*
__walk_internal(pte_t* root, uintptr_t addr, int create)
{
  pte_t* t = root;
  int i;
  //printf("PAGE TABLE WALK BEGINS for address(wi) %llx \n",addr);
  for (i = 1; i < RISCV_PT_LEVELS; i++)
  {
    size_t idx = RISCV_GET_PT_INDEX(addr, i);
    //printf("LEVEL = %llx  INDEX = %llx\n",i,idx);
    if (!(t[idx] & PTE_V))
      return create ? __continue_walk_create(root, addr, &t[idx]) : 0;

    t = (pte_t*) __va(pte_ppn(t[idx]) << RISCV_PAGE_BITS);
    //printf("MM.C[__walk_internal] t = 0x%lx *t = 0x%lx\n",t,*t );
  }
  //printf("MM.C[__walk_internal] t = 0x%lx *t = 0x%lx\nOne call done\n",&t[RISCV_GET_PT_INDEX(addr, 3)],*t );
  return &t[RISCV_GET_PT_INDEX(addr, 3)];
}

/* walk the page table and return PTE
 * return 0 if no mapping exists */
pte_t*
__walk(pte_t* root, uintptr_t addr)
{

  return __walk_internal(root, addr, 0);
}

/* walk the page table and return PTE
 * create the mapping if non exists */
pte_t*
__walk_create(pte_t* root, uintptr_t addr)
{
  return __walk_internal(root, addr, 1);
}

/* maps a physical address to the virtual address
 * and returns VA (returns 0 on error)
 * WARNING: the physical page must be accessible and usable */
uintptr_t
remap_physical_page(uintptr_t vpn, uintptr_t ppn, int flags)
{
  pte_t* pte =  __walk_create(root_page_table, vpn << RISCV_PAGE_BITS);

  if (!pte)
    return 0;

  *pte = pte_create(ppn, flags);

  return (vpn << RISCV_PAGE_BITS);
}

/* maps a physical address range to a virtual address range
 * and returns the number of pages mapped
 * WARNING: the physical page must be accessible and usable */
size_t
remap_physical_pages(uintptr_t vpn, uintptr_t ppn, size_t count, int flags)
{
  unsigned int i;

  for (i = 0; i < count; i++) {
    if(!remap_physical_page(vpn + i, ppn + i, flags))
      break;
  }

  return i;
}

/* get a mapped physical address for a VA */
uintptr_t
translate(uintptr_t va)
{
  /*if(ff){
  uintptr_t ghost_addr = 0xfffffffffffffef0;
  uintptr_t *status_find_address=__walk(root_page_table,ghost_addr);
  if(status_find_address!=0)
    printf("in mm.c[translate] GHOST ADDRESS status_find_address = 0x%lx  and content =  0x%lx\n",status_find_address,*status_find_address );
  else
    printf("in mm.c[translate] GHOST ADDRESS ONLY  status_find_address = 0x%lx\n",status_find_address );
  ff=0;}
  */




  pte_t* pte = __walk(root_page_table, va);

  if(*pte & PTE_V)
    return (pte_ppn(*pte) << RISCV_PAGE_BITS) | (RISCV_PAGE_OFFSET(va));
  else
    return 0;
}

/* allocate a new page to a given vpn
 * returns VA of the page, (returns 0 if fails) */
uintptr_t
alloc_page(uintptr_t vpn, int flags)
{
  uintptr_t page;
  pte_t* pte = __walk_create(root_page_table, vpn << RISCV_PAGE_BITS);

  if (!pte)
    return 0;

	/* if the page has been already allocated, return the page */
  if(*pte & PTE_V) {
    //printf("in mm.c[alloc_page] GHOST ADDRESS ONLY  *pte << RISCV_PAGE_BITS = 0x%lx\n",__va(*pte << RISCV_PAGE_BITS) );
    return __va(*pte << RISCV_PAGE_BITS);
  }

	/* otherwise, allocate one from the freemem */
  page = spa_get();
  *pte = pte_create(ppn(__pa(page)), flags | PTE_V | PTE_L );

  return page;
}

void
free_page(uintptr_t vpn){
	
  pte_t* pte = __walk(root_page_table, vpn << RISCV_PAGE_BITS);

  // No such PTE, or invalid

  if(!pte){// || !(*pte & PTE_V)){// uncomment these two lines for full tracing

	  return;
  }
  uintptr_t ppn = pte_ppn(*pte);
  // Mark invalid
  // TODO maybe do more here
  *pte = (*pte & (~PTE_V));

  // Return phys page
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
    pte_t* pte = __walk_internal(root_page_table, (vpn+i) << RISCV_PAGE_BITS, 0);
    // If the page exists and is valid then we cannot use it
    if(pte && (*pte & PTE_V)){
      break;
    }
  }
  return i;
}
//----------------------MY OWN FUNCITIONS--------------------------

pte_t* get_root_page_table_addr()
{
  return root_page_table;
}

pte_t*
__walk_during_page_fault(pte_t* root, uintptr_t addr)
{

  return __walk_internal(root, addr, 0);
}
