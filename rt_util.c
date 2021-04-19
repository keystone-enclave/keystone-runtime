//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "mm.h"
#include "rt_util.h"
#include "printf.h"
#include "string.h"
#include "uaccess.h"
#include "freemem.h"
#include "vm.h"

// Statically allocated copy-buffer
unsigned char rt_copy_buffer_1[RISCV_PAGE_SIZE];
unsigned char rt_copy_buffer_2[RISCV_PAGE_SIZE];

size_t rt_util_getrandom(void* vaddr, size_t buflen){
  size_t remaining = buflen;
  uintptr_t rnd;
  uintptr_t* next = (uintptr_t*)vaddr;
  // Get data
  while(remaining > sizeof(uintptr_t)){
    rnd = sbi_random();
    ALLOW_USER_ACCESS( *next = rnd );
    remaining -= sizeof(uintptr_t);
    next++;
  }
  // Cleanup
  if( remaining > 0 ){
    rnd = sbi_random();
    copy_to_user(next, &rnd, remaining);
  }
  size_t ret = buflen;
  return ret;
}

void rt_util_misc_fatal(){
  //Better hope we can debug it!
  sbi_exit_enclave(-1);
}

void not_implemented_fatal(struct encl_ctx* ctx){
#ifdef FATAL_DEBUG
    unsigned long addr, cause, pc;
    pc = ctx->regs.sepc;
    addr = ctx->sbadaddr;
    cause = ctx->scause;
    printf("[runtime] non-handlable interrupt/exception at 0x%lx on 0x%lx (scause: 0x%lx)\r\n", pc, addr, cause);
#endif

    // Bail to m-mode
    __asm__ volatile("csrr a0, scause\r\nli a7, 1111\r\n ecall");

    return;
}

void rt_page_fault(struct encl_ctx* ctx)
{
#ifdef FATAL_DEBUG
  unsigned long addr, cause, pc;
  pc = ctx->regs.sepc;
  addr = ctx->sbadaddr;
  cause = ctx->scause;
  // printf("[runtime] page fault at 0x%lx on 0x%lx (scause: 0x%lx), paddr: %p, pte: %p\r\n", pc, addr, cause, (void *) kernel_va_to_pa((void *) addr), (pte_of_va(addr)));
  printf("[runtime] page fault at 0x%lx on 0x%lx (scause: 0x%lx)\r\n", pc, addr, cause);
#endif

  sbi_exit_enclave(-1);

  /* never reach here */
  assert(false);
  return;
}

extern void copy_physical_page(uintptr_t dst, uintptr_t src, uintptr_t helper);
extern void __copy_physical_page_switch_to_pa();
void
cow_relocate(pte* root, uintptr_t addr) {
  pte* t = root;
  int i;
  for (i = 1; i < RISCV_PT_LEVELS + 1; i++)
  {
    size_t idx = RISCV_GET_PT_INDEX(addr, i);

    if (!(t[idx] & PTE_V))
      debug("copy on write failed to relocate: page not valid!");

    uintptr_t pa = pte_ppn (t[idx]) << RISCV_PAGE_BITS;
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

  return;
}

void
handle_copy_on_write(struct encl_ctx* ctx) {
  debug("copy on write called at pc = 0x%lx, VA = 0x%lx",
      ctx->regs.sepc, ctx->sbadaddr);

  cow_relocate(root_page_table, ctx->sbadaddr);

  debug("copy on write relocated page to 0x%lx", translate(ctx->sbadaddr));

  return;
}

void tlb_flush(void)
{
  __asm__ volatile("fence.i\t\nsfence.vma\t\n");
}
