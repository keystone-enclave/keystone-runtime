//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "mm.h"
#include "rt_util.h"
#include "printf.h"
#include "string.h"
#include "uaccess.h"
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

void handle_copy_write(struct encl_ctx* ctx){
  unsigned long addr;
  addr = PAGE_DOWN(ctx->sbadaddr);

  printf("Init handle_copy_write: %p\n", ctx->sbadaddr);

  //Get physical address of parent 
  uintptr_t paddr_page = kernel_va_to_pa((void *) addr);   
  uint8_t offset = paddr_page - load_pa_start;

  //Get child's physical page
  uintptr_t new_paddr_page = load_pa_child_start + offset; 

  printf("1. parent-page: %p, offset: %d, child-page: %p\n", paddr_page, offset, new_paddr_page); 
  printf("hi\n");

  //Set page table's PTE to new child's physical address
  pte *p = pte_of_va(addr);

  printf("2. parent-page: %p, offset: %d, child-page: %p\n", paddr_page, offset, new_paddr_page); 


  *p = pte_create(ppn(new_paddr_page), PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);

  printf("3. parent-page: %p, offset: %d, child-page: %p\n", paddr_page, offset, new_paddr_page); 



//   printf("[runtime] handle_copy_write: addr: %p, new_paddr_page: %p\n", paddr_page, new_paddr_page); 



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

void tlb_flush(void)
{
  __asm__ volatile("fence.i\t\nsfence.vma\t\n");
}
