//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "mm.h"
#include "rt_util.h"
#include "printf.h"
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

void dump_ctx(struct encl_ctx* ctx)
{
  printf("sstatus  [%016lx]   scause [%016lx]\n"
         "sbadaddr [%016lx]   sepc   [%016lx]\n"
         "ra [%016lx] sp [%016lx] gp [%016lx] tp [%016lx]\n"
         "t0 [%016lx] t1 [%016lx] t2 [%016lx] t4 [%016lx]\n"
         "t4 [%016lx] t5 [%016lx] t6 [%016lx] s0 [%016lx]\n"
         "s1 [%016lx] s2 [%016lx] s3 [%016lx] s4 [%016lx]\n"
         "s5 [%016lx] s6 [%016lx] s7 [%016lx] s8 [%016lx]\n"
         "s9 [%016lx] s10 [%016lx] s11 [%016lx]\n"
         "a0 [%016lx] a1 [%016lx] a2 [%016lx] a3 [%016lx]\n"
         "a4 [%016lx] a5 [%016lx] a6 [%016lx] a7 [%016lx]\n"
         ,ctx->sstatus, ctx->scause,
         ctx->sbadaddr, ctx->regs.sepc,
         ctx->regs.ra, ctx->regs.sp, ctx->regs.gp, ctx->regs.tp,
         ctx->regs.t0, ctx->regs.t1, ctx->regs.t2, ctx->regs.t3,
         ctx->regs.t4, ctx->regs.t5, ctx->regs.t6, ctx->regs.s0,
         ctx->regs.s1, ctx->regs.s2, ctx->regs.s3, ctx->regs.s4,
         ctx->regs.s5, ctx->regs.s6, ctx->regs.s7, ctx->regs.s8,
         ctx->regs.s9, ctx->regs.s10, ctx->regs.s11,
         ctx->regs.a0, ctx->regs.a1, ctx->regs.a2, ctx->regs.a3,
         ctx->regs.a4, ctx->regs.a5, ctx->regs.a6, ctx->regs.a7
         );
}

void rt_page_fault(struct encl_ctx* ctx)
{
#ifdef FATAL_DEBUG
  unsigned long addr, cause, pc;
  pc = ctx->regs.sepc;
  addr = ctx->sbadaddr;
  cause = ctx->scause;
  printf("[runtime] page fault at 0x%lx on 0x%lx (scause: 0x%lx)\r\n", pc, addr, cause);
  dump_ctx(ctx);
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
