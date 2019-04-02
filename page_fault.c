//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "regs.h"
#include "vm.h"
#include "printf.h"
#include "freemem.h"

void rt_page_fault(struct encl_ctx_t* ctx)
{
  unsigned long addr, cause, pc;

  pc = ctx->regs.sepc;
  addr = ctx->sbadaddr;
  cause = ctx->scause;

  printf("[runtime] page fault at 0x%lx on 0x%lx (scause: 0x%lx)\n", pc, addr, cause);

  sbi_exit_enclave(-1);
  return;
}
