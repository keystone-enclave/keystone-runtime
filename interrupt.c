//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "regs.h"
#include "sbi.h"
#include "timex.h"
#include "interrupt.h"
#include "printf.h"
#include <asm/csr.h>
#include "page_replacement.h"
#include "rt_util.h"
#include "vm.h"

#define DEFAULT_CLOCK_DELAY 3500//200

void init_timer(void)
{
  sbi_set_timer(get_cycles64() + DEFAULT_CLOCK_DELAY);
  csr_set(sstatus, SR_SPIE);
  csr_set(sie, SIE_STIE | SIE_SSIE);
}

void handle_timer_interrupt()
{
  sbi_stop_enclave(0);
  unsigned long next_cycle = get_cycles64() + DEFAULT_CLOCK_DELAY;
  sbi_set_timer(next_cycle);
  csr_set(sstatus, SR_SPIE);
  csr_set(sie, SIE_STIE | SIE_SSIE);

  //printf("[TIMER] inside timer\n" );
  //clear_bits();
  return;
}

void handle_interrupts(struct encl_ctx_t* regs)
{
  //is_rt=1;
  unsigned long cause = regs->scause;
  //printf("[TIMER] inside handle_interrupts with cause %lu\n",cause );
  switch(cause) {
    case INTERRUPT_CAUSE_TIMER:
      handle_timer_interrupt();

      break;
    /* ignore other interrupts */
    case INTERRUPT_CAUSE_SOFTWARE:
    case INTERRUPT_CAUSE_EXTERNAL:
    default:
      sbi_stop_enclave(0);
      return;
  }
  is_rt=0;
}
