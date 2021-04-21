#ifndef _PROC_SNAPSHOT_H_
#define _PROC_SNAPSHOT_H_

#include "regs.h"

struct proc_snapshot{
    struct encl_ctx ctx; 
    uintptr_t user_pa_start;
    uintptr_t freemem_pa_start;
    uintptr_t freemem_pa_end;
    uintptr_t size; 
    char payload[0];
};


#endif