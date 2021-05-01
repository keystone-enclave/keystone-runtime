#ifndef _PROC_SNAPSHOT_H_
#define _PROC_SNAPSHOT_H_

#include "regs.h"

struct proc_snapshot_payload {
    unsigned char tag_buf_payload[16];
    const unsigned char initial_value_payload[12];
};

struct proc_snapshot{
    struct encl_ctx ctx; 
    uintptr_t user_pa_start;
    uintptr_t freemem_pa_start;
    uintptr_t freemem_pa_end;
    unsigned char tag_buf_ctx[16];
    unsigned char tag_buf_root_pt[16];
    const unsigned char initial_value_ctx[12];
    const unsigned char initial_value_root_pt[12];
    uintptr_t size; 
    char payload[0];
};


#endif