#ifndef _PROC_SNAPSHOT_H_
#define _PROC_SNAPSHOT_H_

#include "regs.h"

struct proc_snapshot{
    struct encl_ctx ctx; 
    int size; 
    char payload[0];
};


#endif