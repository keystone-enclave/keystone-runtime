//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#include "printf.h"
#include "regs.h"
#include "edge_syscall.h"
#include "vm.h"

#define RUNTIME_SYSCALL_UNKNOWN         1000
#define RUNTIME_SYSCALL_OCALL           1001
#define RUNTIME_SYSCALL_SHAREDCOPY      1002
#define RUNTIME_SYSCALL_ATTEST_ENCLAVE  1003
#define RUNTIME_SYSCALL_EXIT            1101
#define RUNTIME_SYSCALL_SBRK            2000
#define RUNTIME_SYSCALL_RAND            3000

void handle_syscall(struct encl_ctx_t* ctx);
void init_edge_internals(void);
uintptr_t dispatch_edgecall_syscall(edge_syscall_t* syscall_data_ptr,
                                    size_t data_len);

uintptr_t dispatch_edgecall_ocall( unsigned long call_id,
                                    				   void* data, size_t data_len,
                                    				   void* return_buffer, size_t return_len,uintptr_t arg6);



uintptr_t handle_copy_from_shared(void* dst, uintptr_t offset, size_t size);


// Define this to enable printing of a large amount of syscall information
//#define INTERNAL_STRACE 1

#ifdef INTERNAL_STRACE
#define print_strace printf
#else
#define print_strace(...)
#endif

#endif /* syscall.h */
