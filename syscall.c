//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <stdint.h>
#include <stddef.h>
#include "syscall.h"
#include "string.h"
#include <edge_call.h>
#include "uaccess.h"

#define LINUX_SYSCALL_WRAPPING
#define IO_SYSCALL_WRAPPING

#include "syscall_nums.h"

#ifdef IO_SYSCALL_WRAPPING
#include "io_wrap.h"
#endif /* IO_SYSCALL_WRAPPING */

#ifdef LINUX_SYSCALL_WRAPPING
#include "linux_wrap.h"
#endif /* LINUX_SYSCALL_WRAPPING */

extern void exit_enclave(uintptr_t arg0);

/* These are set by entry.S during init */
uintptr_t shared_buffer;
uintptr_t shared_buffer_size;

uintptr_t dispatch_edgecall_ocall( unsigned long call_id,
				   void* data, size_t data_len,
				   void* return_buffer, size_t return_len){

  uintptr_t ret;
  /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */
  struct edge_call_t* edge_call = (struct edge_call_t*)shared_buffer;

  /* We encode the call id, copy the argument data into the shared
   * region, calculate the offsets to the argument data, and then
   * dispatch the ocall to host */

  edge_call->call_id = call_id;
  uintptr_t buffer_data_start = edge_call_data_ptr();

  if(data_len > (shared_buffer_size - (buffer_data_start - shared_buffer))){
    goto ocall_error;
  }
  //TODO safety check on source
  copy_from_user((void*)buffer_data_start, (void*)data, data_len);

  if(edge_call_setup_call(edge_call, (void*)buffer_data_start, data_len) != 0){
    goto ocall_error;
  }

  ret = SBI_CALL_1(SBI_SM_STOP_ENCLAVE, 1);

  if (ret != 0) {
    goto ocall_error;
  }

  if(edge_call->return_data.call_status != CALL_STATUS_OK){
    goto ocall_error;
  }

  if( return_len == 0 ){
    /* Done, no return */
    return (uintptr_t)NULL;
  }

  uintptr_t return_ptr;
  if(edge_call_ret_ptr(edge_call, &return_ptr) != 0){
    goto ocall_error;
  }

  /* Done, there was a return value to copy out of shared mem */
  /* TODO This is currently assuming return_len is the length, not the
     value passed in the edge_call return data. We need to somehow
     validate these. The size in the edge_call return data is larger
     almost certainly.*/
  copy_to_user(return_buffer, (void*)return_ptr, return_len);

  return 0;

 ocall_error:
  /* TODO In the future, this should fault */
  return 1;
}

uintptr_t handle_copy_from_shared(void* dst, uintptr_t offset, size_t size){

  /* This is where we would handle cache side channels for a given
     platform */

  /* The only safety check we do is to confirm all data comes from the
   * shared region. */
  uintptr_t src_ptr;
  if(edge_call_get_ptr_from_offset(offset, size,
				   &src_ptr) != 0){
    return 1;
  }

  return copy_to_user(dst, (void*)src_ptr, size);
}

void init_edge_internals(){
  edge_call_init_internals(shared_buffer, shared_buffer_size);
}

void handle_syscall(struct encl_ctx_t* ctx)
{
  uintptr_t n = ctx->regs.a7;
  uintptr_t arg0 = ctx->regs.a0;
  uintptr_t arg1 = ctx->regs.a1;
  uintptr_t arg2 = ctx->regs.a2;
  uintptr_t arg3 = ctx->regs.a3;
  uintptr_t arg4 = ctx->regs.a4;

  uintptr_t ret = 0;

  ctx->regs.sepc += 4;

  switch (n) {
  case(RUNTIME_SYSCALL_EXIT):
    SBI_CALL_1(SBI_SM_EXIT_ENCLAVE, arg0);
    break;
  case(RUNTIME_SYSCALL_OCALL):
    ret = dispatch_edgecall_ocall(arg0, (void*)arg1, arg2, (void*)arg3, arg4);
    break;
  case(RUNTIME_SYSCALL_SHAREDCOPY):
    ret = handle_copy_from_shared((void*)arg0, arg1, arg2);
    break;
  case(RUNTIME_SYSCALL_ATTEST_ENCLAVE):
    ret = SBI_CALL_3(SBI_SM_ATTEST_ENCLAVE, arg0, arg1, arg2);
    break;


#ifdef LINUX_SYSCALL_WRAPPING
  case(SYS_clock_gettime):
    ret = linux_clock_gettime((__clockid_t)arg0, (struct timespec*)arg1);
    break;

  case(SYS_getrandom):
    ret = linux_getrandom((void*)arg0, (size_t)arg1, (unsigned int)arg2);
    break;

  case(SYS_rt_sigprocmask):
    ret = linux_rt_sigprocmask((int)arg0, (const sigset_t*)arg1, (sigset_t*)arg2);
    break;
#endif /* LINUX_SYSCALL_WRAPPING */

#ifdef IO_SYSCALL_WRAPPING
  case(SYS_read):
    ret = io_syscall_read(arg0, arg1, arg2);
    break;
  case(SYS_write):
    ret = io_syscall_write(arg0, arg1, arg2);
    break;
  case(SYS_openat):
    ret = io_syscall_openat(arg0, arg1, arg2, arg3);
    break;
#endif /* IO_SYSCALL_WRAPPING */


  case(RUNTIME_SYSCALL_UNKNOWN):
  default:
    printf("[runtime] syscall %ld not implemented\n", (unsigned long) n);
    ret = -1;
    break;
  }

  /* store the result in the stack */
  ctx->regs.a0 = ret;
  return;
}
