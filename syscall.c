//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <stdint.h>
#include <stddef.h>
#include "syscall.h"
#include "string.h"
#include "edge_call.h"
#include "uaccess.h"
#include "mm.h"
#include "rt_util.h"
#include "process_snapshot.h"
#include "vm.h"
#include "freemem.h"
#include "aes_gcm.h"
#include "gcm.h"

#include "syscall_nums.h"

#ifdef IO_SYSCALL_WRAPPING
#include "io_wrap.h"
#endif /* IO_SYSCALL_WRAPPING */

#ifdef LINUX_SYSCALL_WRAPPING
#include "linux_wrap.h"
#endif /* LINUX_SYSCALL_WRAPPING */

extern uintptr_t utm_paddr_start; 
extern uintptr_t freemem_paddr_start;

extern void exit_enclave(uintptr_t arg0);

extern const unsigned char key[32];
extern unsigned char plaintext[1024];
extern unsigned char expected_ciphertext[64];
extern const unsigned char initial_value[12];
extern const unsigned char additional[];

uintptr_t dispatch_edgecall_syscall(struct edge_syscall* syscall_data_ptr, size_t data_len){
  int ret;

  // Syscall data should already be at the edge_call_data section
  /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */
  struct edge_call* edge_call = (struct edge_call*) shared_buffer;

  edge_call->call_id = EDGECALL_SYSCALL;

  printf("In edge call\n");
  if(edge_call_setup_call(edge_call, (void*)syscall_data_ptr, data_len) != 0){
    return -1;
  }

  printf("After setup\n");

  ret = sbi_stop_enclave(SBI_STOP_REQ_EDGE_CALL);

  if (ret != 0) {
    return -1;
  }

  printf("After stop\n");

  if(edge_call->return_data.call_status != CALL_STATUS_OK){
    return -1;
  }

  uintptr_t return_ptr;
  size_t return_len;
  if(edge_call_ret_ptr(edge_call, &return_ptr, &return_len) != 0){
    return -1;
  }

  if(return_len < sizeof(uintptr_t)){
    return -1;
  }

  return *(uintptr_t*)return_ptr;
}

uintptr_t dispatch_edgecall_ocall( unsigned long call_id,
				   void* data, size_t data_len,
				   void* return_buffer, size_t return_len){

  uintptr_t ret;
  /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */
  struct edge_call* edge_call = (struct edge_call*)shared_buffer;

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

  ret = sbi_stop_enclave(SBI_STOP_REQ_EDGE_CALL);

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
  size_t ret_len_untrusted;
  if(edge_call_ret_ptr(edge_call, &return_ptr, &ret_len_untrusted) != 0){
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

uintptr_t dispatch_fork_ocall(struct proc_snapshot* snapshot, size_t data_len){

  /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */
  struct edge_call* edge_call = (struct edge_call*)shared_buffer;

  /* We encode the call id, copy the argument data into the shared
   * region, calculate the offsets to the argument data, and then
   * dispatch the ocall to host */

  //OCALL_HANDLE_FORK 5
  edge_call->call_id = 3208;

  // printf("[rt-dispatch_fork_ocall] edge_call->call_id: %d\n", edge_call->call_id);
  uintptr_t buffer_data_start = edge_call_data_ptr();
  // printf("[rt-dispatch_fork_ocall] buffer_data_start %p\n", buffer_data_start);

  if(data_len > (shared_buffer_size - (buffer_data_start - shared_buffer))){
    goto ocall_error;
  }

  mbedtls_gcm_context ctx; 
  mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
  unsigned char tag_buf[16];
  int ret;
  uintptr_t buffer_payload = buffer_data_start + sizeof(struct proc_snapshot);
  uintptr_t *user_va =(uintptr_t *) __va(user_paddr_start);

  mbedtls_gcm_init( &ctx );
  ret = mbedtls_gcm_setkey( &ctx, cipher, key, 128 );

  //Encrypt register state of process 
  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(struct encl_ctx), initial_value, 12, additional, 0, (const unsigned char *) &snapshot->ctx, (unsigned char *) &snapshot->ctx, 16, tag_buf);
  memcpy((void*)buffer_data_start, snapshot, sizeof(struct proc_snapshot));

  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, data_len - sizeof(struct proc_snapshot), initial_value, 12, additional, 0, (const unsigned char *) user_va, (unsigned char *) buffer_payload, 16, tag_buf);
  mbedtls_gcm_free( &ctx );

  printf("[runtime] ret: %d\n", ret);

  if(edge_call_setup_call(edge_call, (void*)buffer_data_start, data_len) != 0){
    goto ocall_error;
  }

  return 0; 

  ocall_error:
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

void handle_syscall(struct encl_ctx* ctx)
{
  uintptr_t n = ctx->regs.a7;
  uintptr_t arg0 = ctx->regs.a0;
  uintptr_t arg1 = ctx->regs.a1;
  uintptr_t arg2 = ctx->regs.a2;
  uintptr_t arg3 = ctx->regs.a3;
  uintptr_t arg4 = ctx->regs.a4;

  // We only use arg5 in these for now, keep warnings happy.
#if defined(LINUX_SYSCALL_WRAPPING) || defined(IO_SYSCALL_WRAPPING)
  uintptr_t arg5 = ctx->regs.a5;
#endif /* IO_SYSCALL_WRAPPING */
  uintptr_t ret = 0;

  ctx->regs.sepc += 4;

  switch (n) {
  case(RUNTIME_SYSCALL_EXIT):
    sbi_exit_enclave(arg0);
    break;
  case(RUNTIME_SYSCALL_OCALL):
    ret = dispatch_edgecall_ocall(arg0, (void*)arg1, arg2, (void*)arg3, arg4);
    break;
  case(RUNTIME_SYSCALL_SHAREDCOPY):
    ret = handle_copy_from_shared((void*)arg0, arg1, arg2);
    break;
  case(RUNTIME_SYSCALL_ATTEST_ENCLAVE):;
    copy_from_user((void*)rt_copy_buffer_2, (void*)arg1, arg2);

    ret = sbi_attest_enclave(rt_copy_buffer_1, rt_copy_buffer_2, arg2);

    /* TODO we consistently don't have report size when we need it */
    copy_to_user((void*)arg0, (void*)rt_copy_buffer_1, 2048);
    //print_strace("[ATTEST] p1 0x%p->0x%p p2 0x%p->0x%p sz %lx = %lu\r\n",arg0,arg0_trans,arg1,arg1_trans,arg2,ret);
    break;
  case(RUNTIME_SYSCALL_GET_SEALING_KEY):;
    /* Stores the key receive structure */
    uintptr_t buffer_1_pa = kernel_va_to_pa(rt_copy_buffer_1);

    /* Stores the key identifier */
    uintptr_t buffer_2_pa = kernel_va_to_pa(rt_copy_buffer_2);

    if (arg1 > sizeof(rt_copy_buffer_1) ||
        arg3 > sizeof(rt_copy_buffer_2)) {
      ret = -1;
      break;
    }

    copy_from_user(rt_copy_buffer_2, (void *)arg2, arg3);

    ret = sbi_get_sealing_key(buffer_1_pa, buffer_2_pa, arg3);

    if (!ret) {
      copy_to_user((void *)arg0, (void *)rt_copy_buffer_1, arg1);
    }

    /* Delete key from copy buffer */
    memset(rt_copy_buffer_1, 0x00, sizeof(rt_copy_buffer_1));

    break;
  case(SYSCALL_SNAPSHOT):;
    print_strace("[runtime] snapshot \r\n");
    struct sbi_snapshot_ret snapshot_ret;
    uintptr_t pa_snapshot_ret = kernel_va_to_pa(&snapshot_ret);

    ret = sbi_snapshot(pa_snapshot_ret);

    //0xffffffffc0009018
    load_pa_child_start = snapshot_ret.dram_base;

    printf("Snapshot: utm_base: %p, size: %d, shared_buffer: %p, shared_buffer_size: %d\n", snapshot_ret.utm_paddr,snapshot_ret.utm_size,
    shared_buffer, shared_buffer_size);

    // pte *p;

    // //Remaps UTM to new UTM
    // for(int i = 0; i < PAGE_UP(snapshot_ret.utm_size)/RISCV_PAGE_SIZE; i++){
    //     p = pte_of_va(shared_buffer + i * RISCV_PAGE_SIZE);
    //     *p = pte_create(ppn(snapshot_ret.utm_paddr + i * RISCV_PAGE_SIZE), PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);
    // }


    break;
  case(SYSCALL_FORK):
    print_strace("[runtime] fork \r\n");

    struct proc_snapshot snapshot;

    //Copy user context to snapshot 
    memcpy(&snapshot.ctx, ctx, sizeof(struct encl_ctx)); 
    snapshot.ctx.regs.sepc = csr_read(sepc);
    snapshot.user_pa_start = user_paddr_start;
    snapshot.freemem_pa_start = load_pa_start;
    snapshot.freemem_pa_end = __pa(spa_get_head());

    snapshot.size = (__pa(spa_get_head()) - user_paddr_start) + sizeof(struct proc_snapshot);

    //Place the snapshot in the untrusted buffer 
    dispatch_fork_ocall(&snapshot, snapshot.size);

    ret = sbi_fork(SBI_STOP_REQ_FORK);

    //Return child eid 
    // ret = fork_ret->eid; 

    /* Remap page table */
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

  case(SYS_getpid):
    ret = linux_getpid();
    break;

  case(SYS_uname):
    ret = linux_uname((void*) arg0);
    break;

  case(SYS_rt_sigaction):
    ret = linux_RET_ZERO_wrap(n);
    break;

  case(SYS_set_tid_address):
    ret = linux_set_tid_address((int*) arg0);
    break;

  case(SYS_brk):
    ret = syscall_brk((void*) arg0);
    break;

  case(SYS_mmap):
    ret = syscall_mmap((void*) arg0, (size_t)arg1, (int)arg2,
                       (int)arg3, (int)arg4, (__off_t)arg5);
    break;

  case(SYS_munmap):
    ret = syscall_munmap((void*) arg0, (size_t)arg1);
    break;

  case(SYS_exit):
  case(SYS_exit_group):
    print_strace("[runtime] exit or exit_group (%lu)\r\n",n);
    sbi_exit_enclave(arg0);
    break;

  case(SYS_clone):
    print_strace("[runtime] clone\r\n");
    sbi_stop_enclave(SBI_STOP_REQ_CLONE);
    break;
#endif /* LINUX_SYSCALL_WRAPPING */

#ifdef IO_SYSCALL_WRAPPING
  case(SYS_read):
    ret = io_syscall_read((int)arg0, (void*)arg1, (size_t)arg2);
    break;
  case(SYS_write):
    ret = io_syscall_write((int)arg0, (void*)arg1, (size_t)arg2);
    break;
  case(SYS_writev):
    ret = io_syscall_writev((int)arg0, (const struct iovec*)arg1, (int)arg2);
    break;
  case(SYS_readv):
    ret = io_syscall_readv((int)arg0, (const struct iovec*)arg1, (int)arg2);
    break;
  case(SYS_openat):
    ret = io_syscall_openat((int)arg0, (char*)arg1, (int)arg2, (mode_t)arg3);
    break;
  case(SYS_unlinkat):
    ret = io_syscall_unlinkat((int)arg0, (char*)arg1, (int)arg2);
    break;
  case(SYS_fstatat):
    ret = io_syscall_fstatat((int)arg0, (char*)arg1, (struct stat*)arg2, (int)arg3);
    break;
  case(SYS_lseek):
    ret = io_syscall_lseek((int)arg0, (off_t)arg1, (int)arg2);
    break;
  case(SYS_ftruncate):
    ret = io_syscall_ftruncate((int)arg0, (off_t)arg1);
    break;
  case(SYS_sync):
    ret = io_syscall_sync();
    break;
  case(SYS_fsync):
    ret = io_syscall_fsync((int)arg0);
    break;
  case(SYS_close):
    ret = io_syscall_close((int)arg0);
    break;
#endif /* IO_SYSCALL_WRAPPING */


  case(RUNTIME_SYSCALL_UNKNOWN):
  default:
    print_strace("[runtime] syscall %ld not implemented\r\n", (unsigned long) n);
    ret = -1;
    break;
  }

  /* store the result in the stack */
  ctx->regs.a0 = ret;
  return;
}
