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
#include "vm.h"
#include "page_replacement.h"
#include "oram.h"
#include "syscall_nums.h"
#include "interrupt.h"
#ifdef IO_SYSCALL_WRAPPING
#include "io_wrap.h"
#endif /* IO_SYSCALL_WRAPPING */

#ifdef LINUX_SYSCALL_WRAPPING
#include "linux_wrap.h"
#endif /* LINUX_SYSCALL_WRAPPING */
#include "rt_util.h"
extern void exit_enclave(uintptr_t arg0);

#define COPY_TO_USER 1
#define COPY_FROM_USER 2
//char backup_shared_memory[BACKUP_BUFFER_SIZE];// If we need to bring in a page during an ocall, then we need to make another ocall to bring in the page. Since shared memory contents will get overwritten because of the ocal that brings in the page we are taking a backup of the shared memory contents before the ocall to bring a page takes place.

uintptr_t dispatch_edgecall_syscall(edge_syscall_t* syscall_data_ptr, size_t data_len){
  is_rt=1;
  int ret;

  // Syscall data should already be at the edge_call_data section
  /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */

  struct edge_call_t* edge_call = ((struct edge_call_t*)shared_buffer);

  edge_call->call_id = EDGECALL_SYSCALL;


  if(edge_call_setup_call(edge_call, (void*)syscall_data_ptr, data_len) != 0){

    return -1;
  }

  ret = SBI_CALL_1(SBI_SM_STOP_ENCLAVE, 1);
  csr_write(sstatus, csr_read(sstatus) | 0x6000);// uncomment after checking
  init_timer();
  if (ret != 0) {

    return -1;
  }

  if(edge_call->return_data.call_status != CALL_STATUS_OK){

    return -1;
  }

  uintptr_t return_ptr;
  if(edge_call_ret_ptr(edge_call, &return_ptr) != 0){

    return -1;
  }
  is_rt=0;
  return *(uintptr_t*)return_ptr;
}

//----------------------------------------------------------------------------------------------------------
uintptr_t copy_from_user_page_wise(void* buffer_data_start, void* data, size_t data_len)
{

  /*
  This function copies from user enclave page to shared memory. The way it does is first it checks whether the user enclave page is present in memory by doing a software page table walk.
  Incase it is not present then it brings in that page and copies that data. The copying is done page. In this way we are able to avoid the page fault for user enclave page in supervisor mode

  */
  is_rt=1;
  fault_mode=0;

  if( data==0)
      return 0;


  uintptr_t *root_page_table_addr=get_root_page_table_addr();
  uintptr_t no_of_bytes_completed = 0;
  uintptr_t starting_addr_utm=(uintptr_t)buffer_data_start;
  uintptr_t starting_addr_data=(uintptr_t)data;
  size_t length = PAGE_UP(starting_addr_data) - starting_addr_data;
  length= data_len>length?length:data_len;
  //char backup_shared_memory[BACKUP_BUFFER_SIZE];// If we need to bring in a page during an ocall, then we need to make another ocall to bring in the page. Since shared memory contents will get overwritten because of the ocal that brings in the page we are taking a backup of the shared memory contents before the ocall to bring a page takes place.
  uintptr_t *status_find_address=0;
  status_find_address=__walk(root_page_table_addr,starting_addr_data);
  if(status_find_address==0)
  {
    printf("[runtime] Unmapped address in dispatch_edgecall_ocall. Fatal error. Exiting.\n");
    sbi_exit_enclave(-1);

  }

  if( !( (*status_find_address) & PTE_V    )  )// change 1 to PTE_V
  {
    copy_to_user(   (void*)backup_shared_memory,(void*)shared_buffer,buff_size);//taking backup
    handle_page_fault(starting_addr_data,status_find_address);
    if(debug)
      printf("[runtime] page fault during copy_from_user_page_wise on 0x%lx\n",PAGE_DOWN(starting_addr_data) );

    copy_from_user((void*)shared_buffer,(void*)backup_shared_memory,buff_size);
  }

  copy_from_user((void*)starting_addr_utm,(void*)starting_addr_data,length);

  no_of_bytes_completed+=length;
  starting_addr_utm+=length;
  starting_addr_data+=length;

  while( (data_len-no_of_bytes_completed)>=RISCV_PAGE_SIZE)
  {
    //repeat the same
    status_find_address=__walk(root_page_table_addr,starting_addr_data);
    if(status_find_address==0)
    {
      printf("[runtime] Unmapped address in dispatch_edgecall_ocall. Fatal error. Exiting.\n");
      sbi_exit_enclave(-1);
    }

    if( !( (*status_find_address) & PTE_V    )  )// change 1 to PTE_V
    {
      copy_to_user(   (void*)backup_shared_memory,(void*)shared_buffer,buff_size);//taking backup
      handle_page_fault(starting_addr_data,status_find_address);
      if(debug)
        printf("[runtime] page fault during copy_from_user_page_wise on 0x%lx\n",PAGE_DOWN(starting_addr_data) );
      copy_from_user((void*)shared_buffer,(void*)backup_shared_memory,buff_size);
    }

    copy_from_user((void*)starting_addr_utm,(void*)starting_addr_data,RISCV_PAGE_SIZE);
    no_of_bytes_completed+=RISCV_PAGE_SIZE;
    starting_addr_utm+=RISCV_PAGE_SIZE;
    starting_addr_data+=RISCV_PAGE_SIZE;
  }
  status_find_address=__walk(root_page_table_addr,starting_addr_data);
  if(status_find_address==0)
  {
    printf("[runtime] Unmapped address in dispatch_edgecall_ocall. Fatal error. Exiting.\n");
    sbi_exit_enclave(-1);
  }

  if( !( (*status_find_address) & PTE_V    )  )// change 1 to PTE_V
  {
    copy_to_user(   (void*)backup_shared_memory,(void*)shared_buffer,buff_size);//taking backup
    handle_page_fault(starting_addr_data,status_find_address);
    if(debug)
      printf("[runtime] page fault during copy_from_user_page_wise on 0x%lx\n",PAGE_DOWN(starting_addr_data) );

    copy_from_user((void*)shared_buffer,(void*)backup_shared_memory,buff_size);
  }
  length = data_len-no_of_bytes_completed;
 is_rt=0;
 //init_timer();
 return copy_from_user((void*)starting_addr_utm,(void*)starting_addr_data,length);

}
//------------------------------------------------------------------------------
uintptr_t copy_to_user_page_wise(void* data,void* buffer_data_start,  size_t data_len)
{
  is_rt=1;
  fault_mode=1;
  if( data_len==0)
      return 0;

  uintptr_t *root_page_table_addr=get_root_page_table_addr();
  uintptr_t no_of_bytes_completed = 0;
  uintptr_t starting_addr_utm=(uintptr_t)buffer_data_start;
  uintptr_t starting_addr_data=(uintptr_t)data;
  size_t length = PAGE_UP(starting_addr_data) - starting_addr_data;
  length= data_len>length?length:data_len;
  //char backup_shared_memory[buff_size];
  uintptr_t *status_find_address=0;
  status_find_address=__walk(root_page_table_addr,starting_addr_data);
  if(status_find_address==0)
  {
    printf("[runtime] Unmapped address in dispatch_edgecall_ocall. Fatal error. Exiting.\n");
    sbi_exit_enclave(-1);
  }

  if( !( (*status_find_address) & PTE_V    )  )// change 1 to PTE_V
  {
    copy_to_user(   (void*)backup_shared_memory,(void*)shared_buffer,buff_size);//taking backup
    handle_page_fault(starting_addr_data,status_find_address);
    if(debug)
      printf("[runtime] page fault during copy_to_user_page_wise on 0x%lx\n",PAGE_DOWN(starting_addr_data) );
    copy_from_user((void*)shared_buffer,(void*)backup_shared_memory,buff_size);
  }

  copy_to_user((void*)starting_addr_data,(void*)starting_addr_utm,length);
  no_of_bytes_completed+=length;
  starting_addr_utm+=length;
  starting_addr_data+=length;

  while( (data_len-no_of_bytes_completed)>=RISCV_PAGE_SIZE)
  {
    //repeat the same
    status_find_address=__walk(root_page_table_addr,starting_addr_data);
    if(status_find_address==0)
    {
      printf("[runtime] Unmapped address in dispatch_edgecall_ocall. Fatal error. Exiting.\n");
      sbi_exit_enclave(-1);

    }

    if( !( (*status_find_address) & PTE_V    )  )// change 1 to PTE_V
    {
      copy_to_user(   (void*)backup_shared_memory,(void*)shared_buffer,buff_size);//taking backup
      handle_page_fault(starting_addr_data,status_find_address);
      if(debug)
        printf("[runtime] page fault during copy_to_user_page_wise on 0x%lx\n",PAGE_DOWN(starting_addr_data) );
      copy_from_user((void*)shared_buffer,(void*)backup_shared_memory,buff_size);
    }

    copy_to_user((void*)starting_addr_data,(void*)starting_addr_utm,RISCV_PAGE_SIZE);
    no_of_bytes_completed+=RISCV_PAGE_SIZE;
    starting_addr_utm+=RISCV_PAGE_SIZE;
    starting_addr_data+=RISCV_PAGE_SIZE;

  }

  status_find_address=__walk(root_page_table_addr,starting_addr_data);
  if(status_find_address==0)
  {
    printf("[runtime] Unmapped address in dispatch_edgecall_ocall. Fatal error. Exiting.\n");
    sbi_exit_enclave(-1);
  }

  if( !( (*status_find_address) & PTE_V    )  )// change 1 to PTE_V
  {
    copy_to_user(   (void*)backup_shared_memory,(void*)shared_buffer,buff_size);//taking backup
    handle_page_fault(starting_addr_data,status_find_address);
    if(debug)
      printf("[runtime] page fault during copy_to_user_page_wise on 0x%lx\n",PAGE_DOWN(starting_addr_data) );
    copy_to_user((void*)shared_buffer,(void*)backup_shared_memory,buff_size);
  }

  length = data_len-no_of_bytes_completed;
 is_rt=0;
 //init_timer();
 return  copy_to_user((void*)starting_addr_data,(void*)starting_addr_utm,length);

}
//------------------------------------------------------------------------------

void zero_out_shared_buffer()
{
  for(int i=0;i<buff_size;i++) *((char*)shared_buffer+i)=0;
}
//------------------------------------------------------------------------------
uintptr_t dispatch_edgecall_ocall( unsigned long call_id,
				   void* data, size_t data_len,
				   void* return_buffer, size_t return_len,uintptr_t arg6){// arg6 will store the address where the actual return data will be stored. return_buffer stores the return data metadata i.e the offset , size etc

  uintptr_t ret;
  /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */

  //zero_out_shared_buffer();// this is done to remove transferred data from previous ocalls

  /*
  uintptr_t zs= BACKUP_BUFFER_SIZE<data_len?BACKUP_BUFFER_SIZE:data_len;
  *((char*)shared_buffer+zs)=0;
  *((char*)shared_buffer+BACKUP_BUFFER_SIZE-1)=0;
  */
  //printf("[syscal] dispatch edgecall starts\n" );

  struct edge_call_t* edge_call = ((struct edge_call_t*)shared_buffer);

  /* We encode the call id, copy the argument data into the shared
   * region, calculate the offsets to the argument data, and then
   * dispatch the ocall to host */

  edge_call->call_id = call_id;
  uintptr_t buffer_data_start = edge_call_data_ptr();
  if(data_len > (shared_buffer_size - (buffer_data_start - shared_buffer))){

    goto ocall_error;
  }
  //TODO safety check on source
  //printf("[runtime] before copy_from_user_page_wise \n  ");
  copy_from_user_page_wise((void*)buffer_data_start, (void*)data, data_len);
  //printf("[runtime] copy_from_user_page_wise done  ");
  if(edge_call_setup_call(edge_call, (void*)buffer_data_start, data_len) != 0){

    goto ocall_error;
  }

  //printf("[syscall.c]calling val= %d\n",call_id );
  ret = SBI_CALL_1(SBI_SM_STOP_ENCLAVE, 1);
  csr_write(sstatus, csr_read(sstatus) | 0x6000);// uncomment after checking

  init_timer();
  //printf("[syscall.c]returned after ocall val=%d\n",call_id );
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

  copy_to_user_page_wise(return_buffer, (void*)return_ptr, return_len);
  //printf("[syscal] dispatch edgecall and copy_to_user_page_wise ends\n" );
  if(arg6!=0)// arg6!=0 means we are try to store some return data
  {
    edge_data_t pkgstr;
    memcpy( (void*)&pkgstr,  (void*)return_ptr,return_len );
    handle_copy_from_shared(  (void*)arg6, pkgstr.offset,pkgstr.size);
  }

  return 0;

 ocall_error:
  /* TODO In the future, this should fault */
  return 1;
}
//----------------------------------------------------------------------------------------------------------

uintptr_t handle_copy_from_shared(void* dst, uintptr_t offset, size_t size){

  /* This is where we would handle cache side channels for a given
     platform */

  /* The only safety check we do is to confirm all data comes from the
   * shared region. */
  uintptr_t src_ptr=offset;

  if(edge_call_get_ptr_from_offset(offset, size,
				   &src_ptr) != 0){
    return 1;
  }
  return copy_to_user_page_wise(dst, (void*)src_ptr, size);
}
//------------------------------------------------------------------------------------------------------------
void init_edge_internals(){
  edge_call_init_internals(shared_buffer, shared_buffer_size);
}
//------------------------------------------------------------------------------------------------------------


uintptr_t handle_sbrk(size_t bytes)
{
  return rt_handle_sbrk(bytes);
}
uintptr_t handle_srand(size_t loc,size_t sz)
{
  /*
  uintptr_t *root_page_table_addr=get_root_page_table_addr();
  uintptr_t *status_find_address=0;
  status_find_address=__walk(root_page_table_addr,loc);



  if(status_find_address==0)
  {
    printf("[runtime] Unmapped address in dispatch_edgecall_ocall. Fatal error. Exiting.\n");
    sbi_exit_enclave(-1);
  }

  if( !( (*status_find_address) & PTE_V    )  )// change 1 to PTE_V
  {
    //copy_to_user(   (void*)backup_shared_memory,(void*)shared_buffer,BACKUP_BUFFER_SIZE);//taking backup
    handle_page_fault(loc,status_find_address);
    if(!tracing)
      printf("[runtime] page fault during handle_srand on 0x%lx\n",PAGE_DOWN(loc) );
    //copy_to_user((void*)shared_buffer,(void*)backup_shared_memory,BACKUP_BUFFER_SIZE);
  }
  */
  rt_util_getrandom((void*) loc, sz);



  return 0;

}
//------------------------------------------------------------------------------------------------------------
void handle_syscall(struct encl_ctx_t* ctx)
{
  uintptr_t n = ctx->regs.a7;
  uintptr_t arg0 = ctx->regs.a0;
  uintptr_t arg1 = ctx->regs.a1;
  uintptr_t arg2 = ctx->regs.a2;
  uintptr_t arg3 = ctx->regs.a3;
  uintptr_t arg4 = ctx->regs.a4;

  uintptr_t arg6 = ctx->regs.a6;


  // We only use arg5 in these for now, keep warnings happy.
#ifdef IO_SYSCALL_WRAPPING
  uintptr_t arg5 = ctx->regs.a5;
#endif /* IO_SYSCALL_WRAPPING */
  uintptr_t ret = 0;

  ctx->regs.sepc += 4;

  switch (n) {
  case(RUNTIME_SYSCALL_EXIT):
    SBI_CALL_1(SBI_SM_EXIT_ENCLAVE, arg0);
    break;
  case(RUNTIME_SYSCALL_OCALL):
    ret = dispatch_edgecall_ocall(arg0, (void*)arg1, arg2, (void*)arg3, arg4,arg6);
    break;
  case(RUNTIME_SYSCALL_SHAREDCOPY):
    ret = handle_copy_from_shared((void*)arg0, arg1, arg2);
    break;
  case(RUNTIME_SYSCALL_ATTEST_ENCLAVE):;
    uintptr_t arg0_trans = translate(arg0);
    uintptr_t arg1_trans = translate(arg1);
    ret = SBI_CALL_3(SBI_SM_ATTEST_ENCLAVE, arg0_trans, arg1_trans, arg2);
    //print_strace("[ATTEST] p1 0x%p->0x%p p2 0x%p->0x%p sz %lx = %lu\r\n",arg0,arg0_trans,arg1,arg1_trans,arg2,ret);
    break;


  case(RUNTIME_SYSCALL_SBRK):;

    ret = handle_sbrk(arg0);
    break;

  case(RUNTIME_SYSCALL_RAND):;
    ret = handle_srand(arg0,arg1);
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
    SBI_CALL_1(SBI_SM_EXIT_ENCLAVE, arg0);
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
  csr_write(sstatus, csr_read(sstatus) | 0x6000);// uncomment after checking
  //init_timer();
  return;
}
