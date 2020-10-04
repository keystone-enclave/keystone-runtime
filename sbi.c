#include "sbi.h"

#include "vm_defs.h"
#include "uaccess.h"
#include "vm.h"
#include "mailbox.h"

#define SBI_CALL(___which, ___arg0, ___arg1, ___arg2)            \
  ({                                                             \
    register uintptr_t a0 __asm__("a0") = (uintptr_t)(___arg0);  \
    register uintptr_t a1 __asm__("a1") = (uintptr_t)(___arg1);  \
    register uintptr_t a2 __asm__("a2") = (uintptr_t)(___arg2);  \
    register uintptr_t a7 __asm__("a7") = (uintptr_t)(___which); \
    __asm__ volatile("ecall"                                     \
                     : "+r"(a0)                                  \
                     : "r"(a1), "r"(a2), "r"(a7)                 \
                     : "memory");                                \
    a0;                                                          \
  })

/* Lazy implementations until SBI is finalized */
#define SBI_CALL_0(___which) SBI_CALL(___which, 0, 0, 0)
#define SBI_CALL_1(___which, ___arg0) SBI_CALL(___which, ___arg0, 0, 0)
#define SBI_CALL_2(___which, ___arg0, ___arg1) \
  SBI_CALL(___which, ___arg0, ___arg1, 0)
#define SBI_CALL_3(___which, ___arg0, ___arg1, ___arg2) \
  SBI_CALL(___which, ___arg0, ___arg1, ___arg2)

void
sbi_putchar(char character) {
  SBI_CALL_1(SBI_CONSOLE_PUTCHAR, character);
}

void
sbi_set_timer(uint64_t stime_value) {
#if __riscv_xlen == 32
  SBI_CALL_2(SBI_SET_TIMER, stime_value, stime_value >> 32);
#else
  SBI_CALL_1(SBI_SET_TIMER, stime_value);
#endif
}

uintptr_t
sbi_stop_enclave(uint64_t request) {
  return SBI_CALL_1(SBI_SM_STOP_ENCLAVE, request);
}

void
sbi_exit_enclave(uint64_t retval) {
  SBI_CALL_1(SBI_SM_EXIT_ENCLAVE, retval);
}

uintptr_t
sbi_random() {
  return SBI_CALL_0(SBI_SM_RANDOM);
}

uintptr_t
sbi_query_multimem() {
  return SBI_CALL_2(
      SBI_SM_CALL_PLUGIN, SM_MULTIMEM_PLUGIN_ID, SM_MULTIMEM_CALL_GET_SIZE);
}

uintptr_t
sbi_query_multimem_addr() {
  return SBI_CALL_2(
      SBI_SM_CALL_PLUGIN, SM_MULTIMEM_PLUGIN_ID, SM_MULTIMEM_CALL_GET_ADDR);
}

uintptr_t
sbi_attest_enclave(void* report, void* buf, uintptr_t len) {
  return SBI_CALL_3(SBI_SM_ATTEST_ENCLAVE, report, buf, len);
}

int mem_share(size_t uid, uintptr_t enclave_addr, uintptr_t enclave_size){
   int ret;
   uintptr_t phys_e_addr;
   uintptr_t phys_e_size;

   uintptr_t addr_phys_e_addr = kernel_va_to_pa(&phys_e_addr);
   uintptr_t addr_phys_e_size = kernel_va_to_pa(&phys_e_size);

   ret = SBI_CALL_3(SBI_SM_MEM_SHARE, (uintptr_t) uid, addr_phys_e_addr, addr_phys_e_size);

   copy_to_user((void *) enclave_addr, &phys_e_addr, sizeof(uintptr_t));
   copy_to_user((void *) enclave_size, &phys_e_size, sizeof(uintptr_t));
   return ret;
}

int mem_stop(size_t uid){
   int ret;
   ret = SBI_CALL_1(SBI_SM_MEM_STOP, (uintptr_t) uid);
   return ret;
}

/*
  Retrieves a message from the mailbox from sender uid
  Copies at most buf_size bytes to buf from the message contents
  If no message is present, this will block.
  Returs the bytes written to buf.
*/
int recv_mailbox_msg(size_t uid, void *buf, size_t buf_size){
  int ret;
  char cpy[256];
  uintptr_t ptr = kernel_va_to_pa(cpy);

  ret = SBI_CALL_3(SBI_SM_MAILBOX_RECV, (uintptr_t) uid, ptr, buf_size);
  copy_to_user(buf, cpy, buf_size);
  return ret;
}
/*
  Sends a msg_size byte message copied from buf to uid
  Calls the SBI function to trap to the SM
  We do not acquire a lock here because the SM will acquire the lock.
*/
int send_mailbox_msg(size_t uid, void *buf, size_t msg_size){
  int ret;
  char cpy[256];
  uintptr_t ptr = kernel_va_to_pa(cpy);

  if(msg_size > MAILBOX_SIZE)
     return MAILBOX_ERROR;
  copy_from_user(cpy, buf, msg_size);
  ret = SBI_CALL_3(SBI_SM_MAILBOX_SEND, (uintptr_t) uid, ptr, msg_size);
  return ret;
}

size_t get_uid(void *uid){
  int ret;
  size_t cpy_ptr;
  uintptr_t phys_ptr = kernel_va_to_pa(&cpy_ptr);
  ret = SBI_CALL_1(SBI_SM_UID, phys_ptr);
  copy_to_user(uid, (void *) &cpy_ptr, sizeof(size_t));
  return ret;
}

uintptr_t
sbi_get_sealing_key(uintptr_t key_struct, uintptr_t key_ident, uintptr_t len) {
  return SBI_CALL_3(SBI_SM_GET_SEALING_KEY, key_struct, key_ident, len);
}
