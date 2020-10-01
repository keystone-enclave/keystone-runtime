#include "sbi.h"

#include "vm_defs.h"

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

uintptr_t
sbi_get_sealing_key(uintptr_t key_struct, uintptr_t key_ident, uintptr_t len) {
  return SBI_CALL_3(SBI_SM_GET_SEALING_KEY, key_struct, key_ident, len);
}