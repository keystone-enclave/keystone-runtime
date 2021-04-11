#include <asm/csr.h>

#define SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE 0x08424b45
#define SBI_SM_SNAPSHOT          3007

#if __riscv_xlen == 64
#define STORE sd
#define LOAD ld
#define LOG_REGBYTES  3
#define WORD .dword
#elif __riscv_xlen == 32
#define STORE sw
#define LOAD lw
#define LOG_REGBYTES  2
#define WORD .word
#endif

#define LWU lwu
#define REGBYTES (1<<LOG_REGBYTES)
#define ENCL_CONTEXT_SIZE (REGBYTES*35)
#define HOST_CONTEXT_SIZE (REGBYTES*32)


sbi_snapshot:
  .global sbi_snapshot
  j snapshot_trampoline

snapshot_trampoline:
  .global snapshot_trampoline

  // change stvec to the dummy access fault handler
  la t0, first_access_fault
  csrw stvec, t0

  // call snapshot() sbi
  li a6, SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE
  li a0, SBI_SM_SNAPSHOT
  ecall

  // return from snapshot().
  // a0: dram base
  // a1: dram size

// caution: this should not touch stack
first_access_fault:


