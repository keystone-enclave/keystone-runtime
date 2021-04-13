#include <asm/csr.h>

#define SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE 0x08424b45
#define SBI_SM_SNAPSHOT          3007
#define SBI_SM_EXIT_ENCLAVE      3006

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
#define PAGE_SHIFT  12
#define PAGE_SIZE (1<<PAGE_SHIFT)
snapshot_trampoline:
  .global snapshot_trampoline
  addi sp, sp, (-13*REGBYTES)
  STORE s0, 0*REGBYTES(sp)
  STORE s1, 1*REGBYTES(sp)
  STORE s2, 2*REGBYTES(sp)
  STORE s3, 3*REGBYTES(sp)
  STORE s4, 4*REGBYTES(sp)
  STORE s5, 5*REGBYTES(sp)
  STORE s6, 6*REGBYTES(sp)
  STORE s7, 7*REGBYTES(sp)
  STORE s8, 8*REGBYTES(sp)
  STORE s9, 9*REGBYTES(sp)
  STORE s10, 10*REGBYTES(sp)
  STORE s11, 11*REGBYTES(sp)
  STORE ra, 12*REGBYTES(sp)

  // change stvec to the dummy access fault handler
  la t0, first_page_fault
  csrw stvec, t0
  // store original satp
  csrr s4, satp
  // store VA for resume
  la s5, resume_with_virtual_address
  // call snapshot() sbi
  li a7, SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE
  li a6, SBI_SM_SNAPSHOT

/* this includes the ecall instruction because mepc = PC + 4 */
boot_cloned_enclave:
.global boot_cloned_enclave
  ecall
  // Now, we're starting a new enclave
  // s4: original satp
  // a0: dram base --> s0
  // a1: dram size --> s1
  // a2: utm base --> s2
  // a3: utm size --> s3
  // store all of them to saved registers (s0 is already there)
  add s0, a0, x0
  add s1, a1, x0
  add s2, a2, x0
  add s3, a3, x0

  // copy root page table
  // (s4 << PAGE_SHIFT) to get original root page table PA
  slli a1, s4, PAGE_SHIFT

  /* copy_page(a0, a1) */
  jal ra, copy_page

rtbreakpoint:
  .global rtbreakpoint
  // update satp (retain mode)
  srli s4, s4, 44
  slli s4, s4, 44
  srli s0, s0, PAGE_SHIFT
  or s4, s4, s0
  sfence.vma
  csrw satp, s4

copy_page:
  // a0: dst PA
  // a1: src PA
  li t0, PAGE_SIZE
  mv t1, x0
copy_page_loop:
  bge t1, t0, copy_page_done
  add t2, a1, t1
  LOAD t3, 0(t2)
  add t2, a0, t1
  STORE t3, 0(t2)
  addi t1, t1, REGBYTES
  j copy_page_loop
copy_page_done:
  jalr x0, ra, 0

snapshot_trampoline_exit:
  LOAD s0, 0*REGBYTES(sp)
  LOAD s1, 1*REGBYTES(sp)
  LOAD s2, 2*REGBYTES(sp)
  LOAD s3, 3*REGBYTES(sp)
  LOAD s4, 4*REGBYTES(sp)
  LOAD s5, 5*REGBYTES(sp)
  LOAD s6, 6*REGBYTES(sp)
  LOAD s7, 7*REGBYTES(sp)
  LOAD s8, 8*REGBYTES(sp)
  LOAD s9, 9*REGBYTES(sp)
  LOAD s10, 10*REGBYTES(sp)
  LOAD s11, 11*REGBYTES(sp)
  LOAD ra, 12*REGBYTES(sp)
  addi sp, sp, (13*REGBYTES)

/* first fault handler after switching SATP */

resume_with_virtual_address:
  // let's just exit for now
  li a7, SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE
  li a6, SBI_SM_EXIT_ENCLAVE
  ecall

first_page_fault:
  la t0, encl_trap_handler
  csrw stvec, t0
  jalr x0, s5, 0


