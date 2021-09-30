#include <asm/csr.h>

#define SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE 0x08424b45
#define SBI_SM_SNAPSHOT          3007
#define SBI_SM_EXIT_ENCLAVE      3006
#define PTE_PPN_SHIFT 10

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
  addi sp, sp, (-14*REGBYTES)
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
  // also store sstatus
  csrr t0, sstatus
  STORE t0, 13*REGBYTES(sp)

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
  // store all of them to saved registers (s4 is already there)
  // s6: current free list

  add s0, a0, x0
  add s1, a1, x0
  add s2, a2, x0
  add s3, a3, x0
  mv s6, s0

  // copy root page table
  // (s4 << PAGE_SHIFT) to get original root page table PA
  slli a7, s4, PAGE_SHIFT
  jal ra, copy_page_a7 /* uses t0, t1, t2, t3 */

  // remap kernel
  // start: rt_base
  // end: kernel_stack_end
  la t5, rt_base
  la t6, kernel_stack_end // # of pages for the kernel
  sub t6, t6, t5
  srli t6, t6, PAGE_SHIFT
  li s11, 0x0 // # of stack pages mapped
__map_stack_page:
  beq t6, s11, snapshot_trampoline_exit
  slli a0, s11, PAGE_SHIFT
  add a0, t5, a0
  j relocate_virtual_page_a0
__ra_relocate_virtual_page_a0:
  addi s11, s11, 1
  j __map_stack_page

/*******************************/
/* uses: t0-t4 */
relocate_virtual_page_a0:
  // a0: virtual page address to relocate
  // t0 = L1 page table (dram base)
  mv t0, s0

  // t1 = L1 index * 8
  mv t1, a0
  srli t1, t1, 30
  li t4, 0x1ff
  and t1, t1, t4
  slli t1, t1, 3

  // s9 = L1 PTE
  // s10 = pointer to the PTE
  add s10, t0, t1
  LOAD s9, 0(s10)

  // see if PTE is already pointing to EPM
  // t0 = (PTE >> 10) << 12
  srli t0, s9, PTE_PPN_SHIFT
  slli t0, t0, PAGE_SHIFT
  blt t0, s0, __not_in_epm_l1
  add t1, s0, s1
  bge t0, t1, __not_in_epm_l1
  // otherwise just go to next level with t0 set
  j __relocate_virtual_page_l2
__not_in_epm_l1:

  mv a7, t0
  /* uses t0, t1, t2, t3 */
  jal ra, copy_page_a7
  // a7 now contains new page address
  andi s9, s9, 0x3ff

  // t0 = L2 page table
  mv t0, a7
  srli a7, a7, 12
  slli a7, a7, 10
  or a7, a7, s9
  // a7 = new PTE
  STORE a7, 0(s10)

__relocate_virtual_page_l2:
  // t0 = L2 page table (^ previous)
  // t1 = L2 index * 8
  mv t1, a0
  srli t1, t1, 21
  li t4, 0x1ff
  and t1, t1, t4
  slli t1, t1, 3

  // s9 = L2 PTE
  // s10 = pointer to the PTE
  add s10, t0, t1
  LOAD s9, 0(s10)

  // see if PTE is a mega page
  and t4, s9, 0xE // RWX mask
  bne t4, x0, l2_is_megapage // RWX != 0 means it's megapage

  // see if PTE is already pointing to EPM
  // t0 = (PTE >> 10) << 12
  srli t0, s9, PTE_PPN_SHIFT
  slli t0, t0, PAGE_SHIFT
  blt t0, s0, __not_in_epm_l2
  add t1, s0, s1
  bge t0, t1, __not_in_epm_l2
  // otherwise just go to next level with t0 set
  j __relocate_virtual_page_l3
__not_in_epm_l2:
  mv a7, t0
  /* uses t0, t1, t2, t3 */
  jal ra, copy_page_a7
  mv t0, a7
  andi s9, s9, 0x3ff
  srli a7, a7, 12
  slli a7, a7, 10
  or a7, a7, s9
  STORE a7, 0(s10)

__relocate_virtual_page_l3:
  // t0 = L3 page table (^ previous)
  // t1 = L3 index * 8
  mv t1, a0
  srli t1, t1, 12
  li t4, 0x1ff
  and t1, t1, t4
  slli t1, t1, 3

  // s9 = L3 PTE
  // s10 = pointer to the PTE
  add s10, t0, t1
  LOAD s9, 0(s10)

  srli t0, s9, PTE_PPN_SHIFT
  slli t0, t0, PAGE_SHIFT

  mv a7, t0
  jal ra, copy_page_a7
  andi s9, s9, 0x3ff
  srli a7, a7, 12
  slli a7, a7, 10
  or a7, a7, s9
  STORE a7, 0(s10)
  j __ra_relocate_virtual_page_a0

l2_is_megapage:
  //TODO
  li a0, -1234
  li a7, SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE
  li a6, SBI_SM_EXIT_ENCLAVE
  ecall

/* relocate virtual page end */

/* copy a page from a7 into s6 and increment s6 by 4K */
/* uses t0, t1, t2, t3 */
copy_page_a7:
  // s6: dst PA
  // a7: src PA
  li t0, PAGE_SIZE
  mv t1, x0
__copy_page_loop:
  bge t1, t0, __copy_page_done
  add t2, a7, t1
  LOAD t3, 0(t2)
  add t2, s6, t1
  STORE t3, 0(t2)
  addi t1, t1, REGBYTES
  j __copy_page_loop
__copy_page_done:
  mv a7, s6
  add s6, s6, t0
  jalr x0, ra, 0

snapshot_trampoline_exit:
  // update satp (retain mode)
  srli t1, s4, 44
  slli t1, t1, 44
  srli t0, s0, PAGE_SHIFT
  or t1, t1, t0
  sfence.vma
  csrw satp, t1
resume_with_virtual_address:
  mv a0, s0 /* dram base */
  mv a1, s1 /* dram size */
  mv a2, s2 /* utm base */
  mv a3, s3 /* utm size */
  mv a4, s6 /* free page start */
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
  LOAD t0, 13*REGBYTES(sp)
  // also restore sstatus
  csrw sstatus, t0
  addi sp, sp, (14*REGBYTES)
  ret


copy_physical_page:
  .global copy_physical_page
  // a0: dst (pa)
  // a1: src (pa)
  // a2: __copy_physical_page_switch_to_pa (pa)

  /* VA */
  addi sp, sp, -(4*REGBYTES)
  STORE s0, 0*REGBYTES(sp)
  STORE s5, 1*REGBYTES(sp)
  csrr t0, sstatus
  STORE t0, 2*REGBYTES(sp)
  STORE ra, 3*REGBYTES(sp)

  // s0 = original satp
  csrr s0, satp

  // s5 = __copy_phyiscal_page_switch_to_va (va)
  la s5, __copy_physical_page_switch_to_va

  // switch stvec
  csrw stvec, a2

  sfence.vma
  csrw satp, x0

  /* PA */
.align 2
__copy_physical_page_switch_to_pa:
  .global __copy_physical_page_switch_to_pa
  // change stvec to the dummy access fault handler

  jal ra, copy_page_pa

  la t0, first_page_fault
  csrw stvec, t0
  sfence.vma
  csrw satp, s0

__copy_physical_page_switch_to_va:
  LOAD ra, 3*REGBYTES(sp)
  LOAD t0, 2*REGBYTES(sp)
  csrw sstatus, t0
  LOAD s5, 1*REGBYTES(sp)
  LOAD s0, 0*REGBYTES(sp)
  addi sp, sp, (4*REGBYTES)
  ret

/* copy a page from a1 into a0 (PA) */
copy_page_pa:
/* uses t0, t1, t2, t3 */
  // a0: dst PA
  // a1: src PA
  li t0, PAGE_SIZE
  mv t1, x0
__copy_page_pa_loop:
  bge t1, t0, __copy_page_pa_done
  add t2, a1, t1
  LOAD t3, 0(t2)
  add t2, a0, t1
  STORE t3, 0(t2)
  addi t1, t1, REGBYTES
  j __copy_page_pa_loop
__copy_page_pa_done:
  jalr x0, ra, 0


/* first fault handler after switching SATP */
.align 3
first_page_fault:
  la t0, encl_trap_handler
  csrw stvec, t0
  jalr x0, s5, 0

