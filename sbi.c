#include "sbi.h"

#include "vm_defs.h"
#include "vm.h"
#include "mm.h"
#include "freemem.h"
#define SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2)    \
  ({                                                             \
    register uintptr_t a0 __asm__("a0") = (uintptr_t)(___arg0);  \
    register uintptr_t a1 __asm__("a1") = (uintptr_t)(___arg1);  \
    register uintptr_t a2 __asm__("a2") = (uintptr_t)(___arg2);  \
    register uintptr_t a6 __asm__("a6") = (uintptr_t)(___which); \
    register uintptr_t a7 __asm__("a7") = (uintptr_t)(___ext);   \
    __asm__ volatile("ecall"                                     \
                     : "+r"(a0)                                  \
                     : "r"(a1), "r"(a2), "r"(a6), "r"(a7)        \
                     : "memory");                                \
    a0;                                                          \
  })

/* Lazy implementations until SBI is finalized */
#define SBI_CALL_0(___ext, ___which) SBI_CALL(___ext, ___which, 0, 0, 0)
#define SBI_CALL_1(___ext, ___which, ___arg0) SBI_CALL(___ext, ___which, ___arg0, 0, 0)
#define SBI_CALL_2(___ext, ___which, ___arg0, ___arg1) \
  SBI_CALL(___ext, ___which, ___arg0, ___arg1, 0)
#define SBI_CALL_3(___ext, ___which, ___arg0, ___arg1, ___arg2) \
  SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2)

void
sbi_putchar(char character) {
  SBI_CALL_1(SBI_CONSOLE_PUTCHAR, 0, character);
}

void
sbi_set_timer(uint64_t stime_value) {
#if __riscv_xlen == 32
  SBI_CALL_2(SBI_SET_TIMER, 0, stime_value, stime_value >> 32);
#else
  SBI_CALL_1(SBI_SET_TIMER, 0, stime_value);
#endif
}

uintptr_t
sbi_stop_enclave(uint64_t request) {
  return SBI_CALL_1(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_STOP_ENCLAVE, request);
}

void
sbi_exit_enclave(uint64_t retval) {
  SBI_CALL_1(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_EXIT_ENCLAVE, retval);
}

uintptr_t
sbi_random() {
  return SBI_CALL_0(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_RANDOM);
}

uintptr_t
sbi_query_multimem() {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_CALL_PLUGIN, SM_MULTIMEM_PLUGIN_ID, SM_MULTIMEM_CALL_GET_SIZE);
}

uintptr_t
sbi_query_multimem_addr() {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_CALL_PLUGIN, SM_MULTIMEM_PLUGIN_ID, SM_MULTIMEM_CALL_GET_ADDR);
}

uintptr_t
sbi_attest_enclave(void* report, void* buf, uintptr_t len) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_ATTEST_ENCLAVE, report, buf, len);
}

uintptr_t
sbi_get_sealing_key(uintptr_t key_struct, uintptr_t key_ident, uintptr_t len) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_GET_SEALING_KEY, key_struct, key_ident, len);
}

extern void rtbreakpoint();
uintptr_t
sbi_snapshot()
{
  uintptr_t pc = kernel_va_to_pa(&boot_cloned_enclave);
  //uintptr_t resume_va = kernel_va_to_pa(&rtbreakpoint);
  //if(resume_va);
  //trap_table[RISCV_EXCP_STORE_FAULT] = (uintptr_t) handle_copy_write;
  snapshot_trampoline(pc);
  register uintptr_t a0 __asm__ ("a0"); /* dram base */
  register uintptr_t a1 __asm__ ("a1"); /* dram size */
  register uintptr_t a2 __asm__ ("a2"); /* next free page */

  uintptr_t dram_base, dram_size, next_free;

  dram_base = a0;
  dram_size = a1;
  next_free = a2;
  debug("dram_base: %lx\n", dram_base);
  debug("dram_size: %lx\n", dram_size);
  debug("next_free: %lx\n", next_free);

  uintptr_t runtime_paddr = dram_base + 3*(1<<RISCV_PAGE_BITS);

  freemem_va_start = EYRIE_LOAD_START + (next_free - dram_base);
  freemem_size = (dram_base + dram_size) - next_free;
  debug("freemem start = %lx", freemem_va_start);
  debug("freemem size = %d", freemem_size);

  /* remap kernel */
  //remap_kernel_space(runtime_paddr, 0x1a000);

  /* update parameters */
  load_pa_start = dram_base;
  kernel_offset = runtime_va_start - runtime_paddr;

  /* remap physical memory */
  remap_kernel_space(runtime_paddr, 0x1a000);
  map_with_reserved_page_table(dram_base, dram_size, EYRIE_LOAD_START, load_l2_page_table, load_l3_page_table);

  csr_write(satp, satp_new(kernel_va_to_pa(root_page_table)));

  /* copy root page table */
  copy_root_page_table();

  debug("runtime_paddr = %lx", kernel_va_to_pa(&rt_base));
  debug("runtime_paddr(walk) = %lx", translate((uintptr_t)&rt_base));
  debug("free_pa = %lx", __pa(freemem_va_start));
  debug("free_pa(walk) = %lx", translate(freemem_va_start));


  /* re-init freemem */
  spa_init(freemem_va_start, freemem_size);
  return 0;
}
