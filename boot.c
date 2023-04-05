#include <asm/csr.h>

#include "printf.h"
#include "interrupt.h"
#include "syscall.h"
#include "vm.h"
#include "string.h"
#include "sbi.h"
#include "freemem.h"
#include "mm.h"
#include "env.h"
#include "paging.h"
#include "elf.h"
#include "loader/loader.h"

/* defined in vm.h */
extern uintptr_t shared_buffer;
extern uintptr_t shared_buffer_size;

/* initial memory layout */
uintptr_t utm_base;
size_t utm_size;

/* defined in entry.S */
extern void* encl_trap_handler;

#ifdef USE_FREEMEM

static int print_pgtable(int level, pte* tb, uintptr_t vaddr)
{
  pte* walk;
  int ret = 0;
  int i=0;

   for (walk=tb, i=0; walk < tb + ((1<<12)/sizeof(pte)) ; walk += 1, i++)
  {
    if(*walk == 0)
      continue;

     pte e = *walk;
    uintptr_t phys_addr = (e >> 10) << 12;

    if(level == 1 || (e & PTE_R) || (e & PTE_W) || (e & PTE_X))
    {
      printf("[pgtable] level:%d, base: 0x%lx, i:%d (0x%lx -> 0x%lx), flags: 0x%lx\r\n", level, tb, i, ((vaddr << 9) | (i&0x1ff))<<12, phys_addr, e & PTE_FLAG_MASK);
    }
    else
    {
      printf("[pgtable] level:%d, base: 0x%lx, i:%d, pte: 0x%lx, flags: 0x%lx\r\n", level, tb, i, e, e & PTE_FLAG_MASK);
    }

    if(level > 1 && !(e & PTE_R) && !(e & PTE_W) && !(e & PTE_X))
    {
      if(level == 3 && (i&0x100))
        vaddr = 0xffffffffffffffffUL;
      ret |= print_pgtable(level - 1, (pte*) __va(phys_addr), (vaddr << 9) | (i&0x1ff));
    }
  }
  return ret;
}

int verify_and_load_elf_file(uintptr_t ptr, size_t file_size, bool is_eapp) {
  int ret = 0;
  // validate elf 
  if (((void*) ptr == NULL) || (file_size <= 0)) {
    return -1; 
  }
  
  // create elf struct
  elf_t elf_file;
  ret = elf_newFile((void*) ptr, file_size, &elf_file);
  if (ret < 0) {
    return ret;
  }

  // parse and load elf file
  ret = loadElf(&elf_file);

  if (is_eapp) { // setup entry point
    uintptr_t entry = elf_getEntryPoint(&elf_file);
    csr_write(sepc, entry);
  }
  return ret;
}


/* initialize free memory with a simple page allocator*/
void
init_freemem()
{
  spa_init(freemem_va_start, freemem_size);
}

#endif // USE_FREEMEM

/* initialize user stack */
void
init_user_stack_and_env()
{
  void* user_sp = (void*) EYRIE_USER_STACK_START;

#ifdef USE_FREEMEM
  size_t count;
  uintptr_t stack_end = EYRIE_USER_STACK_END;
  size_t stack_count = EYRIE_USER_STACK_SIZE >> RISCV_PAGE_BITS;


  // allocated stack pages right below the runtime
  count = alloc_pages(vpn(stack_end), stack_count,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);

  assert(count == stack_count);

#endif // USE_FREEMEM

  // setup user stack env/aux
  user_sp = setup_start(user_sp);

  // prepare user sp
  csr_write(sscratch, user_sp);
}

void
eyrie_boot(uintptr_t dummy, // $a0 contains the return value from the SBI
           uintptr_t dram_base,
           uintptr_t dram_size,
           uintptr_t runtime_paddr,
           uintptr_t user_paddr,
           uintptr_t free_paddr,
           uintptr_t utm_vaddr,
           uintptr_t utm_size) 
{
  /* set initial values */
  load_pa_start = dram_base;
  root_page_table = (pte*) __va(csr_read(satp) << RISCV_PAGE_BITS);
  shared_buffer = EYRIE_UNTRUSTED_START;
  shared_buffer_size = utm_size;
  runtime_va_start = (uintptr_t) &rt_base;
  kernel_offset = runtime_va_start - runtime_paddr;

  debug("ROOT PAGE TABLE: 0x%lx", root_page_table);
  debug("UTM : 0x%lx-0x%lx (%u KB)", utm_vaddr, utm_vaddr+utm_size, utm_size/1024);
  debug("DRAM: 0x%lx-0x%lx (%u KB)", dram_base, dram_base + dram_size, dram_size/1024);
  debug("USER: 0x%lx-0x%lx (%u KB)", user_paddr, free_paddr, (user_paddr-free_paddr)/1024);

  /* set trap vector */
  csr_write(stvec, &encl_trap_handler);
#ifdef USE_FREEMEM
  freemem_va_start = __va(free_paddr);
  freemem_size = dram_base + dram_size - free_paddr;

  debug("FREE: 0x%lx-0x%lx (%u KB), va 0x%lx", free_paddr, dram_base + dram_size, freemem_size/1024, freemem_va_start);

  /* initialize free memory */
  init_freemem();

  print_pgtable(3, root_page_table, 0);

  /* load eapp elf */
  verify_and_load_elf_file(__va(user_paddr), free_paddr-user_paddr, true);

  //TODO: This should be set by walking the userspace vm and finding
  //highest used addr. Instead we start partway through the anon space
  set_program_break(EYRIE_ANON_REGION_START + (1024 * 1024 * 1024));

  #ifdef USE_PAGING
  init_paging(user_paddr, free_paddr);
  #endif /* USE_PAGING */
#endif /* USE_FREEMEM */

  /* initialize user stack */
  init_user_stack_and_env();

  /* prepare edge & system calls */
  init_edge_internals();

  print_pgtable(3, root_page_table, 0);

  /* set timer */
  init_timer();

  /* Enable the FPU */
  csr_write(sstatus, csr_read(sstatus) | 0x6000);

  debug("eyrie boot finished. drop to the user land ...");
  /* booting all finished, droping to the user land */
  return;
}
