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
#include "page_replacement.h"
#include "malloc.h"
#include "rt_util.h"

//#include "oram.h"

/* defined in vm.h */
extern uintptr_t shared_buffer;
extern uintptr_t shared_buffer_size;
//extern uintptr_t replacement_algo_queue[QUEUE_SIZE];
extern uintptr_t *replacement_algo_queue;

extern uintptr_t pointer;
extern uintptr_t frame_size;
//extern char *second_chance;
extern uintptr_t is_rt;
extern uintptr_t clock_counter;

//extern uintptr_t *page_addr_tbl;
//extern uintptr_t *find_index;
//extern char *access_counter;

extern uintptr_t *position;
//extern uintptr_t knocked_page_addr[QUEUE_SIZE];
extern uintptr_t *knocked_page_addr;
extern int N;
extern int L;
extern unsigned int Z;
/* initial memory layout */
uintptr_t utm_base;
size_t utm_size;

/* defined in entry.S */
extern void* encl_trap_handler;

#ifdef USE_FREEMEM
//------------------------------------------------------------------------------
void
map_physical_memory_with_megapages(uintptr_t dram_base,
                                   uintptr_t dram_size,
                                   uintptr_t ptr)
{
  uintptr_t offset = 0;

  /* we're gonna use L2 mega pages, so the memory
   * is supposed to be smaller than a gigapage */
  assert(dram_size <= RISCV_GET_LVL_PGSIZE(1));

  /* if the enclave memory is larger than a megapage,
   * it is supposed to be aligned with a megapage */
  assert(IS_ALIGNED(dram_base, RISCV_GET_LVL_PGSIZE_BITS(2)));

  /* the starting VA must be aligned with a gigapage so that
   * we can use all entries of an L2 page table */
  assert(IS_ALIGNED(ptr, RISCV_GET_LVL_PGSIZE_BITS(1)));

  /* root page table */
  root_page_table[RISCV_GET_PT_INDEX(ptr, 1)] =
    ptd_create(ppn(kernel_va_to_pa(load_l2_page_table)));

  /* map megapages */
  for (offset = 0;
       offset < dram_size;
       offset += RISCV_GET_LVL_PGSIZE(2))
  {
    load_l2_page_table[RISCV_GET_PT_INDEX(ptr + offset, 2)] =
      pte_create(ppn(dram_base + offset),
          PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);
  }
}
//------------------------------------------------------------------------------
void
map_physical_memory_with_kilopages(uintptr_t dram_base,
                                   uintptr_t dram_size,
                                   uintptr_t ptr)
{
  uintptr_t offset = 0;

  assert(dram_size <= RISCV_GET_LVL_PGSIZE(2));

  /* the memory is supposed to be aligned with a 4K page */
  assert(IS_ALIGNED(dram_base, RISCV_GET_LVL_PGSIZE_BITS(3)));

  /* the starting VA must be aligned with a megapage so that
   * we can use all entries of a last-level page table */
  assert(IS_ALIGNED(ptr, RISCV_GET_LVL_PGSIZE_BITS(2)));

  /* root page table */
  root_page_table[RISCV_GET_PT_INDEX(ptr, 1)] =
    ptd_create(ppn(kernel_va_to_pa(load_l2_page_table)));

  /* l2 page table */
  load_l2_page_table[RISCV_GET_PT_INDEX(ptr, 2)] =
    ptd_create(ppn(kernel_va_to_pa(load_l3_page_table)));

  /* map pages */
  for (offset = 0;
       offset < dram_size;
       offset += RISCV_GET_LVL_PGSIZE(3))
  {
    load_l3_page_table[RISCV_GET_PT_INDEX(ptr + offset, 3)] =
      pte_create(ppn(dram_base + offset),
          PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);
  }
}
//------------------------------------------------------------------------------
/* map entire enclave physical memory so that
 * we can access the old page table and free memory */
/* remap runtime kernel to a new root page table */
void
map_physical_memory(uintptr_t dram_base,
                    uintptr_t dram_size)
{
  uintptr_t ptr = EYRIE_LOAD_START;
  /* load address should not override kernel address */
  assert(RISCV_GET_PT_INDEX(ptr, 1) != RISCV_GET_PT_INDEX(runtime_va_start, 1));

  if (dram_size > RISCV_GET_LVL_PGSIZE(2))
    map_physical_memory_with_megapages(dram_base, dram_size, ptr);
  else
    map_physical_memory_with_kilopages(dram_base, dram_size, ptr);
}
//------------------------------------------------------------------------------
void
remap_kernel_space(uintptr_t runtime_base,
                   uintptr_t runtime_size)
{
  uintptr_t offset;

  /* eyrie runtime is supposed to be smaller than a megapage */
  assert(runtime_size <= RISCV_GET_LVL_PGSIZE(2));

  /* root page table */
  root_page_table[RISCV_GET_PT_INDEX(runtime_va_start, 1)] =
    ptd_create(ppn(kernel_va_to_pa(kernel_l2_page_table)));

  /* L2 page talbe */
  kernel_l2_page_table[RISCV_GET_PT_INDEX(runtime_va_start, 2)] =
    ptd_create(ppn(kernel_va_to_pa(kernel_l3_page_table)));

  for (offset = 0;
       offset < runtime_size;
       offset += RISCV_GET_LVL_PGSIZE(3))
  {
    kernel_l3_page_table[RISCV_GET_PT_INDEX(runtime_va_start + offset, 3)] =
      pte_create(ppn(runtime_base + offset),
          PTE_R | PTE_W | PTE_X | PTE_A | PTE_D|PTE_L);
  }
}
//------------------------------------------------------------------------------
void
copy_root_page_table()
{
  /* the old table lives in the first page */
  pte_t* old_root_page_table = (pte_t*) EYRIE_LOAD_START;
  int i;

  /* copy all valid entries of the old root page table */
  for (i = 0; i < BIT(RISCV_PT_INDEX_BITS); i++) {
    if (      old_root_page_table[i] & PTE_V   /*|| old_root_page_table[i] & (1<<8)*/ &&
        !(root_page_table[i] & PTE_V)) {
      root_page_table[i] = old_root_page_table[i];
    }
  }
}
//------------------------------------------------------------------------------
/* initialize free memory with a simple page allocator*/
void
init_freemem()
{
  spa_init(freemem_va_start, freemem_size);
}

#endif // USE_FREEMEM
//------------------------------------------------------------------------------
/* initialize user stack */
void
init_user_stack_and_env()
{
  void* user_sp = (void*) EYRIE_USER_STACK_START;

#ifdef USE_FREEMEM
  size_t count;
  uintptr_t stack_end = EYRIE_USER_STACK_END;
  size_t stack_count = EYRIE_USER_STACK_SIZE >> RISCV_PAGE_BITS;
  //printf("%d\n",__LINE__);
  // allocated stack pages right below the runtime
  count = alloc_pages(vpn(stack_end), stack_count,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U | PTE_X|PTE_L);
  //printf("%d\n",__LINE__);
  assert(count == stack_count);
#endif // USE_FREEMEM

  // setup user stack env/aux
  //printf("%d\n",__LINE__);
  user_sp = setup_start(user_sp);
  //printf("%d\n",__LINE__);
  // prepare user sp
  csr_write(sscratch, user_sp);
}
//------------------------------------------------------------------------------

void init_page_replacement_queue(uintptr_t dram_base)// this initializes the queue which is used in the page replacement algorithm
{
  //RDINSTRET
  uintptr_t ins_cnt_st=0;
  asm volatile ("rdinstret %0" : "=r" (ins_cnt_st));

  //printf("[boot.c] new ins worked\n");

  malloc(MALLOC_SIZE);
  replacement_algo_queue=(uintptr_t*)malloc(MALLOC_SIZE2*sizeof(uintptr_t));
  replacement_algo_queue_map=(uintptr_t*)malloc(MALLOC_SIZE2*sizeof(uintptr_t));
  //second_chance=(char*)malloc(MALLOC_SIZE2*sizeof(char));
  //page_addr_tbl=(uintptr_t*)malloc(MALLOC_SIZE*sizeof(uintptr_t));

  //find_index=(uintptr_t*)malloc(MALLOC_SIZE2*sizeof(uintptr_t));
  //access_counter=(char*)malloc(MALLOC_SIZE*sizeof(char));

  //memset((void*)replacement_algo_queue, 0, MALLOC_SIZE2*sizeof(uintptr_t));
  //memset((void*)replacement_algo_queue_map, 0, MALLOC_SIZE2*sizeof(uintptr_t));
  //memset((void*)access_counter, 0, MALLOC_SIZE*sizeof(char));

  //memset((void*)find_index, 0, MALLOC_SIZE2*sizeof(uintptr_t));

  // for(int i=0;i<MALLOC_SIZE2;i++)
  // {
  //   second_chance[i]='n';
  // }
  uintptr_t ins_cnt_en=0;
  asm volatile ("rdinstret %0" : "=r" (ins_cnt_en));

  //printf("[boot.c] new ins worked 2\n");
  //printf("[boot.c] ins executed %lu \n",(ins_cnt_en-ins_cnt_st));

  //printf("[BOOT.C] ")
  prev_addr=0;
  uintptr_t num_of_allocated_pages=0;num_of_allocated_pages=num_of_allocated_pages;
  uintptr_t *root_table_addr=get_root_page_table_addr();
  q_front=q_rear=-1;
  pointer=0;
  clock_counter=0;
  frame_size=MALLOC_SIZE2;
  uintptr_t last_addr = get_program_break();
  for(uintptr_t i=MIN_ENCLAVE_VADDR;i<last_addr;i+=RISCV_PAGE_SIZE)
  {
    uintptr_t * status_find_address=__walk(root_table_addr,i);
    uintptr_t pa_ppn=(*status_find_address)>>PTE_PPN_SHIFT;
    uintptr_t va_org= __va(pa_ppn<<RISCV_PAGE_BITS);
    place_new_page(va_org,i);

    //page_addr_tbl[vpn(i)]=(uintptr_t)status_find_address;
    //comment this

    if(vpn(i)>=1  )//10 for reco and 24 for picosat 40 for libjpeg 4 for avl and mat_mul
    {
        //*status_find_address=(*status_find_address & (~PTE_V) )| PTE_E ;
        *status_find_address=(*status_find_address) | PTE_L |PTE_E;
        //*status_find_address=*status_find_address & ~PTE_V;
    }




   }

}

//------------------------------------------------------------------------------
uintptr_t get_last_addr()
{
  uintptr_t *root_table_addr=get_root_page_table_addr();
  for(uintptr_t i=MIN_ENCLAVE_VADDR;;i+=RISCV_PAGE_SIZE)
  {
    uintptr_t * status_find_address=__walk(root_table_addr,i);
    if( ! (  (*status_find_address) & PTE_L ) )
    {
          return i;
    }
  }
}
//------------------------------------------------------------------------------
uintptr_t get_last_addr_rt()
{
  uintptr_t *root_table_addr=get_root_page_table_addr();
  for(uintptr_t i=runtime_va_start;;i+=RISCV_PAGE_SIZE)
  {
    uintptr_t * status_find_address=__walk(root_table_addr,i);
    if( ! (  (*status_find_address) & PTE_L ) )
    {
          return i;
    }
  }
}




//------------------------------------------------------------------------------





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
  is_rt=1;
  //printf("[BOOT.C] I am inside boot.c\n" );
  /* set initial values */
  //printf("[boot.c] STARTING BOOT.C\n" );
  load_pa_start = dram_base;
  shared_buffer = utm_vaddr;
  shared_buffer_size = utm_size;
  no_of_edge_calls=0;
  runtime_va_start = (uintptr_t) &rt_base;
  kernel_offset = runtime_va_start - runtime_paddr;
#ifdef USE_FREEMEM
  freemem_va_start = __va(free_paddr);
  freemem_size = dram_base + dram_size - free_paddr;

  /* remap kernel VA */
  remap_kernel_space(runtime_paddr, user_paddr - runtime_paddr);
  //printf("%d\n",__LINE__);
  map_physical_memory(dram_base, dram_size);
  //printf("%d\n",__LINE__);
  /* switch to the new page table */
  csr_write(satp, satp_new(kernel_va_to_pa(root_page_table)));
  //printf("%d\n",__LINE__);
  /* copy valid entries from the old page table */
  copy_root_page_table();
  //printf("%d\n",__LINE__);
  /* initialize free memory */
  init_freemem();
  //printf("%d\n",__LINE__);
  //TODO: This should be set by walking the userspace vm and finding
  //highest used addr. Instead we start partway through the anon space
  set_program_break(get_last_addr());
  //printf("%d\n",__LINE__);
  set_program_break_rt(get_last_addr_rt());
  //printf("%d\n",__LINE__);

#endif // USE_FREEMEM

  /* initialize user stack */
  init_user_stack_and_env();
  //printf("%d\n",__LINE__);
  /* set trap vector */
  csr_write(stvec, &encl_trap_handler);
  //printf("%d\n",__LINE__);
  /* prepare edge & system calls */
  init_edge_internals();
  //printf("%d\n",__LINE__);
  /* set timer */

  //init_timer();

  //printf("%d\n",__LINE__);


  //printf("%d\n",__LINE__);
  /* booting all finished, droping to the user land */
  /*
  malloc(MALLOC_SIZE);
  replacement_algo_queue=(uintptr_t*)malloc(MALLOC_SIZE2*sizeof(uintptr_t));
  replacement_algo_queue_map=(uintptr_t*)malloc(MALLOC_SIZE2*sizeof(uintptr_t));
  q_front=q_rear=-1;
  */


  uintptr_t freemem_va_start_old=freemem_va_start;
  printf("PRINTING FROM BOOT.c\n");
  //uintptr_t *sfa=__walk(get_root_page_table_addr(),0x3ffffbf00);
  //printf("DUMMY\n");
  //printf("THE PAGE TABLE ENTRY IS %x\n",*sfa);
  //*sfa= *sfa & (~PTE_V);
  //printf("PAGE TABLE ENTRY HAS BEEN INVALIDATED\n");

  csr_write(sstatus, csr_read(sstatus) | 0x6000);// uncomment after checking
  init_page_replacement_queue(dram_base);
   //printf("%d\n",__LINE__);

  uintptr_t * status_find_address=__walk(get_root_page_table_addr(),replacement_algo_queue_map[0]);
  uintptr_t pa_ppn=(*status_find_address)>>PTE_PPN_SHIFT;
  uintptr_t va_org= __va(pa_ppn<<RISCV_PAGE_BITS);

  
  freemem_va_start = va_org;
  freemem_size += freemem_va_start_old-freemem_va_start;


  asm volatile ("fence.i\t\nsfence.vma\t\n");


  //printf("[boot.c] dropping to user land\n" );
  //printf("[boot.c] clock_counter = %lu\n",clock_counter );

  /*
  uintptr_t left =12; left=left;
  //uintptr_t left =spa_available();
  deplete_free_pages_for_testing(left);// this is only for testing
  */
  is_rt=0;
  return;
}
//------------------------------------------------------------------------------
