#ifndef __VM_H__
#define __VM_H__


#include <asm/csr.h>
#include "printf.h"
#include "common.h"


#define BIT(n) (1ul << (n))
#define MASK(n) (BIT(n)-1ul)
#define IS_ALIGNED(n, b) (!((n) & MASK(b)))

#define QUEUE_SIZE 500

#define RISCV_PT_INDEX_BITS 9
#define RISCV_PT_LEVELS 3
#define RISCV_PAGE_BITS 12
#define RISCV_PAGE_SIZE (1<<RISCV_PAGE_BITS)
#define PTE_PPN_SHIFT 10
#define RISCV_PAGE_OFFSET(addr) (addr % RISCV_PAGE_SIZE)
#define RISCV_GET_PT_INDEX(addr, n)                                     \
  (((addr) >> (((RISCV_PT_INDEX_BITS) * ((RISCV_PT_LEVELS) - (n))) + RISCV_PAGE_BITS)) \
   & MASK(RISCV_PT_INDEX_BITS))
#define RISCV_GET_LVL_PGSIZE_BITS(n) (((RISCV_PT_INDEX_BITS) * (RISCV_PT_LEVELS - (n))) + RISCV_PAGE_BITS)
#define RISCV_GET_LVL_PGSIZE(n)      BIT(RISCV_GET_LVL_PGSIZE_BITS((n)))

#define ROUND_UP(n, b) (((((n) - 1ul) >> (b)) + 1ul) << (b))
#define ROUND_DOWN(n, b) (n & ~((2 << (b-1)) - 1))
#define PAGE_DOWN(n) ROUND_DOWN(n, RISCV_PAGE_BITS)
#define PAGE_UP(n) ROUND_UP(n, RISCV_PAGE_BITS)

/* Starting address of the enclave memory */
#define EYRIE_LOAD_START        0xffffffff00000000
#define EYRIE_UNTRUSTED_START   0xffffffff80000000
#define EYRIE_USER_STACK_START  0x0000000400000000 //0x0000000400000000
#define EYRIE_ANON_REGION_START 0x0000002000000000 // Arbitrary VA to start looking for large mappings
#define EYRIE_ANON_REGION_END   EYRIE_LOAD_START
#define EYRIE_USER_STACK_SIZE   0x20000
#define MIN_ENCLAVE_VADDR 0X1000
//#define EYRIE_USER_STACK_SIZE   73*4096 //73 pages

#define EYRIE_USER_STACK_END    (EYRIE_USER_STACK_START - EYRIE_USER_STACK_SIZE)

#define PTE_V     0x001 // Valid
#define PTE_R     0x002 // Read
#define PTE_W     0x004 // Write
#define PTE_X     0x008 // Execute
#define PTE_U     0x010 // User
#define PTE_G     0x020 // Global
#define PTE_A     0x040 // Accessed
#define PTE_D     0x080 // Dirty
#define PTE_L     1<<8  // Legal
#define PTE_E     1<<9 //  Encrypted

//----------------list of error/fault codes-----------------------//
#define Instruction_address_misaligned 0
#define Instruction_access_fault 1
#define Illegal_instruction 2
#define Breakpoint 3
#define Reserved 4
#define Load_access_fault 5
#define AMO_address_misaligned 6
#define Store_AMO_access_fault 7
#define Environment_call 8
#define Instruction_page_fault 12
#define Load_page_fault 13
#define Store_AMO_page_fault 15










extern void* rt_base;

uintptr_t runtime_va_start;
/* Eyrie is for Sv39 */
static inline uintptr_t satp_new(uintptr_t pa)
{
  return (SATP_MODE | (pa >> RISCV_PAGE_BITS));
}

uintptr_t kernel_offset;
static inline uintptr_t kernel_va_to_pa(void* ptr)
{
  return (uintptr_t) ptr - kernel_offset;
}

uintptr_t load_pa_start;
static inline uintptr_t __va(uintptr_t pa)
{
  return (pa - load_pa_start) + EYRIE_LOAD_START;
}

static inline uintptr_t __pa(uintptr_t va)
{
  return (va - EYRIE_LOAD_START) + load_pa_start;
}

typedef uintptr_t pte_t;
static inline pte_t pte_create(uintptr_t ppn, int type)
{
  return (pte_t)((ppn << PTE_PPN_SHIFT) | PTE_V | type );
}

static inline pte_t ptd_create(uintptr_t ppn)
{
  return pte_create(ppn, PTE_V);
}

static inline uintptr_t ppn(uintptr_t pa)
{
  return pa >> RISCV_PAGE_BITS;
}

// this is identical to ppn, but separate it to avoid confusion between va/pa
static inline uintptr_t vpn(uintptr_t va)
{
  return va >> RISCV_PAGE_BITS;
}

static inline uintptr_t pte_ppn(pte_t pte)
{
  return pte >> PTE_PPN_SHIFT;
}

#ifdef USE_FREEMEM

/* root page table */
pte_t root_page_table[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));
/* page tables for kernel remap */
pte_t kernel_l2_page_table[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));
pte_t kernel_l3_page_table[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));
/* page tables for loading physical memory */
pte_t load_l2_page_table[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));
pte_t load_l3_page_table[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));

/* Program break */
uintptr_t program_break;
uintptr_t program_break_rt;


/* freemem */
uintptr_t freemem_va_start;
size_t freemem_size;

#endif // USE_FREEMEM

/* shared buffer */
uintptr_t shared_buffer;
uintptr_t shared_buffer_size;
uintptr_t no_of_edge_calls;
//uintptr_t replacement_algo_queue[QUEUE_SIZE];
//uintptr_t replacement_algo_queue_map[QUEUE_SIZE];

uintptr_t *replacement_algo_queue;
uintptr_t *replacement_algo_queue_map;
uintptr_t *free_indices;
int *block_map;
int *stash_loc;

uintptr_t frame_size;
uintptr_t pointer;
uintptr_t clock_counter;
//char *second_chance;

//uintptr_t *page_addr_tbl;

//uintptr_t *find_index;
//char *access_counter;



uintptr_t is_rt;



uintptr_t pop_item[2];
int q_front;
int q_rear;

typedef struct pages
{
  uintptr_t address;
  char data[RISCV_PAGE_SIZE];
  char hmac[32];
  uintptr_t ver_num;
  uintptr_t dummy;
}pages;

typedef struct pages_at
{
  uintptr_t address;
  uintptr_t dummy;
  char data[RISCV_PAGE_SIZE];
  char hmac[32];
}pages_at;


 typedef struct iv_page
 {
   char iv[16];
 }iv_page;


//-------------------------------------------------------------------------
/*typedef struct Block_oram
{
  uintptr_t enclav_vaddr;
  char  page[RISCV_PAGE_SIZE];

} Block_oram;
*/
uintptr_t *position;
//uintptr_t position[QUEUE_SIZE];
//uintptr_t knocked_page_addr[QUEUE_SIZE];
uintptr_t *knocked_page_addr;
int N;
int L;
unsigned int Z;
//iv_page p_ivs[QUEUE_SIZE];
iv_page *p_ivs;
//#define BACKUP_BUFFER_SIZE 138000
//#define BACKUP_BUFFER_SIZE 27000
//#define BACKUP_BUFFER_SIZE 5300
//#define BACKUP_BUFFER_SIZE 9000
#define BACKUP_BUFFER_SIZE 275000
#define BACKUP_BUFFER_SIZE_RORAM 275000
#define BACKUP_BUFFER_SIZE_ORAM 35000
#define BACKUP_BUFFER_SIZE_OTHERS 6000//6000



//#define BACKUP_BUFFER_SIZE 35000

#define MALLOC_SIZE 140000//140000
#define MALLOC_SIZE2 128000//125500



#endif
