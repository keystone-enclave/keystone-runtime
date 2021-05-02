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
#include "process_snapshot.h"
#include "malloc.h"
#include "uaccess.h"
#include "gcm.h"

/* defined in vm.h */
extern uintptr_t shared_buffer;
extern uintptr_t shared_buffer_size;
extern uintptr_t utm_paddr_start; 

/* initial memory layout */
uintptr_t utm_base;
size_t utm_size;

/* defined in entry.S */
extern void* encl_trap_handler;

/* Snapshot of user processs*/
struct proc_snapshot snapshot;

const unsigned char key[32] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
  0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };
unsigned char plaintext[1024] = { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
  0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
  0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
  0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
  0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
  0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
  0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
  0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55 };
unsigned char expected_ciphertext[64] = { 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
  0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
  0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
  0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
  0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
  0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
  0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
  0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85};
const unsigned char initial_value[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
  0xde, 0xca, 0xf8, 0x88 };
const unsigned char additional[] = {};

#ifdef USE_FREEMEM


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
  map_with_reserved_page_table(dram_base, dram_size,
      ptr, load_l2_page_table, load_l3_page_table);
}

void
remap_kernel_space(uintptr_t runtime_base,
                   uintptr_t runtime_size)
{
  /* eyrie runtime is supposed to be smaller than a megapage */

  #if __riscv_xlen == 64
  assert(runtime_size <= RISCV_GET_LVL_PGSIZE(2));
  #elif __riscv_xlen == 32
  assert(runtime_size <= RISCV_GET_LVL_PGSIZE(1));
  #endif

  map_with_reserved_page_table(runtime_base, runtime_size,
     runtime_va_start, kernel_l2_page_table, kernel_l3_page_table);
}

void
map_untrusted_memory(uintptr_t base,
                     uintptr_t size)
{
  uintptr_t ptr = EYRIE_UNTRUSTED_START;

  /* untrusted memory is smaller than a megapage (2 MB in RV64, 4MB in RV32) */
  #if __riscv_xlen == 64
  assert(size <= RISCV_GET_LVL_PGSIZE(2));
  #elif __riscv_xlen == 32
  assert(size <= RISCV_GET_LVL_PGSIZE(1));
  #endif

  map_with_reserved_page_table(base, size,
      ptr, utm_l2_page_table, utm_l3_page_table);

  shared_buffer = ptr;
  shared_buffer_size = size;
}

void
copy_root_page_table()
{
  /* the old table lives in the first page */
  pte* old_root_page_table = (pte*) EYRIE_LOAD_START;
  int i;

  /* copy all valid entries of the old root page table */
  for (i = 0; i < BIT(RISCV_PT_INDEX_BITS); i++) {
    if (old_root_page_table[i] & PTE_V &&
        !(root_page_table[i] & PTE_V)) {
      root_page_table[i] = old_root_page_table[i];
    }
  }
}

/* initialize free memory with a simple page allocator*/
void
init_freemem()
{
  spa_init(freemem_va_start, freemem_size);
}

#endif // USE_FREEMEM


int remap_additional(struct proc_snapshot *snapshot, int level, pte* tb, uintptr_t vaddr) {
  pte* walk;
  int i;
  uintptr_t parent_freemem_start = snapshot->freemem_pa_start;
  // uintptr_t parent_freemem_end = snapshot->freemem_pa_end;

  /* iterate over PTEs */
  for (walk = tb, i = 0; walk < tb + (RISCV_PAGE_SIZE / sizeof(pte));
       walk += 1, i++) {

    if ((*walk) == 0) {
      continue;
    }

    uintptr_t vpn;
    uintptr_t phys_addr = ((*walk) >> PTE_PPN_SHIFT) << RISCV_PAGE_BITS;

    /* propagate the highest bit of the VA */
    if (level == RISCV_PGLEVEL_TOP && i & RISCV_PGTABLE_HIGHEST_BIT)
      vpn = ((-1UL << RISCV_PT_INDEX_BITS) | (i & PTE_FLAG_MASK));
    else
      vpn = ((vaddr << RISCV_PT_INDEX_BITS) | (i & PTE_FLAG_MASK));

    uintptr_t va_start = vpn << RISCV_PAGE_BITS;

    if(va_start >= EYRIE_LOAD_START){
      continue;
    }

    if (level == 1) {
      /* if PTE is leaf, extend hash for the page */
      
      // printf("user PAGE hashed: 0x%lx (pa: 0x%lx)\n", vpn << RISCV_PAGE_BITS, phys_addr);
      if(phys_addr < load_pa_start || phys_addr >= load_pa_end){
        uintptr_t new_phys_addr = load_pa_start + (phys_addr - parent_freemem_start);
        *walk = pte_create(new_phys_addr >> RISCV_PAGE_BITS, (*walk) & PTE_FLAG_MASK); 
      }

    } else {
      /* otherwise, recurse on a lower level */

      pte* mapped_paddr;
      uintptr_t new_phys_addr = 0; 

      if(phys_addr < load_pa_start || phys_addr >= load_pa_end){
        new_phys_addr = load_pa_start + (phys_addr - parent_freemem_start);
        mapped_paddr = (pte *) __va(new_phys_addr);
        *walk = (ppn(new_phys_addr) << PTE_PPN_SHIFT) | (*walk & PTE_FLAG_MASK);
      } else {
        mapped_paddr = (pte *) __va(phys_addr);
      }

      if(level == 3){
        root_page_table[i] = *walk; 
      }
      remap_additional(snapshot, level - 1, mapped_paddr, vpn);      
    }
  }
  return 0;
}

/* initialize user stack */
void
init_user_stack_and_env(bool is_fork)
{
  void* user_sp = (void*) EYRIE_USER_STACK_START;

#ifdef USE_FREEMEM
if(!is_fork){
  size_t count;
  uintptr_t stack_end = EYRIE_USER_STACK_END;
  size_t stack_count = EYRIE_USER_STACK_SIZE >> RISCV_PAGE_BITS;


  // allocated stack pages right below the runtime
  count = alloc_pages(vpn(stack_end), stack_count,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);

  assert(count == stack_count);
}

#endif // USE_FREEMEM

  // setup user stack env/aux
  user_sp = setup_start(user_sp);

  // prepare user sp
  csr_write(sscratch, user_sp);
}

struct proc_snapshot * 
handle_fork(void* buffer, struct proc_snapshot *ret){
  mbedtls_gcm_context ctx; 
  mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
  mbedtls_gcm_init( &ctx );
  mbedtls_gcm_setkey( &ctx, cipher, key, 128 );
  

  uintptr_t user_va = (uintptr_t) __va(user_paddr_start);
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  size_t args_len;

  if(!edge_call->call_id){
    return NULL; 
  }

  if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return NULL;
  }

  memcpy(ret, (void *) call_args, sizeof(struct proc_snapshot));

  //Decrypt snapshot register state 
  struct proc_snapshot *snapshot = (struct proc_snapshot *) call_args;

  memcpy((void *) snapshot->initial_value_ctx, initial_value, 12);
  memcpy((void *) snapshot->initial_value_root_pt, initial_value, 12);

  mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, sizeof(struct encl_ctx), snapshot->initial_value_ctx, 12, additional, 0, (const unsigned char *) &snapshot->ctx, (unsigned char *) &ret->ctx, 16, snapshot->tag_buf_ctx);
    

  pte tmp_root_page_table[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));
  mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, RISCV_PAGE_SIZE, snapshot->initial_value_root_pt, 12, additional, 0, (const unsigned char *) (call_args + sizeof(struct proc_snapshot)), (unsigned char *) tmp_root_page_table, 16, snapshot->tag_buf_root_pt);

  sbi_stop_enclave(SBI_STOP_REQ_FORK_MORE); 

  int recv_bytes = 0; 
  struct proc_snapshot_payload payload_header; 

  while(recv_bytes < ret->size){

    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
      return NULL;
    }

    memcpy(&payload_header, (void *) call_args, sizeof(struct proc_snapshot_payload));
    mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, args_len - sizeof(struct proc_snapshot_payload), payload_header.initial_value_payload, 12, additional, 0, (const unsigned char *) call_args + sizeof(struct proc_snapshot_payload), (unsigned char *) (user_va + recv_bytes), 16, payload_header.tag_buf_payload);

    recv_bytes += (args_len - sizeof(struct proc_snapshot_payload));
    printf("Received %d from parent, copied %d / %d so far.\n", args_len, recv_bytes, ret->size);

    if(recv_bytes >= ret->size){
      //No need to signal parent if we finished consumingg payload size
      break;
    }
    sbi_stop_enclave(SBI_STOP_REQ_FORK_MORE);
  }

  remap_additional(ret, RISCV_PT_LEVELS, tmp_root_page_table, 0);

  //Clear out the snapshot after use
  memset((void *) call_args, 0, args_len);

  return (struct proc_snapshot *) ret;
}

uintptr_t
eyrie_boot(uintptr_t dummy, // $a0 contains the return value from the SBI
           uintptr_t dram_base,
           uintptr_t dram_size,
           uintptr_t runtime_paddr,
           uintptr_t user_paddr,
           uintptr_t free_paddr,
           uintptr_t utm_paddr,
           uintptr_t utm_size)
{
  /* set initial values */
  load_pa_start = dram_base;
  load_pa_end = dram_base + dram_size;
  load_pa_child_start = dram_base;
  runtime_va_start = (uintptr_t) &rt_base;
  kernel_offset = runtime_va_start - runtime_paddr;
  user_paddr_start = user_paddr;
  user_paddr_end = free_paddr;
  utm_paddr_start = utm_paddr; 

  shared_buffer = EYRIE_UNTRUSTED_START;
  shared_buffer_size = utm_size; 

  debug("UTM : 0x%lx-0x%lx (%u KB)", utm_paddr, utm_paddr+utm_size, utm_size/1024);
  debug("DRAM: 0x%lx-0x%lx (%u KB)", dram_base, dram_base + dram_size, dram_size/1024);
  debug("USER : 0x%lx-0x%lx (%u KB)", user_paddr_start, user_paddr_end, (user_paddr_end - user_paddr_start)/1024);

#ifdef USE_FREEMEM
  freemem_va_start = __va(free_paddr);
  freemem_size = dram_base + dram_size - free_paddr;

  debug("FREE: 0x%lx-0x%lx (%u KB), va 0x%lx", free_paddr, dram_base + dram_size, freemem_size/1024, freemem_va_start);

  /* remap kernel VA */
  remap_kernel_space(runtime_paddr, user_paddr - runtime_paddr);
  map_physical_memory(dram_base, dram_size);

  /* switch to the new page table */
  csr_write(satp, satp_new(kernel_va_to_pa(root_page_table)));

  /* copy valid entries from the old page table */
  copy_root_page_table();

  map_untrusted_memory(utm_paddr, utm_size);

  /* initialize free memory */
  init_freemem();

  //TODO: This should be set by walking the userspace vm and finding
  //highest used addr. Instead we start partway through the anon space
  set_program_break(EYRIE_ANON_REGION_START + (1024 * 1024 * 1024));

  #ifdef USE_PAGING
  init_paging(user_paddr, free_paddr);
  #endif /* USE_PAGING */
#endif /* USE_FREEMEM */

  /* prepare edge & system calls */
  init_edge_internals();

  bool is_fork = handle_fork((void *) shared_buffer, &snapshot); 

  /* initialize user stack */
  init_user_stack_and_env(is_fork);

  /* set trap vector */
  csr_write(stvec, &encl_trap_handler);

  /* set timer */
  init_timer();

  /* Enable the FPU */
  csr_write(sstatus, csr_read(sstatus) | 0x6000);

  if(is_fork){
    //This will be non-zero in the cases of fork() 
    csr_write(sepc, snapshot.ctx.regs.sepc + 4);
    //Set return value of fork() to be 0 (indicates child)
    snapshot.ctx.regs.a0 = 0; 
  }
  
  debug("eyrie boot finished. drop to the user land ...");
  /* booting all finished, droping to the user land */

  uintptr_t ret = (uintptr_t) &snapshot.ctx.regs;
  return ret;
}
