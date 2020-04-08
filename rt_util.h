#ifndef _RT_UTIL_H_
#define _RT_UTIL_H_

#include "regs.h"
#include <stddef.h>

#define FATAL_DEBUG

//int rt_util_getrandom(void* vaddr, size_t buflen);
size_t rt_util_getrandom(void* vaddr, size_t buflen);

void fill_page_with_zeroes(char * page_addrs);
extern void chacha20(uint8_t *out, const uint8_t *in, size_t inlen, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);

void not_implemented_fatal(struct encl_ctx_t* ctx);
void rt_util_misc_fatal();
void handle_page_fault(uintptr_t addr, uintptr_t *status_find_address);
extern uint8_t z_1[16];
extern uint8_t z_2[16];
extern uint8_t Key_hmac[16];
extern uintptr_t pages_read;
extern uintptr_t real_pages_read;
extern uintptr_t pages_written;
extern uintptr_t real_pages_written;
extern uintptr_t max_stash_occ;
extern uintptr_t sum_stash_occ;
extern uintptr_t oram_acc;
extern int tracing;
extern int debug;
extern int exc;
extern int countpf;
extern int fault_lim;
extern uintptr_t prev_addr;
extern uintptr_t *prev_addr_status;


uintptr_t rt_handle_sbrk(size_t bytes);
uintptr_t rt_handle_sbrk_rt(size_t bytes);
//#define pow(a,b) (1<<b)
#define DUMMY_BLOCK_ADDR 0
#define STASH_SIZE 35
#define ARRAY_SIZE 500
#define BLOCK_SIZE 4096
#define NO_ORAM 0
#define PATH_ORAM 1
#define OPAM 2
#define ENC_PFH 3
#define RORAM 4
#define NO_OF_COUNTERS 16

int get_tree_index(int x);
double log2(int x);
double ceil(double x);
unsigned int UniformRandom();
void  pxget(int leafindex , int Px[ARRAY_SIZE]);
//extern char firstimeaccess[ARRAY_SIZE];
extern char *firstimeaccess;
extern char *buff;
extern char *backup_shared_memory;



typedef enum  { PAGE_FAULT_HANDLER_SIMPLE=0, PAGE_FAULT_HANDLER_ORAM=1,
       PAGE_FAULT_HANDLER_OPAM=2, PAGE_FAULT_HANDLER_ENC_ADDR=3 }page_fault_type;
typedef struct enclave_options_t {
  page_fault_type page_fault_handler;
  uint8_t integrity_protection;
  uint8_t confidentiality;
  int num_free_pages;
  uint8_t page_addr_tracing;
  uint8_t debug_mode;
  uint8_t tree_exc;
  int fault_limit;
} enclave_options;


typedef struct counter_t
{
  uintptr_t count;
  char name[50];
} counter;

extern counter counters[NO_OF_COUNTERS];
#define PAGES_READ 0
#define PAGES_WRITTEN 1
#define INIT_NUM_PAGES 2
#define PAGE_FAULT_COUNT 3
#define FREE_PAGES_FR 4
#define EXTENSIONS 5
#define TOTAL_PAGES 6
#define REAL_PAGES_READ 7
#define REAL_PAGES_WRITTEN 8
#define DUMMY_PAGES_READ 9
#define DUMMY_PAGES_WRITTEN 10
#define MAX_STASH_OCC 11
#define SUM_STASH_OCC 12
#define ORAM_ACC 13
#define ORAM_INIT 14
#define COPY_WASTE 15
int pow(uintptr_t a, uintptr_t b);
#define ARITY 16.0//16.0  4.0

extern int confidentiality;
extern uintptr_t fault_mode;
extern uintptr_t copy_waste;

extern uintptr_t buff_size;

extern uintptr_t time_rblocks_process_r;
extern uintptr_t time_rblocks_process_w;
extern uintptr_t time_dblocks_process_r;
extern uintptr_t time_dblocks_process_w;
extern uintptr_t time_block_copy_r;
extern uintptr_t time_block_copy_w;

#define BLOCKS_FOR_TIME_COUNTING 8192







#endif /* _RT_UTIL_H_ */
