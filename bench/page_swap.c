#define _GNU_SOURCE

#include "../page_swap.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#include "../freemem.h"
#include "../paging.h"
#include "../vm_defs.h"
#include "bencher.h"

void
sbi_exit_enclave(uintptr_t code) {
  exit(code);
}

size_t
rt_util_getrandom(void* vaddr, size_t buflen) {
  uint8_t* charbuf = (uint8_t*)vaddr;
  for (size_t i = 0; i < buflen; i++) charbuf[i] = rand();
  return buflen;
}

uintptr_t
sbi_random() {
  uintptr_t out;
  rt_util_getrandom(&out, sizeof out);
  return out;
}

bool
paging_epm_inbounds(uintptr_t addr) {
  (void)addr;
  return true;
}

static void* backing_region;
#define BACKING_REGION_SIZE (2 * 1024 * 1024)

bool
paging_backpage_inbounds(uintptr_t addr) {
  return (addr >= (uintptr_t)backing_region) &&
         (addr < (uintptr_t)backing_region + BACKING_REGION_SIZE);
}

uintptr_t
paging_backing_region() {
  if (!backing_region) {
    backing_region = mmap(
        NULL, BACKING_REGION_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(backing_region != MAP_FAILED);
  }
  return (uintptr_t)backing_region;
}
uintptr_t
paging_backing_region_size() {
  return BACKING_REGION_SIZE;
}

uintptr_t
__va(uintptr_t pa) {
  return pa;
}

uintptr_t
paging_evict_and_free_one(uintptr_t swap_va) {
  (void)swap_va;
  assert(false);
}

bool
spa_page_inbounds(uintptr_t page_addr) {
  (void)page_addr;
  return true;
}

#define VM_REGION_SIZE (2 * 1024 * 1024)
#define VM_REGION_PAGES (VM_REGION_SIZE / RISCV_PAGE_SIZE)
#define SWAPPABLE_PAGES 128
#define RAND_BOOK_SIZE 4096

typedef struct {
  void* vm_region;
  uint64_t swapped_out[SWAPPABLE_PAGES / 64];
  uintptr_t swappable_pages_front[SWAPPABLE_PAGES];
  uintptr_t swappable_pages_back[SWAPPABLE_PAGES];

  int rand_book[RAND_BOOK_SIZE];
  size_t rand_book_idx;
} bench_ctx_t;

static int
bench_ctx__init(bench_ctx_t* ctx) {
  ctx->vm_region = mmap(
      NULL, VM_REGION_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
      -1, 0);
  if (ctx->vm_region == MAP_FAILED) return -1;

  for (size_t i = 0; i < RAND_BOOK_SIZE; i++) ctx->rand_book[i] = rand();
  return 0;
}

static int
bench_ctx__destroy(bench_ctx_t* ctx) {
  return munmap(ctx->vm_region, VM_REGION_SIZE);
}

static int
bench_ctx__rand(bench_ctx_t* ctx) {
  int out            = ctx->rand_book[ctx->rand_book_idx];
  ctx->rand_book_idx = (ctx->rand_book_idx + 1) % RAND_BOOK_SIZE;
  return out;
}

static int
page_swap__init(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;

  spa_init((uintptr_t)ctx->vm_region, VM_REGION_SIZE);
  pswap_init();
  memset(ctx->swapped_out, 0, sizeof ctx->swapped_out);

  for (size_t i = 0; i < SWAPPABLE_PAGES; i++) {
    ctx->swappable_pages_front[i] = spa_get();
    ctx->swappable_pages_back[i]  = paging_alloc_backing_page();
    rt_util_getrandom((void*)ctx->swappable_pages_front[i], RISCV_PAGE_SIZE);
  }

  ctx->rand_book_idx = rand() % RAND_BOOK_SIZE;
  return 0;
}

static int
page_swap__destroy(void* _ctx) {
  (void)_ctx;
  return 0;
}

static int
page_swap(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;

  // Choose a page (excluding the first page, which is used by the SPA)
  size_t which_page    = bench_ctx__rand(ctx) % SWAPPABLE_PAGES;
  uintptr_t front_page = ctx->swappable_pages_front[which_page];
  uintptr_t back_page  = ctx->swappable_pages_back[which_page];
  uintptr_t swap_page;

  if (ctx->swapped_out[which_page / 64] & (1ull << (which_page % 64))) {
    // Have already swapped this page out
    swap_page = back_page;
  } else {
    swap_page = 0;
    ctx->swapped_out[which_page / 64] |= (1ull << (which_page % 64));
  }

  return page_swap_epm(back_page, front_page, swap_page);
}

int
main(int argc, char** argv) {
  srand(time(NULL));
  bench_ctx_t ctx = {};
  int err         = bench_ctx__init(&ctx);
  assert(!err);

  struct bench benches[] = {
      {.name   = "page swap",
       .init   = page_swap__init,
       .deinit = page_swap__destroy,
       .iter   = page_swap},
  };
  struct bench_opts opts = bench_argp(argc, argv);
  run_benches(&opts, benches, sizeof(benches) / sizeof(struct bench), &ctx);

  err = bench_ctx__destroy(&ctx);
  assert(!err);
}