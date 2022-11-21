#define _GNU_SOURCE

#include <../merkle.h>
#include <assert.h>
#include <bencher.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

void
sbi_exit_enclave(uintptr_t code) {
  exit(code);
}

uintptr_t
paging_alloc_backing_page() {
  void* out = mmap(
      NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(out != MAP_FAILED);
  return (uintptr_t)out;
}

#define RAND_BOOK_LEN (4 * 1024 * 1024)

typedef struct bench_ctx {
  merkle_node_t root;
  int* rand_book;
  int rand_idx;
} bench_ctx_t;

void
bench_ctx__init(bench_ctx_t* ctx) {
  ctx->rand_book = (int*)malloc(sizeof(int) * RAND_BOOK_LEN);
  for (int i = 0; i < RAND_BOOK_LEN; i++) {
    ctx->rand_book[i] = rand();
  }
}

int
bench_insert__init(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;
  ctx->rand_idx    = rand() % RAND_BOOK_LEN;
  return 0;
}

int
bench_insert__destroy(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;
  merk_clear(&ctx->root);
  return 0;
}

int
bench_insert(void* _ctx) {
  bench_ctx_t* ctx         = (bench_ctx_t*)_ctx;
  const uint8_t* fake_hash = (uint8_t*)&ctx->rand_book[ctx->rand_idx / 2];
  int err                  = merk_insert(&ctx->root, ctx->rand_idx, fake_hash);
  ctx->rand_idx            = (ctx->rand_idx + 1) % RAND_BOOK_LEN;
  return err;
}

int
bench_insert_subset_128(void* _ctx) {
  bench_ctx_t* ctx         = (bench_ctx_t*)_ctx;
  const uint8_t* fake_hash = (uint8_t*)ctx->rand_book;
  int err       = merk_insert(&ctx->root, ctx->rand_idx % 128, fake_hash);
  ctx->rand_idx = (ctx->rand_idx + 1) % RAND_BOOK_LEN;
  return err;
}

int
bench_verify_128__init(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;
  ctx->rand_idx    = rand() % RAND_BOOK_LEN;

  for (int i = 0; i < 128; i++) {
    int key          = ctx->rand_book[(ctx->rand_idx + i) % 128];
    uint8_t hash[32] = {};
    memcpy(hash, &key, sizeof key);
    merk_insert(&ctx->root, key, hash);
  }

  ctx->rand_idx = rand() % RAND_BOOK_LEN;
  return 0;
}

int
bench_verify__destroy(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;
  merk_clear(&ctx->root);
  return 0;
}

int
bench_verify_128(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;
  int key          = ctx->rand_idx % 128;
  uint8_t hash[32] = {};
  memcpy(hash, &key, sizeof key);
  int err       = merk_verify(&ctx->root, key, hash);
  ctx->rand_idx = (ctx->rand_idx + 1) % RAND_BOOK_LEN;
  return err;
}

int
main(int argc, char** argv) {
  srand(time(NULL));
  bench_ctx_t ctx = {};
  bench_ctx__init(&ctx);

  struct bench benches[] = {
      {.name   = "merkle tree insert",
       .init   = bench_insert__init,
       .deinit = bench_insert__destroy,
       .iter   = bench_insert},
      {.name   = "merkle tree insert subset (128)",
       .init   = bench_insert__init,
       .deinit = bench_insert__destroy,
       .iter   = bench_insert_subset_128},
      {.name   = "merkle tree verify (128)",
       .init   = bench_insert__init,
       .deinit = bench_insert__destroy,
       .iter   = bench_insert_subset_128},
  };
  struct bench_opts opts = bench_argp(argc, argv);
  run_benches(&opts, benches, sizeof(benches) / sizeof(struct bench), &ctx);
}
