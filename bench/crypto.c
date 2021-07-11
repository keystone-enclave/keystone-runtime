#define _GNU_SOURCE

#include <../aes.h>
#include <../sha256.h>
#include <assert.h>
#include <bencher.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#define RAND_BOOK_LEN 1024

typedef struct bench_ctx {
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
nop(void* _ctx) {
  (void)_ctx;
  return 0;
}

int
bench_sha_1byte(void* _ctx) {
  SHA256_CTX sha;
  volatile uint8_t byte = 0;
  uint8_t hash[32];

  sha256_init(&sha);
  sha256_update(&sha, &byte, 1);
  sha256_final(&sha, hash);

  __asm__ __volatile__("" ::"r"(hash));
  return 0;
}

int
bench_sha_32byte(void* _ctx) {
  SHA256_CTX sha;
  uint8_t hash[32];
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;

  sha256_init(&sha);
  sha256_update(&sha, ctx->rand_book, 32);
  sha256_final(&sha, hash);

  __asm__ __volatile__("" ::"r"(hash));
  return 0;
}

int
bench_sha_page(void* _ctx) {
  SHA256_CTX sha;
  uint8_t hash[32];
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;
  assert(sizeof(int) * RAND_BOOK_LEN >= 4096);

  sha256_init(&sha);
  sha256_update(&sha, ctx->rand_book, 4096);
  sha256_final(&sha, hash);

  __asm__ __volatile__("" ::"r"(hash));
  return 0;
}

int
main(int argc, char** argv) {
  srand(time(NULL));
  bench_ctx_t ctx = {};
  bench_ctx__init(&ctx);

  struct bench benches[] = {
      {.name   = "sha 1 byte",
       .init   = nop,
       .deinit = nop,
       .iter   = bench_sha_1byte},
      {.name   = "sha 32 byte",
       .init   = nop,
       .deinit = nop,
       .iter   = bench_sha_32byte},
      {.name   = "sha 4096 bytes",
       .init   = nop,
       .deinit = nop,
       .iter   = bench_sha_page},
  };
  struct bench_opts opts = bench_argp(argc, argv);
  run_benches(&opts, benches, sizeof(benches) / sizeof(struct bench), &ctx);
}
