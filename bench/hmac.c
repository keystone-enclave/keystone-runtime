#define _GNU_SOURCE

#include <../hmac.h>
#include <assert.h>
#include <bencher.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#define RAND_BOOK_LEN (4 * 1024 * 1024)

typedef struct bench_ctx {
  int* rand_book;
  uint8_t* key;
  uint8_t* page;
} bench_ctx_t;

void
bench_ctx__init(bench_ctx_t* ctx) {
  ctx->rand_book = (int*)malloc(sizeof(int) * RAND_BOOK_LEN);
  for (int i = 0; i < RAND_BOOK_LEN; i++) {
    ctx->rand_book[i] = rand();
  }
}

int
hmac_page__init(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;
  ctx->key         = (uint8_t*)ctx->rand_book + rand() % (RAND_BOOK_LEN - 32);
  ctx->page        = (uint8_t*)ctx->rand_book + rand() % (RAND_BOOK_LEN - 4096);
  return 0;
}

int
hmac_page__destroy(void* _ctx) {
  (void)_ctx;
  return 0;
}

int
hmac_page(void* _ctx) {
  bench_ctx_t* ctx = (bench_ctx_t*)_ctx;
  uint8_t hash[32];
  int err = hmac(ctx->page, 4096, ctx->key, 32, hash);
  __asm__ __volatile__("" ::"r"(hash));
  return err;
}

int
main(int argc, char** argv) {
  srand(time(NULL));
  bench_ctx_t ctx = {};
  bench_ctx__init(&ctx);

  struct bench benches[] = {
      {.name   = "hmac page",
       .init   = hmac_page__init,
       .deinit = hmac_page__destroy,
       .iter   = hmac_page},
  };
  struct bench_opts opts = bench_argp(argc, argv);
  run_benches(&opts, benches, sizeof(benches) / sizeof(struct bench), &ctx);
}
