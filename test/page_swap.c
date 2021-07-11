#define _GNU_SOURCE

#include "../page_swap.c"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "mock.h"

void
sbi_exit_enclave(uintptr_t code) {
  exit(code);
}

uintptr_t
sbi_random() {
  uintptr_t out;
  rt_util_getrandom(&out, sizeof out);
  return out;
}

size_t
rt_util_getrandom(void* vaddr, size_t buflen) {
  uint8_t* charbuf = (uint8_t*)vaddr;
  for (size_t i = 0; i < buflen; i++) charbuf[i] = rand();
  return buflen;
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
    assert_int_not_equal(backing_region, MAP_FAILED);
  }
  return (uintptr_t)backing_region;
}
uintptr_t
paging_backing_region_size() {
  return BACKING_REGION_SIZE;
}

static uintptr_t
palloc() {
  void* out = mmap(
      NULL, RISCV_PAGE_SIZE, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert_int_not_equal(out, MAP_FAILED);
  return (uintptr_t)out;
}

static void
pfree(uintptr_t page) {
  int res = munmap((void*)page, RISCV_PAGE_SIZE);
  assert_int_equal(res, 0);
}

uintptr_t
spa_get(void) {
  return palloc();
}

static hash_t
hash_page(uintptr_t page) {
  hash_t out;
  SHA256_CTX sha;
  sha256_init(&sha);
  sha256_update(&sha, (uint8_t*)page, RISCV_PAGE_SIZE);
  sha256_final(&sha, out.val);
  return out;
}
static bool
hash_eq(hash_t* h1, hash_t* h2) {
  return !memcmp(h1, h2, sizeof(hash_t));
}

static double
bit_similarity(uintptr_t page1, uintptr_t page2) {
  double avg = 0;
  size_t n   = 0;

  uint64_t* p1buf = (uint64_t*)page1;
  uint64_t* p2buf = (uint64_t*)page2;
  for (size_t i = 0; i < RISCV_PAGE_SIZE / 8; i++) {
    double word_similarity =
        (double)__builtin_popcountll(p1buf[i] ^ p2buf[i]) / 64.0;
    avg += (word_similarity - avg) / ++n;
  }

  return avg;
}
static double
bit_similarity_sd() {
  // For 2 IID pages, each bit is similar with probability 0.5.
  // So the sum of all similarities follows a binomial distribution
  // B(8*PAGE_SIZE, 0.5). The mean # of similar bits is 4*PAGE_SIZE, +/-
  // sqrt(2*PAGE_SIZE) So the mean similarity is 0.5 +/- 1/sqrt(8*PAGE_SIZE)
  // With PAGE_SIZE=4096, this is 0.5 */- 0.0028

  return 1.0 / sqrt(8 * RISCV_PAGE_SIZE);
}

void
test_swapout_randomness() {
  pswap_init();

  uintptr_t back_page  = paging_alloc_backing_page();
  uintptr_t front_page = palloc();
  rt_util_getrandom((void*)front_page, RISCV_PAGE_SIZE);

  page_swap_epm(back_page, front_page, 0);

  // Backing page should be essentially random.
  double sim = bit_similarity(back_page, front_page);
  assert_true(sim < 0.5 + 4 * bit_similarity_sd());
  assert_true(sim > 0.5 - 4 * bit_similarity_sd());

  pfree(front_page);
}

void
test_swap_out_in() {
  pswap_init();

  uintptr_t back_page  = paging_alloc_backing_page();
  uintptr_t front_page = palloc();
  rt_util_getrandom((void*)front_page, RISCV_PAGE_SIZE);

  hash_t back_hash  = hash_page(back_page);
  hash_t front_hash = hash_page(front_page);

  int err = page_swap_epm(back_page, front_page, 0);
  assert(!err);

  hash_t back_swp_hash  = hash_page(back_page);
  hash_t front_swp_hash = hash_page(front_page);
  assert_false(hash_eq(&back_hash, &back_swp_hash));
  assert_true(hash_eq(&front_hash, &front_swp_hash));

  // Randomize front_page and then swap back in our old front_page
  rt_util_getrandom((void*)front_page, RISCV_PAGE_SIZE);
  err = page_swap_epm(back_page, front_page, back_page);
  assert(!err);

  hash_t back_swp_hash2  = hash_page(back_page);
  hash_t front_swp_hash2 = hash_page(front_page);
  assert_false(hash_eq(&back_hash, &back_swp_hash2));
  assert_false(hash_eq(&back_swp_hash, &back_swp_hash2));
  assert_true(hash_eq(&front_hash, &front_swp_hash2));

  pfree(front_page);
}

void
test_corrupt_back_page() {
  pswap_init();

  uintptr_t back_page  = paging_alloc_backing_page();
  uintptr_t front_page = palloc();
  rt_util_getrandom((void*)front_page, RISCV_PAGE_SIZE);

  int err = page_swap_epm(back_page, front_page, 0);
  assert(!err);

  // Flip a random bit in the page
  *(uint8_t*)(back_page + rand() % RISCV_PAGE_SIZE) ^= (1 << (rand() % 8));

  // Now we should see an error swapping the page back in
  err = page_swap_epm(back_page, front_page, back_page);
  assert(err);

  pfree(front_page);
}

void
test_corrupt_back_page_hmac() {
  pswap_init();

  uintptr_t back_page  = paging_alloc_backing_page();
  uintptr_t front_page = palloc();
  rt_util_getrandom((void*)front_page, RISCV_PAGE_SIZE);

  int err = page_swap_epm(back_page, front_page, 0);
  assert(!err);

  // Flip a random bit in the hmac
  hash_t* hmac = pswap_pageout_hmac(back_page);
  *(uint8_t*)(back_page + rand() % sizeof(hash_t)) ^= (1 << (rand() % 8));

  // Now we should see an error swapping the page back in
  err = page_swap_epm(back_page, front_page, back_page);
  assert(err);

  pfree(front_page);
}

void
test_replay_back_page() {
  pswap_init();

  uintptr_t back_page  = paging_alloc_backing_page();
  uintptr_t front_page = palloc();
  rt_util_getrandom((void*)front_page, RISCV_PAGE_SIZE);

  uint8_t* back_page_backup = (uint8_t*)palloc();
  hash_t back_hmac_backup;

  // Swap the page out
  int err = page_swap_epm(back_page, front_page, 0);
  assert(!err);
  memcpy(back_page_backup, (void*)back_page, RISCV_PAGE_SIZE);
  back_hmac_backup = *pswap_pageout_hmac(back_page);

  // Swap another page
  err = page_swap_epm(back_page, front_page, back_page);
  assert(!err);

  // Restore the backups
  memcpy((void*)back_page, back_page_backup, RISCV_PAGE_SIZE);
  *pswap_pageout_hmac(back_page) = back_hmac_backup;

  // Swapping in should fail
  err = page_swap_epm(back_page, front_page, back_page);
  assert(err);

  pfree(front_page);
  pfree((uintptr_t)back_page_backup);
}

void
test_invasive_replay() {
  pswap_init();

  uintptr_t back_page  = paging_alloc_backing_page();
  uintptr_t front_page = palloc();
  rt_util_getrandom((void*)front_page, RISCV_PAGE_SIZE);

  uint8_t* back_page_backup = (uint8_t*)palloc();
  hash_t back_hmac_backup;
  uint64_t back_ctr_backup;

  // Swap the page out
  int err = page_swap_epm(back_page, front_page, 0);
  assert(!err);
  memcpy(back_page_backup, (void*)back_page, RISCV_PAGE_SIZE);
  back_hmac_backup = *pswap_pageout_hmac(back_page);
  back_ctr_backup  = *pswap_pageout_ctr(back_page);

  // Swap another page
  err = page_swap_epm(back_page, front_page, back_page);
  assert(!err);

  // Restore the backups
  memcpy((void*)back_page, back_page_backup, RISCV_PAGE_SIZE);
  *pswap_pageout_hmac(back_page) = back_hmac_backup;
  *pswap_pageout_ctr(back_page)  = back_ctr_backup;

  // Swapping in should succeed because we somehow restored the page counter
  // This should not be possible in a real attack
  err = page_swap_epm(back_page, front_page, back_page);
  assert(!err);

  pfree(front_page);
  pfree((uintptr_t)back_page_backup);
}

int
main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_swapout_randomness),
      cmocka_unit_test(test_swap_out_in),
      cmocka_unit_test(test_corrupt_back_page),
      cmocka_unit_test(test_corrupt_back_page_hmac),
      cmocka_unit_test(test_replay_back_page),
      cmocka_unit_test(test_invasive_replay),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}