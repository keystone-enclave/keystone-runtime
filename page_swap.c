#include "page_swap.h"

#if defined(USE_FREEMEM) && defined(USE_PAGING)

#include <assert.h>
#include <stdatomic.h>
#include <stddef.h>

#include "aes.h"
#include "hmac.h"
#include "paging.h"
#include "sbi.h"
#include "sha256.h"
#include "vm_defs.h"

typedef struct {
  uint8_t val[32];
} hash_t;

// Specify the amount of pages of swap counters. This works out to 24*(4096/8)
// or 12288 swappable pages; 50MB of memory. These counters are stored in
// on-chip memory.
#define NUM_CTR_INDIRECTS 24
#define NUM_CTR_INTERNAL (RISCV_PAGE_SIZE / 8)
typedef struct {
  uint64_t buf[NUM_CTR_INTERNAL];
} ctr_page_t;
static ctr_page_t* ctr_indirect_ptrs[NUM_CTR_INDIRECTS];

// Specify the amount of pages of HMACs. This should work out to the same amount
// of swappable pages as the ctrs.
#define NUM_HMAC_INDIRECTS 96
#define NUM_HMAC_INTERNAL (RISCV_PAGE_SIZE / sizeof(hash_t))
typedef struct {
  hash_t buf[NUM_HMAC_INTERNAL];
} hmac_page_t;
static hmac_page_t* hmac_indirect_ptrs[NUM_HMAC_INDIRECTS];

static_assert(
    NUM_CTR_INDIRECTS * NUM_CTR_INTERNAL ==
        NUM_HMAC_INDIRECTS * NUM_HMAC_INTERNAL,
    "Number of page swap counters does not match number of HMACs!");

// Set-once global keys
static uint8_t aes_key[32];
static uint8_t hmac_key[32];

static uintptr_t paging_next_backing_page_offset;
/// Provide a mechanism for allocating off-chip pages backing swapped ones.
/// There is no way to deallocate after calling this function, except to
/// reinitialize the page swap subsystem. This gives us a simple way to linearly
/// allocate page counters and HMACs as well.
uintptr_t
paging_alloc_backing_page() {
  uintptr_t offs_update = (paging_next_backing_page_offset + RISCV_PAGE_SIZE) %
                          paging_backing_region_size();

  /* no backing page available */
  if (offs_update == 0) {
    // cycled through all the pages
    warn("no backing page avaiable");
    return 0;
  }

  uintptr_t next_page =
      paging_backing_region() + paging_next_backing_page_offset;
  assert(IS_ALIGNED(next_page, RISCV_PAGE_BITS));

  paging_next_backing_page_offset = offs_update;
  return next_page;
}

unsigned int
paging_remaining_pages() {
  return (paging_backing_region_size() - paging_next_backing_page_offset) /
         RISCV_PAGE_SIZE;
}

void
pswap_init(void) {
  paging_next_backing_page_offset = 0;

  rt_util_getrandom(aes_key, 32);
  rt_util_getrandom(hmac_key, 32);

  memset(ctr_indirect_ptrs, 0, sizeof ctr_indirect_ptrs);
  memset(hmac_indirect_ptrs, 0, sizeof hmac_indirect_ptrs);
}

/// Find the particular pageout counter for a given page. These counters are
/// incremented on every page swap and are concatenated to the HMAC input to
/// prevent replay attacks. To avoid needing to verify integrity of counters,
/// they are stored in on-chip memory.
static uint64_t*
pswap_pageout_ctr(uintptr_t page) {
  assert(paging_backpage_inbounds(page));
  size_t idx          = (page - paging_backing_region()) >> RISCV_PAGE_BITS;
  size_t indirect_idx = idx / NUM_CTR_INTERNAL;
  size_t interior_idx = idx % NUM_CTR_INTERNAL;
  assert(indirect_idx < NUM_CTR_INDIRECTS);

  if (!ctr_indirect_ptrs[indirect_idx]) {
    ctr_indirect_ptrs[indirect_idx] = (ctr_page_t*)spa_get();
    // Fill ptr pages with random values so our counters start unpredictable
    rt_util_getrandom(ctr_indirect_ptrs[indirect_idx], RISCV_PAGE_SIZE);
  }

  return ctr_indirect_ptrs[indirect_idx]->buf + interior_idx;
}

#ifdef USE_PAGE_HASH
/// Find the particular HMAC for a given page. These HMACs are stored in
/// off-chip memory, but that's acceptable because an attacker can neither forge
/// it, nor replay it. Replay security comes from a counter concatenated to the
/// HMAC input.
static hash_t*
pswap_pageout_hmac(uintptr_t page) {
  assert(paging_backpage_inbounds(page));
  size_t idx          = (page - paging_backing_region()) >> RISCV_PAGE_BITS;
  size_t indirect_idx = idx / NUM_HMAC_INTERNAL;
  size_t interior_idx = idx % NUM_HMAC_INTERNAL;
  assert(indirect_idx < NUM_HMAC_INDIRECTS);

  if (!hmac_indirect_ptrs[indirect_idx]) {
    hmac_indirect_ptrs[indirect_idx] =
        (hmac_page_t*)paging_alloc_backing_page();
    // Fill ptr pages with random values so our counters start unpredictable
    memset(hmac_indirect_ptrs[indirect_idx], 0, RISCV_PAGE_SIZE);
  }

  return hmac_indirect_ptrs[indirect_idx]->buf + interior_idx;
}
#endif  // USE_PAGE_HASH

/// Copy page to destination, encrypting if USE_PAGE_CRYPTO is defined.
static void
pswap_encrypt(const void* addr, void* dst, uint64_t pageout_ctr) {
  size_t len = RISCV_PAGE_SIZE;

#ifdef USE_PAGE_CRYPTO
  uint8_t iv[32] = {0};
  WORD key_sched[80];
  aes_key_setup(aes_key, key_sched, 256);

  memcpy(iv + 8, &pageout_ctr, 8);

  aes_encrypt_ctr((uint8_t*)addr, len, (uint8_t*)dst, key_sched, 256, iv);
#else
  memcpy(dst, addr, len);
#endif
}

/// Copy page to destination, decrypting if USE_PAGE_CRYPTO is defined.
static void
pswap_decrypt(const void* addr, void* dst, uint64_t pageout_ctr) {
  size_t len = RISCV_PAGE_SIZE;

#ifdef USE_PAGE_CRYPTO
  uint8_t iv[32] = {0};
  WORD key_sched[80];
  aes_key_setup(aes_key, key_sched, 256);

  memcpy(iv + 8, &pageout_ctr, 8);

  aes_decrypt_ctr((uint8_t*)addr, len, (uint8_t*)dst, key_sched, 256, iv);
#else
  memcpy(dst, addr, len);
#endif
}

#ifdef USE_PAGE_HASH
static void
pswap_hmac(uint8_t* hash, void* page_addr, uint64_t pageout_ctr) {
  HMACContext ctx;

  hmacReset(&ctx, hmac_key, sizeof hmac_key);
  hmacInput(&ctx, page_addr, RISCV_PAGE_SIZE);
  hmacInput(&ctx, (uint8_t*)&pageout_ctr, sizeof(pageout_ctr));
  hmacResult(&ctx, hash);
}
#endif

/* Evict a page from EPM and store it to the backing storage.
 * back_page (PA1) <-- epm_page (PA2) <-- swap_page (PA1)
 * If swap_page is 0, no need to write epm_page. Otherwise, swap_page must
 * point to the same address as back_page.
 */
int
page_swap_epm(uintptr_t back_page, uintptr_t epm_page, uintptr_t swap_page) {
  assert(paging_epm_inbounds(epm_page));
  assert(paging_backpage_inbounds(back_page));

  char buffer[RISCV_PAGE_SIZE] = {};
  if (swap_page) {
    assert(swap_page == back_page);
    memcpy(buffer, (void*)swap_page, RISCV_PAGE_SIZE);
  }

  uint64_t* pageout_ctr    = pswap_pageout_ctr(back_page);
  uint64_t old_pageout_ctr = *pageout_ctr;
  uint64_t new_pageout_ctr = old_pageout_ctr + 1;

#ifdef USE_PAGE_HASH
  hash_t* hmac = pswap_pageout_hmac(back_page);
  uint8_t new_hmac[32];
  pswap_hmac(new_hmac, (void*)epm_page, new_pageout_ctr);
#endif

  pswap_encrypt((void*)epm_page, (void*)back_page, new_pageout_ctr);

  if (swap_page) {
    pswap_decrypt((void*)buffer, (void*)epm_page, old_pageout_ctr);

#ifdef USE_PAGE_HASH
    uint8_t old_hmac[32];
    pswap_hmac(old_hmac, (void*)epm_page, old_pageout_ctr);
    if (memcmp(hmac, old_hmac, sizeof(hash_t))) {
      return -1;
    }
#endif
  }

#ifdef USE_PAGE_HASH
  *hmac = *(hash_t*)new_hmac;
#endif

  *pageout_ctr = new_pageout_ctr;

  return 0;
}

#endif
