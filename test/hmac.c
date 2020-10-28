#define _GNU_SOURCE

#include "../hmac.c"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "mock.h"

void
test_create_hmac() {
  uint8_t key[]   = "null";
  uint8_t input[] = "null";
  uint8_t digest[USHAHashSize()];
  uint8_t digest_expected[] = {0xb4, 0xb1, 0x09, 0x3e, 0xb9, 0x42, 0x81, 0x6c,
                               0x0d, 0x39, 0x99, 0xa9, 0x4b, 0xdf, 0x50, 0x08,
                               0x2a, 0x4b, 0xe3, 0x02, 0x39, 0x62, 0x6e, 0xc6,
                               0xf7, 0x65, 0xc7, 0x94, 0x39, 0x97, 0xfe, 0x89};
  int res = hmac(input, strlen(input), key, strlen(key), digest);
  assert_int_equal(res, 0);
  assert_memory_equal(digest, digest_expected, sizeof(digest));
}

int
main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_create_hmac),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}