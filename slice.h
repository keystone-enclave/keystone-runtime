#pragma once

#include <string.h>

typedef struct {
  void* buf;
  size_t len;
} slice_t;

#define SLICE(ptr, _start, end)               \
  ({                                          \
    size_t start = _start;                    \
    (slice_t){                                \
        .buf = (ptr) + start,                 \
        .len = ((end)-start) * sizeof *(ptr), \
    };                                        \
  })

static inline void
slice_move(void* dst, slice_t src) {
  memmove(dst, src.buf, src.len);
}
static inline void
slice_copy(void* dst, slice_t src) {
  memcpy(dst, src.buf, src.len);
}
static inline void
slice_fill(slice_t dst, char c) {
  memset(dst.buf, c, dst.len);
}