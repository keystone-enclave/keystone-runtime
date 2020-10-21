#pragma once

#include <stdbool.h>
#include <stddef.h>

struct bench {
  const char* name;
  int (*init)(void* ctx);
  int (*iter)(void* ctx);
  int (*deinit)(void* ctx);
};

struct bench_opts {
  bool verbose;
  char* filter;
  int measure_secs;
  int bench_secs;
};

struct bench_opts
bench_argp(int argc, char** argv);
int
run_benches(
    struct bench_opts* opts, struct bench* benches, size_t nbenches, void* ctx);
