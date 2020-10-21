#define _GNU_SOURCE

#include "bencher.h"

#include <argp.h>
#include <assert.h>
#include <math.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ERROR(...) fprintf(stderr, "[ERROR]  " __VA_ARGS__)

static char*
precise_time_str(double seconds) {
  double precision;
  const char* prec_name;
  if (seconds < 1e-6) {
    prec_name = "ns";
    precision = 1e9;
  } else if (seconds < 1e-3) {
    prec_name = "us";
    precision = 1e6;
  } else if (seconds < 1) {
    prec_name = "ms";
    precision = 1e3;
  } else {
    prec_name = "s";
    precision = 1;
  }

  char* out;
  double adjusted = seconds * precision;
  int err = asprintf(&out, "%f%s", trunc(adjusted * 1000) / 1000, prec_name);
  return out;
}

static int
measure_iters(
    struct bench* bench, void* ctx, clock_t clocks, size_t chunk_size,
    size_t* niters) {
  int err;
  size_t i = 0;

  err = bench->init(ctx);
  if (err) {
    ERROR("Failed to initialize benchmark `%s`!\n", bench->name);
    return err;
  }

  clock_t end_clock = clock() + clocks;
  while (clock() < end_clock) {
    for (size_t ci = 0; ci < chunk_size; ci++, i++) {
      err = bench->iter(ctx);
      if (err) {
        ERROR(
            "Failed to run iteration `%zu` of benchmark `%s`!\n", i,
            bench->name);
        return err;
      }
    }
  }

  assert(niters);
  *niters = i;

  err = bench->deinit(ctx);
  if (err) {
    ERROR("Failed to deinitialize benchmark `%s`!\n", bench->name);
    return err;
  }

  return 0;
}

static int
run_bench(
    struct bench* bench, void* ctx, size_t nchunks, size_t chunk_size,
    double* chunk_mean, double* chunk_std) {
  int err;

  err = bench->init(ctx);
  if (err) {
    ERROR("Failed to initialize benchmark `%s`!\n", bench->name);
    return err;
  }

  clock_t chunk_start, chunk_end;
  size_t chunk;
  double mean, m2;

  for (chunk = 0; chunk < nchunks; chunk++) {
    chunk_start = clock();

    for (size_t ci = 0; ci < chunk_size; ci++) {
      err = bench->iter(ctx);
      if (err) {
        ERROR(
            "Failed to run iteration `%zu` of benchmark `%s`!\n",
            chunk * chunk_size + ci, bench->name);
        return err;
      }
    }

    chunk_end = clock();

    double chunk_time = (double)(chunk_end - chunk_start) / CLOCKS_PER_SEC;
    double delta      = chunk_time - mean;
    mean += delta / (chunk + 1);
    double delta2 = chunk_time - mean;
    m2 += delta * delta2;
  }

  double variance = m2 / chunk;
  assert(chunk_mean);
  assert(chunk_std);
  *chunk_mean = mean;
  *chunk_std  = sqrt(variance);

  err = bench->deinit(ctx);
  if (err) {
    ERROR("Failed to deinitialize benchmark `%s`!\n", bench->name);
    return err;
  }

  return 0;
}

int
run_benches(
    struct bench_opts* opts, struct bench* benches, size_t nbenches,
    void* ctx) {
  regex_t filter;
  if (opts->filter) {
    int err = regcomp(&filter, opts->filter, REG_NOSUB);
    if (err) {
      ERROR("Bad regular expression: `%s`", opts->filter);
      exit(err);
    }
  }

  int measure_secs = 2;
  int bench_secs   = 10;
  assert(bench_secs % measure_secs == 0);
  clock_t measure_clocks = measure_secs * CLOCKS_PER_SEC;

#define CHECK_ERR(err, ...) \
  if (err) {                \
    putchar('\n');          \
    ERROR(__VA_ARGS__);     \
    exit(err);              \
  }

  for (size_t i = 0; i < nbenches; i++) {
    struct bench* bench = &benches[i];
    if (opts->filter && regexec(&filter, bench->name, 0, NULL, 0) != 0)
      continue;

    size_t measured_iters;
    clock_t bench_time;
    char* iter_time;
    int err;

    double single_time, _single_std;

    if (opts->verbose)
      printf("`%s`: Measuring single iteration... ", bench->name);
    err = run_bench(bench, ctx, 1, 1, &single_time, &_single_std);
    CHECK_ERR(err, "Failed to measure `%s`!\n", bench->name);

    if (opts->verbose) {
      iter_time = precise_time_str(single_time);
      assert(iter_time);
      printf("<%s\n", iter_time);
      free(iter_time);
    }

    double approx_measured_iters = measure_secs / single_time;
    size_t chunk_size            = pow(2.0, log2(approx_measured_iters) / 2);

    if (opts->verbose)
      printf(
          "`%s`: Counting num iterations in %ds... ", bench->name,
          measure_secs);
    err =
        measure_iters(bench, ctx, measure_clocks, chunk_size, &measured_iters);
    CHECK_ERR(err, "Failed to measure `%s`!\n", bench->name);
    if (opts->verbose) printf("%zu iterations.\n", measured_iters);

    size_t bench_iters = (bench_secs / measure_secs) * measured_iters;
    size_t nchunks     = bench_iters / chunk_size;

    double chunk_mean, chunk_std;

    printf(
        "`%s`: Benchmarking %zux%zu iterations (~%ds)...\n", bench->name,
        nchunks, chunk_size, bench_secs);
    err = run_bench(bench, ctx, nchunks, chunk_size, &chunk_mean, &chunk_std);
    CHECK_ERR(err, "Failed to measure `%s`!\n", bench->name);

    iter_time = precise_time_str(chunk_mean);
    printf("  Chunk runtime: %s", iter_time);
    free(iter_time);

    iter_time = precise_time_str(chunk_std);
    printf(" (+/- %s)\n", iter_time);
    free(iter_time);

    iter_time = precise_time_str(chunk_mean / chunk_size);
    printf("  Time/Iter: %s\n", iter_time);
    free(iter_time);
  }

  return 0;
}

static error_t
bench_arg_parser(int key, char* val, struct argp_state* state) {
  struct bench_opts* opts = (struct bench_opts*)state->input;
  switch (key) {
    case 'f':
      opts->filter = strdup(val);
      break;
    case 'v':
      opts->verbose = true;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

struct bench_opts
bench_argp(int argc, char** argv) {
  struct bench_opts opts = {};

  struct argp_option argp_opts[] = {
      {.name = "filter", .key = 'f', .arg = "REGEXP"},
      {.name = "verbose", .key = 'v'},
      {}};
  struct argp argp = {
      .options = argp_opts,
      .parser  = bench_arg_parser,
  };
  error_t err = argp_parse(&argp, argc, argv, 0, 0, &opts);
  if (err) {
    ERROR("Can't parse arguments!\n");
  }

  return opts;
}
