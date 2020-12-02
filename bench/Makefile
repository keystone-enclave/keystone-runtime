CFLAGS := -I . -g -O3 -Wall -Wextra
LDFLAGS := -lm
BENCH_FLAGS := -DUSE_FREEMEM -DUSE_PAGING -DUSE_PAGE_HASH -DUSE_PAGE_CRYPTO -D__riscv_xlen=64

.PHONY: benches clean

benches: hmac crypto page_swap

MODULES := hmac.o sha256.o aes.o page_swap.o freemem.o bench/bencher.o bench/crypto.o bench/hmac.o bench/page_swap.o
OBJ_PREFIX := objs/

$(addprefix $(OBJ_PREFIX),$(MODULES)) :: $(OBJ_PREFIX)%.o : ../%.c
	mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) $(BENCH_FLAGS) -c -o $@ $^

HMAC_MODULES := hmac.o sha256.o bench/bencher.o bench/hmac.o
hmac: $(addprefix $(OBJ_PREFIX),$(HMAC_MODULES))
	$(CC) $(CFLAGS) $(BENCH_FLAGS) $^ $(LDFLAGS) -o $@

CRYPTO_MODULES := sha256.o aes.o bench/bencher.o bench/crypto.o
crypto: $(addprefix $(OBJ_PREFIX),$(CRYPTO_MODULES))
	$(CC) $(CFLAGS) $(BENCH_FLAGS) $^ $(LDFLAGS) -o $@

PAGE_SWAP_MODULES := sha256.o aes.o hmac.o freemem.o page_swap.o bench/bencher.o bench/page_swap.o
page_swap: $(addprefix $(OBJ_PREFIX),$(PAGE_SWAP_MODULES))
	$(CC) $(CFLAGS) $(BENCH_FLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -rf hmac crypto page_swap objs/
