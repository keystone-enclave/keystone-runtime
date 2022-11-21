CFLAGS := -I . -g -O3 -Wall -Wextra
LDFLAGS := -lm
BENCH_FLAGS := -DUSE_FREEMEM -DUSE_PAGING -DUSE_PAGE_HASH -DUSE_PAGE_CRYPTO -D__riscv_xlen=64

.PHONY: benches clean

benches: merkle crypto

MODULES := merkle.o sha256.o aes.o bench/bencher.o bench/crypto.o bench/merkle.o
OBJ_PREFIX := objs/

$(addprefix $(OBJ_PREFIX),$(MODULES)) :: $(OBJ_PREFIX)%.o : ../%.c
	mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) $(BENCH_FLAGS) -c -o $@ $^

MERKLE_MODULES := merkle.o sha256.o bench/bencher.o bench/merkle.o
merkle: $(addprefix $(OBJ_PREFIX),$(MERKLE_MODULES))
	$(CC) $(CFLAGS) $(BENCH_FLAGS) $^ $(LDFLAGS) -o $@

CRYPTO_MODULES := sha256.o aes.o bench/bencher.o bench/crypto.o
crypto: $(addprefix $(OBJ_PREFIX),$(CRYPTO_MODULES))
	$(CC) $(CFLAGS) $(BENCH_FLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -rf merkle crypto objs/
