CFLAGS := -I . -g -lm -O3 -Wall -Wextra

.PHONY: bencher clean

bencher:
	$(CC) $(CFLAGS) \
		-DUSE_FREEMEM -DUSE_PAGING -DUSE_PAGE_HASH -D__riscv_xlen=64 \
		bencher.c merkle.c \
		../merkle.c ../sha256.c \
		-o $@

clean:
	rm -rf bencher