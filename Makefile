CC_H = riscv$(BITS)-unknown-linux-gnu-
CC = $(CC_H)gcc
OBJCOPY = $(CC_H)objcopy


ifndef KEYSTONE_SDK_DIR
  $(error KEYSTONE_SDK_DIR is undefined)
endif

CFLAGS = -Wall -Werror -fPIC -fno-builtin $(OPTIONS_FLAGS)
SRCS = boot.c interrupt.c printf.c syscall.c string.c linux_wrap.c io_wrap.c rt_util.c mm.c env.c freemem.c paging.c
ASM_SRCS = entry.S
RUNTIME = eyrie-rt
LINK = $(CC_H)ld
LDFLAGS = -static -nostdlib

SDK_LIB_DIR = $(KEYSTONE_SDK_DIR)/lib
SDK_INCLUDE_EDGE_DIR = $(SDK_LIB_DIR)/edge/include
SDK_EDGE_LIB = $(SDK_LIB_DIR)/libkeystone-edge.a

LDFLAGS += -L$(SDK_LIB_DIR)
CFLAGS += -I$(SDK_INCLUDE_EDGE_DIR) -I ./tmplib

DISK_IMAGE = ../busybear-linux/busybear.bin
MOUNT_DIR = ./tmp_busybear

OBJS = $(patsubst %.c,%.o,$(SRCS))
ASM_OBJS = $(patsubst %.S,%.o,$(ASM_SRCS))

TMPLIB = uaccess.o

all: $(RUNTIME) $(OBJS)

$(TMPLIB):
	$(MAKE) -C tmplib

$(DISK_IMAGE):
	echo "missing $(DISK_IMAGE)."

copy: $(RUNTIME) $(DISK_IMAGE)
	echo "Copying library $(RUNTIME)"
	mkdir -p $(MOUNT_DIR)
	sudo mount $(DISK_IMAGE) $(MOUNT_DIR)
	sudo cp $(RUNTIME) $(MOUNT_DIR)/lib
	sudo umount $(MOUNT_DIR)
	rm -rf $(MOUNT_DIR)

$(RUNTIME): $(ASM_OBJS) $(OBJS) $(SDK_EDGE_LIB) $(TMPLIB)
	$(LINK) $(LINKFLAGS) -o $@ $^ -T runtime.lds $(RISCV)/lib/gcc/riscv$(BITS)-unknown-elf/8.3.0/libgcc.a
	$(OBJCOPY) --add-section .options_log=.options_log --set-section-flags .options_log=noload,readonly $(RUNTIME) 

$(ASM_OBJS): $(ASM_SRCS)
	$(CC) $(CFLAGS) -c $<

%.o: %.c  $(TMPLIB)
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(RUNTIME) *.o
	$(MAKE) -C tmplib clean
	# for legacy reasons, remove any lingering uaccess.h
	rm -f uaccess.h
