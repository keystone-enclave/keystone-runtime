#include <stdint.h>
#include "io_wrap.h"
/* Syscalls iozone uses in -i0 mode
*** Fake these
 *  clock_gettime
 *  getpid
 *   set_tid_address
 *   uname
*** Proxy these
    openat
    close
    fsync
    newfstatat
    sync
    write
    unlinkat
    ftruncate
*** Unclear if we need
    execve
    exit_group
*** Hard
    rt_sigaction
    rt_sigprocmask
    brk
    mmap
*/
struct io_syscall_wrapper{
  int syscall_num;
  void* syscall_data;
};

/* uintptr_t io_syscall_read(int fd, void* buf, size_t len) */
uintptr_t io_syscall_read(uintptr_t fd, uintptr_t buf, uintptr_t len){

  return -1;
}
/* uintptr_t io_syscall_write(int fd, void* buf, size_t len) */
uintptr_t io_syscall_write(uintptr_t fd, uintptr_t buf, uintptr_t len){

  return -1;
}
/* uintptr_t io_syscall_openat(int dirfd, char* path,
                            int flags, mode_t mode) */
uintptr_t io_syscall_openat(uintptr_t dirfd, uintptr_t path,
                            uintptr_t flags, uintptr_t mode){

  return -1;
}
