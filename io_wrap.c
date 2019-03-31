#include <stdint.h>
#include "io_wrap.h"
#include <alloca.h>
#include "uaccess.h"
#include "syscall.h"
#include "string.h"
#include "edge_syscall.h"

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



uintptr_t io_syscall_read(int fd, void* buf, size_t len){
  edge_syscall_t* edge_syscall = (edge_syscall_t*)edge_call_data_ptr();
  sargs_SYS_read* args = (sargs_SYS_read*)edge_syscall->data;

  edge_syscall->syscall_num = SYS_read;
  args->fd =fd;
  args->len = len;

  size_t totalsize = (sizeof(edge_syscall_t) +
                      sizeof(sargs_SYS_read) +
                      len);

  uintptr_t ret = dispatch_edgecall_syscall(edge_syscall, totalsize);
  print_strace("[runtime] dispatching proxied read (size: %lu) = %li\r\n",len, ret);

  if(ret > 0 && ret <= len){
      //TODO safety check!
    copy_to_user(buf, args->buf, ret);
  }
  return ret;
}

#define MAX_STRACE_PRINT 20

uintptr_t io_syscall_write(int fd, void* buf, size_t len){
  print_strace("[write] len :%lu\r\n", len);
  if(len > 0){
    size_t stracelen = len > MAX_STRACE_PRINT? MAX_STRACE_PRINT:len;
    char* lbuf[MAX_STRACE_PRINT+1];
    memset(lbuf, 0, sizeof(lbuf));
    copy_from_user(lbuf, (void*)buf, stracelen);
    print_strace("[write] \"%s\"\r\n", (char*)lbuf);
  }

  edge_syscall_t* edge_syscall = (edge_syscall_t*)edge_call_data_ptr();
  sargs_SYS_write* args = (sargs_SYS_write*)edge_syscall->data;

  edge_syscall->syscall_num = SYS_write;
  args->fd =fd;
  args->len = len;
  //TODO safety check!
  copy_from_user(args->buf, buf, len);

  size_t totalsize = (sizeof(edge_syscall_t) +
                      sizeof(sargs_SYS_write) +
                      len);

  uintptr_t ret = dispatch_edgecall_syscall(edge_syscall, totalsize);
  print_strace("[runtime] dispatching proxied write (size: %lu) = %li\r\n",len, ret);
  return ret;
}

uintptr_t io_syscall_openat(int dirfd, char* path,
                            int flags, mode_t mode){
  edge_syscall_t* edge_syscall = (edge_syscall_t*)edge_call_data_ptr();
  sargs_SYS_openat* args = (sargs_SYS_openat*)edge_syscall->data;

  edge_syscall->syscall_num = SYS_openat;
  args->dirfd = dirfd;
  args->flags = flags;
  args->mode = mode;
  //TODO safety check!
  size_t pathlen;
  ALLOW_USER_ACCESS(pathlen = _strlen(path)+1);
  copy_from_user(args->path, path, pathlen);

  size_t totalsize = (sizeof(edge_syscall_t) +
                      sizeof(sargs_SYS_openat) +
                      pathlen);

  uintptr_t ret = dispatch_edgecall_syscall(edge_syscall, totalsize);
  print_strace("[runtime] dispatching openat(path: %s) = %li\r\n",args->path, ret);

  return ret;
}

uintptr_t io_syscall_writev(int fd, const struct iovec *iov, int iovcnt){
  int i=0;
  uintptr_t ret = 0;
  size_t total = 0;
  print_strace("[runtime] Simulating writev (cnt %i) with write calls\r\n",iovcnt);
  for(i=0; i<iovcnt && ret >= 0;i++){
    struct iovec iov_local;
    copy_from_user(&iov_local, &(iov[i]), sizeof(struct iovec));
    ret = io_syscall_write(fd,iov_local.iov_base, iov_local.iov_len);
    total += ret;
  }
  if(ret >= 0)
    ret = total;

  return ret;
}

uintptr_t io_syscall_readv(int fd, const struct iovec *iov, int iovcnt){
  int i=0;
  uintptr_t ret = 0;
  size_t total = 0;
  print_strace("[runtime] Simulating readv (cnt %i) with read calls\r\n",iovcnt);
  for(i=0; i<iovcnt && ret >= 0;i++){
    struct iovec iov_local;
    copy_from_user(&iov_local, &(iov[i]), sizeof(struct iovec));
    ret = io_syscall_read(fd, iov_local.iov_base, iov_local.iov_len);
    total += ret;
  }
  if(ret >= 0)
    ret = total;

  return ret;
}
