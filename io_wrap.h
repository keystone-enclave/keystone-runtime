#ifndef _IO_WRAP_H_
#define _IO_WRAP_H_

#include <sys/uio.h>

uintptr_t io_syscall_read(int fd, void* buf, size_t len);
uintptr_t io_syscall_write(int fd, void* buf, size_t len);
uintptr_t io_syscall_writev(int fd, const struct iovec *iov, int iovcnt);
uintptr_t io_syscall_openat(int dirfd, char* path,
                            int flags, mode_t mode);

#endif /* _IO_WRAP_H_ */
