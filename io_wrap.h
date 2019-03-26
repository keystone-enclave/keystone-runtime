#ifndef _IO_WRAP_H_
#define _IO_WRAP_H_

uintptr_t io_syscall_read(uintptr_t fd, uintptr_t buf, uintptr_t len);
/* uintptr_t io_syscall_write(int fd, void* buf, size_t len) */
uintptr_t io_syscall_write(uintptr_t fd, uintptr_t buf, uintptr_t len);
/* uintptr_t io_syscall_openat(int dirfd, char* path,
                            int flags, mode_t mode) */
uintptr_t io_syscall_openat(uintptr_t dirfd, uintptr_t path,
                            uintptr_t flags, uintptr_t mode);

#endif /* _IO_WRAP_H_ */
