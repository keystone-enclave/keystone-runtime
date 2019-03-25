#ifndef _LINUX_WRAP_H_
#define _LINUX_WRAP_H_

#include <stddef.h>
#include <sys/time.h>

int linux_clock_gettime(__clockid_t clock, struct timespec *tp);
int linux_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int linux_getrandom(void *buf, size_t buflen, unsigned int flags);

#endif /* _LINUX_WRAP_H_ */
