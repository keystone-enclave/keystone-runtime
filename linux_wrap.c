#include "uaccess.h"
#include "linux_wrap.h"
#include "printf.h"
int linux_clock_gettime(__clockid_t clock, struct timespec *tp){
  printf("[runtime] clock_gettime not supported (clock %x, FAKING\n", clock);
  /* We will just return cycle count for now */
    unsigned long cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));

    copy_to_user(&(tp->tv_sec), &cycles, sizeof(unsigned long));
    copy_to_user(&(tp->tv_nsec), &cycles, sizeof(unsigned long));

    return 0;
}

int linux_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset){
  printf("[runtime] rt_sigprocmask not supported (how %x), IGNORING\n", how);
  return 0;
}

int linux_getrandom(void *buf, size_t buflen, unsigned int flags){
  printf("[runtime] getrandom not supported (size %lx), FAKING [UNSAFE]\n", buflen);
  unsigned char v;
  size_t remaining = buflen;

  unsigned char* next_buf = (unsigned char*)buf;
  while(remaining > 0){
    v = remaining%255;
    copy_to_user(next_buf,&v,sizeof(unsigned char));
    remaining--;
    next_buf++;
  }

  return buflen;
}
