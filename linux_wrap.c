#include "uaccess.h"
#include "linux_wrap.h"
#include "syscall.h"
#include <sys/mman.h>
#include "freemem.h"
#include "mm.h"

#define CLOCK_FREQ 1000000000

//TODO we should check which clock this is
uintptr_t linux_clock_gettime(__clockid_t clock, struct timespec *tp){
  print_strace("[runtime] clock_gettime not fully supported (clock %x, assuming)\r\n", clock);
  unsigned long cycles;
  asm volatile ("rdcycle %0" : "=r" (cycles));

  unsigned long sec = cycles / CLOCK_FREQ;
  unsigned long nsec = (cycles % CLOCK_FREQ);

  copy_to_user(&(tp->tv_sec), &sec, sizeof(unsigned long));
  copy_to_user(&(tp->tv_nsec), &nsec, sizeof(unsigned long));

  return 0;
}

uintptr_t linux_set_tid_address(int* tidptr_t){
  //Ignore for now
  print_strace("[runtime] set_tid_address, not setting address (%p), IGNORING\r\n",tidptr_t);
  return 1;
}

uintptr_t linux_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset){
  print_strace("[runtime] rt_sigprocmask not supported (how %x), IGNORING\r\n", how);
  return 0;
}

uintptr_t linux_RET_ZERO_wrap(unsigned long which){
  print_strace("[runtime] Cannot handle syscall %lu, IGNORING = 0\r\n", which);
  return 0;
}

uintptr_t linux_RET_BAD_wrap(unsigned long which){
  print_strace("[runtime] Cannot handle syscall %lu, FAILING = -1\r\n", which);
  return -1;
}

uintptr_t linux_getpid(){
  uintptr_t fakepid = 2;
  print_strace("[runtime] Faking getpid with %lx\r\n",fakepid);
  return fakepid;
}

uintptr_t linux_getrandom(void *buf, size_t buflen, unsigned int flags){
  print_strace("[runtime] [UNSAFE] getrandom not supported (size %lx), returning non-random values\r\n", buflen);
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

uintptr_t syscall_mmap(void *addr, size_t length, int prot, int flags,
                 int fd, __off_t offset){
  uintptr_t ret = (uintptr_t)((void*)-1);

  int pte_flags = PTE_U | PTE_A;

  if(flags != (MAP_ANONYMOUS | MAP_PRIVATE) || fd != -1){
    // we don't support mmaping any other way yet
    return (uintptr_t)((void*)-1);
  }

  // Set flags
  if(prot & PROT_READ)
    pte_flags |= PTE_R;
  if(prot & PROT_WRITE)
    pte_flags |= PTE_W | PTE_D;
  if(prot & PROT_EXEC)
    pte_flags |= PTE_X;



  // Find a continuous VA space that will fit the req. size
  int req_pages = vpn(PAGE_UP(length));
  uintptr_t starting_vpn = vpn(EYRIE_ANON_REGION_START);
  uintptr_t vpn_error;
  // Start looking at EYRIE_ANON_REGION_START
  for(; (starting_vpn + req_pages) <= EYRIE_ANON_REGION_END; starting_vpn = vpn_error){
    vpn_error = try_alloc_pages_unused_only(starting_vpn, req_pages, pte_flags);
    // Region was clear, we got our pages allocated
    if(vpn_error == 0){
      ret = starting_vpn << RISCV_PAGE_BITS;
      break;
    }
    // Region was NOT clear, start looking at the page after the one that was taken
    else
      starting_vpn = vpn_error+1;
  }

  print_strace("[runtime] [mmap]: addr: %p, length %lu, prot 0x%x, flags 0x%x, fd %i, offset %lu (%li pages %x) = 0x%lx\r\n", addr, length, prot, flags, fd, offset, req_pages, pte_flags, ret);

  // If we get here everything went wrong
  return ret;
}


uintptr_t syscall_brk(void* addr){
  // Two possible valid calls to brk we handle:
  // NULL -> give current break
  // ADDR -> give more pages up to ADDR if possible

  uintptr_t req_break = (uintptr_t)addr;

  uintptr_t current_break = get_program_break();

  if( req_break == 0 ){
    // Return current break
    return current_break;
  }

  // Otherwise try to allocate pages
  // Sanity check
  if( req_break <= current_break ){
    return current_break;
  }

  // Can we allocate?
  int req_page_count = (PAGE_UP(req_break) - current_break) / RISCV_PAGE_SIZE;
  if( spa_available() < req_page_count)
    return current_break;

  // Allocate pages
  // TODO free pages on failure
  if( alloc_pages(vpn(current_break),
                  req_page_count,
                  PTE_W | PTE_R | PTE_D)
      != req_page_count){
    return current_break;
  }

  return req_break;

}
