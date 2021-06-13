#ifdef IO_NET_SYSCALL_WRAPPING
#include <stdint.h>
#include "io_wrap.h"
#include <alloca.h>
#include "uaccess.h"
#include "syscall.h"
#include "string.h"
#include "edge_syscall.h"
#include <sys/epoll.h>

uintptr_t io_syscall_socket(int domain, int type, int protocol){
  uintptr_t ret = -1;
  struct edge_syscall* edge_syscall = (struct edge_syscall*)edge_call_data_ptr();
  edge_syscall->syscall_num = SYS_socket;

  sargs_SYS_socket *args = (sargs_SYS_socket *) edge_syscall->data;

  args->domain = domain; 
  args->type = type; 
  args->protocol = protocol; 

  size_t totalsize = sizeof(struct edge_syscall) + sizeof(sargs_SYS_socket);
  ret = dispatch_edgecall_syscall(edge_syscall, totalsize);

  print_strace("[runtime] proxied socket: %d \r\n", ret);
  return ret; 
}

uintptr_t io_syscall_setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len){
  uintptr_t ret = -1;
  struct edge_syscall* edge_syscall = (struct edge_syscall*)edge_call_data_ptr();
  edge_syscall->syscall_num = SYS_setsockopt;

  sargs_SYS_setsockopt *args = (sargs_SYS_setsockopt *) edge_syscall->data;

  args->socket = socket; 
  args->level = level; 
  args->option_name = option_name; 
  args->option_len = option_len; 

  copy_from_user(&args->option_value, option_value, option_len);

  printf("socket: socket: %d, level: %d, opt_name: %d, opt_val: %d, opt_len: %d\n", 
          args->socket, args->level, args->option_name, args->option_value, args->option_len);

  size_t totalsize = sizeof(struct edge_syscall) + sizeof(sargs_SYS_setsockopt);
  ret = dispatch_edgecall_syscall(edge_syscall, totalsize);

  print_strace("[runtime] proxied setsockopt: %d \r\n", ret);
  return ret; 

}

uintptr_t io_syscall_bind (int sockfd, uintptr_t addr, socklen_t addrlen){

  uintptr_t ret = -1;
  struct edge_syscall* edge_syscall = (struct edge_syscall*)edge_call_data_ptr();
  edge_syscall->syscall_num = SYS_bind;

  sargs_SYS_bind *args = (sargs_SYS_bind *) edge_syscall->data;

  args->sockfd = sockfd; 
  args->addrlen = addrlen; 

  printf("sockfd: %d, addrlen: %d\n", 
          args->sockfd, args->addrlen);

  copy_from_user(&args->addr, (void *) addr, addrlen);

  printf("sockfd: %d, addrlen: %d\n", 
          args->sockfd, args->addrlen);

  size_t totalsize = sizeof(struct edge_syscall) + sizeof(sargs_SYS_bind);
  ret = dispatch_edgecall_syscall(edge_syscall, totalsize);

  print_strace("[runtime] proxied bind: %d \r\n", ret);
  return ret; 

}

uintptr_t io_syscall_listen(int sockfd, int backlog){
   uintptr_t ret = -1;
  struct edge_syscall* edge_syscall = (struct edge_syscall*)edge_call_data_ptr();
  edge_syscall->syscall_num = SYS_listen;

  sargs_SYS_listen *args = (sargs_SYS_listen *) edge_syscall->data;

  args->sockfd = sockfd; 
  args->backlog = backlog; 

  size_t totalsize = sizeof(struct edge_syscall) + sizeof(sargs_SYS_listen);
  ret = dispatch_edgecall_syscall(edge_syscall, totalsize);

  print_strace("[runtime] proxied listen: %d \r\n", ret);
  return ret; 

}

uintptr_t io_syscall_accept(int sockfd, uintptr_t addr, uintptr_t addrlen) {
  uintptr_t ret = -1;
  struct edge_syscall* edge_syscall = (struct edge_syscall*)edge_call_data_ptr();
  edge_syscall->syscall_num = SYS_accept;

  sargs_SYS_accept *args = (sargs_SYS_accept *) edge_syscall->data;

  args->sockfd = sockfd; 

  copy_from_user(&args->addrlen, (void *) addrlen, sizeof(socklen_t));
  copy_from_user(&args->addr, (void *) addr, args->addrlen);

  size_t totalsize = sizeof(struct edge_syscall) + sizeof(sargs_SYS_accept);
  ret = dispatch_edgecall_syscall(edge_syscall, totalsize);

  print_strace("[runtime] proxied accept: %d \r\n", ret);
  return ret; 
}

#endif /* IO_NET_SYSCALL_WRAPPING */ 