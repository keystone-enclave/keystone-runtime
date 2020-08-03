#ifndef __MAILBOX_H__
#define __MAILBOX_H__

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "sbi.h"

#define MAILBOX_SIZE 256
typedef struct { int lock; } spinlock_t;
#define SPINLOCK_INIT {0}

struct mailbox
{
  size_t capacity; 
  size_t size; 
  uint8_t enabled; 
  spinlock_t lock; 
  uint8_t data[MAILBOX_SIZE]; 
}; 

struct mailbox_header
{
  size_t send_eid;
  size_t size; 
  uint8_t data[0]; 
}; 

static struct mailbox mailbox;

/* Initializes mailbox and registers it to the SM */
int init_mailbox(){
   int ret;
   mailbox.capacity = MAILBOX_SIZE;
   mailbox.size = 0;
   mailbox.lock.lock = 0;
   memset(mailbox.data, 0, MAILBOX_SIZE);

   ret = SBI_CALL_1(SBI_SM_MAILBOX_REGISTER, &mailbox); 
   return ret; 

}
/*
  Retrieves a message from the mailbox from sender uid  
  Copies at most buf_size bytes to buf from the message contents 
  If no message is present, this will block. 
  Returs the bytes written to buf. 
*/
int recv_mailbox_msg(size_t uid, void *buf, size_t buf_size){
  return 1;
}
/* 
  Sends a msg_size byte message copied from buf to uid
  Calls the SBI function to trap to the SM 
*/
int send_mailbox_msg(size_t uid, void *buf, size_t msg_size){
  int ret;
  ret = SBI_CALL_3(SBI_SM_MAILBOX_SEND, uid, buf, msg_size);
  return ret;
}
/* 
  Acquires the enclave mailbox. 
*/
int acquire_mailbox_lock(){
  return 1;
}
#endif
