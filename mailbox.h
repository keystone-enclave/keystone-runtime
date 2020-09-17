#ifndef MAILBOX_H
#define MAILBOX_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "sbi.h"

#define MAILBOX_SIZE 256
typedef struct { int lock; } spinlock_t;
#define SPINLOCK_INIT {0}

#define MAILBOX_ERROR 1 
#define MAILBOX_SUCCESS 0 

struct mailbox
{
  size_t capacity; 
  size_t size; 
  uint8_t enabled; 
  size_t uid; 
  spinlock_t lock; 
  uint8_t data[MAILBOX_SIZE]; 
}; 

struct mailbox_header
{
  size_t send_uid;
  size_t size; 
  uint8_t data[0]; 
}; 

extern struct mailbox mailbox;

/* Initializes mailbox and registers it to the SM */
int init_mailbox(); 
/*
  Retrieves a message from the mailbox from sender uid  
  Copies at most buf_size bytes to buf from the message contents 
  If no message is present, this will block. 
  Returs the bytes written to buf. 
*/
int recv_mailbox_msg(size_t uid, void *buf, size_t buf_size);
/* 
  Sends a msg_size byte message copied from buf to uid
  Calls the SBI function to trap to the SM 
*/
int send_mailbox_msg(size_t uid, void *buf, size_t msg_size);

/* Gets the enclave uid from the SM */
size_t get_uid(); 

#endif
