#ifndef __MAILBOX_H__
#define __MAILBOX_H__

#define MAILBOX_SIZE 256
struct mailbox
{
  size_t capacity; 
  size_t size; 
  uint8_t enabled; 
  int lock; 
  byte data[MAILBOX_SIZE]; 
}; 

struct mailbox_header
{
  size_t send_eid;
  size_t size; 
  byte data[0]; 
}; 

//Initializes mailbox
int init_mailbox(struct mailbox *mailbox); 

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

/* 
  Acquires the enclave mailbox. 
*/
int acquire_mailbox_lock()

#endif
