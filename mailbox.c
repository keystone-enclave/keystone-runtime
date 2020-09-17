#include "mailbox.h" 
#include "printf.h"
#include "vm.h"
#include "uaccess.h"
 
/*
  Retrieves a message from the mailbox from sender uid
  Copies at most buf_size bytes to buf from the message contents
  If no message is present, this will block.
  Returs the bytes written to buf.
*/
int recv_mailbox_msg(size_t uid, void *buf, size_t buf_size){
  int ret;
  char cpy[256];
  uintptr_t ptr = kernel_va_to_pa(cpy);

  ret = SBI_CALL_3(SBI_SM_MAILBOX_RECV, (uintptr_t) uid, ptr, buf_size);
  copy_to_user(buf, cpy, buf_size);
  return ret;
}
/*
  Sends a msg_size byte message copied from buf to uid
  Calls the SBI function to trap to the SM
  We do not acquire a lock here because the SM will acquire the lock. 
*/
int send_mailbox_msg(size_t uid, void *buf, size_t msg_size){
  int ret;
  char cpy[256];
  uintptr_t ptr = kernel_va_to_pa(cpy);
  
  if(msg_size > MAILBOX_SIZE)
     return MAILBOX_ERROR;
  copy_from_user(cpy, buf, msg_size); 
  ret = SBI_CALL_3(SBI_SM_MAILBOX_SEND, (uintptr_t) uid, ptr, msg_size);
  return ret; 
}

size_t get_uid(){
  int ret;
  ret = SBI_CALL_0(SBI_SM_UID); 
  return ret; 
}

