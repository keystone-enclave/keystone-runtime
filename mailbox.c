#include "mailbox.h" 
#include "printf.h"
#include "vm.h"
#include "uaccess.h"
 
struct mailbox mailbox;

/* Initializes mailbox and registers it to the SM */
int init_mailbox(){
   int ret;
   mailbox.capacity = MAILBOX_SIZE;
   mailbox.size = 0;
   mailbox.lock.lock = 0;
   memset(mailbox.data, 0, MAILBOX_SIZE);

   ret = SBI_CALL_1(SBI_SM_MAILBOX_REGISTER, kernel_va_to_pa(&mailbox));
   return ret;

}
/*
  Retrieves a message from the mailbox from sender uid
  Copies at most buf_size bytes to buf from the message contents
  If no message is present, this will block.
  Returs the bytes written to buf.
*/
int recv_mailbox_msg(size_t uid, void *buf, size_t buf_size){
  uint8_t *ptr = mailbox.data;
  struct mailbox_header *hdr = (struct mailbox_header *) ptr;  
  size_t size = 0; 
  size_t hdr_size = 0; 

  //Acquire lock on the mailbox
  acquire_mailbox_lock();    

  while(size < mailbox.size){

     hdr_size = hdr->size; 

     if(hdr->send_uid == uid){
        //Check if the message is bigger than the buffer. 
        if(hdr->size > buf_size){
            return 1; 
	}

        copy_to_user(buf, hdr->data, buf_size); 

        //Clear the message from the mailbox
        memset(hdr->data, 0, hdr->size);
        memset(hdr, 0, sizeof(struct mailbox_header));
        memcpy(hdr, ptr + hdr_size + sizeof(struct mailbox_header), mailbox.size - (size + sizeof(struct mailbox_header) + hdr_size)); 
       
        mailbox.size -= hdr_size + sizeof(struct mailbox_header); 
        return 0; 
     }

    size += sizeof(struct mailbox_header) + hdr_size;
    ptr += sizeof(struct mailbox_header) + hdr_size;    
    hdr = (struct mailbox_header *) ptr;
    release_mailbox_lock(); 

  }
  
  //Release lock on mailbox 

  return 1;
}
/*
  Sends a msg_size byte message copied from buf to uid
  Calls the SBI function to trap to the SM
  We do not acquire a lock here because the SM will acquire the lock. 
*/
int send_mailbox_msg(size_t uid, void *buf, size_t msg_size){
  int ret;
  char cpy[256];
  printf("[runtime] uid: %u\n", uid); 
  copy_from_user(cpy, buf, msg_size); 
  ret = SBI_CALL_3(SBI_SM_MAILBOX_SEND, uid, kernel_va_to_pa(cpy), msg_size);
  return ret;
}
/*
  Acquires the enclave mailbox.
*/
int acquire_mailbox_lock(){
   return 1;
}

/*
  Releases the enclave mailbox.
*/
int release_mailbox_lock(){
   return 0; 
}
