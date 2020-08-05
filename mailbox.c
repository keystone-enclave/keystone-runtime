#include "mailbox.h" 

struct mailbox mailbox;

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
  struct mailbox_header *hdr = (struct mailbox_header *) mailbox.data; 
  size_t size = 0; 

  //Acquire lock on the mailbox
   

  while(size < mailbox.size){
     if(hdr->send_uid == uid){
        //Check if the message is bigger than the buffer. 
        if(hdr->size > buf_size){
            return 1; 
	}
  
        memcpy(buf, hdr->data, buf_size); 

        //Clear the message from the mailbox
        memset(hdr, 0, hdr->size); 

        size_t rem = mailbox.size - ((size_t) (((char *) hdr) + hdr->size)) - (size_t) mailbox.data;
        
        if(rem < 0)
		return 0; 
        
        memcpy(hdr, hdr + hdr->size, rem); 
        
        mailbox.size -= hdr->size; 
     }

    size += sizeof(struct mailbox_header) + hdr->size; 
    hdr += sizeof(struct mailbox_header) + hdr->size;    
 

  }
  
  //Release lock on mailbox 

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
