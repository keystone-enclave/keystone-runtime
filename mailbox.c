//Initializes mailbox
int init_mailbox(struct mailbox *mailbox){
   return 1; 

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
  return 1; 
}

/*
  Acquires the enclave mailbox.
*/
int acquire_mailbox_lock(){
  return 1; 
}
