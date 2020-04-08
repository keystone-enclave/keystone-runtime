#include "vm.h"
#include "page_replacement.h"
#include "printf.h"
#include "roram.h"
#include "index_q.h"



uintptr_t get_q_size2()
{
  /*
  if(front==-1)
      return 0;
  return (rear>=front)?  rear-front+1 : ((STASH_SIZE_RORAM)-(front-rear-1));
  */

  return (front+1);
}

//----------------------------------------------------------------------------------------------------



intptr_t is_Empty_queue2()
{
  return front==-1;
}
//----------------------------------------------------------------------------------------------------
uintptr_t is_Full_queue2()
{
  //return (rear+1)%(STASH_SIZE_RORAM)==front;

  return front==STASH_SIZE_RORAM;
}
//----------------------------------------------------------------------------------------------------
uintptr_t enque2(uintptr_t item_enc_va)
{
  if(!( item_enc_va>=0 && item_enc_va < STASH_SIZE_RORAM ))
  {
    printf("at line enque %d",item_enc_va);
  }


  if(is_Full_queue2())
  {
    return QUEUE_FULL;
  }

  /*

  if(front==rear && is_Empty_queue2() ){
    front=rear=0;

    free_indices[rear]=item_enc_va;

    return ENQUE_SUCCESS;
  }
  rear=(rear+1)%STASH_SIZE_RORAM;
  free_indices[rear]=item_enc_va;
  //replacement_algo_queue[rear]=item_org_va;

  //printf("[PAGE REPLACEMENT] front = %d  rear = %d and val=0x%lx\n",front, rear,replacement_algo_queue_map[rear]);

  return ENQUE_SUCCESS;

  */

  free_indices[++front]=item_enc_va;
  return ENQUE_SUCCESS;





}
//----------------------------------------------------------------------------------------------------
uintptr_t deque2()
{
  if(is_Empty_queue2())
  {
    return QUEUE_EMPTY;
  }
  //pop_item[0]= replacement_algo_queue[front];


  uintptr_t free_pos= free_indices[front];

  /*
  if(front==rear)
  {
    front=rear=-1;
  }
  else
  {
    front=(front+1)%(STASH_SIZE_RORAM);
  }
  return free_pos;
  */

  front--;
  return free_pos;

}
