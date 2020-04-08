#include "vm.h"
#include "page_replacement.h"
#include "printf.h"
#include"mm.h"
//CLOCK ALGO
//----------------------------------------------------------------------------------------------------
uintptr_t clock_insert(uintptr_t item_org_va, uintptr_t item_enc_va)
{
  //printf("[clock_insert] clock_counter = %lu\n",clock_counter );
  if(clock_counter>=frame_size)
    return QUEUE_FULL;
  replacement_algo_queue_map[pointer]=item_enc_va;
  //find_index[vpn(item_enc_va)]=pointer;
  //second_chance[pointer]='n';
  clock_counter++;
  pointer=(pointer+1)%frame_size;
  //printf("[clock] %d\n", __LINE__);
  return ENQUE_SUCCESS;

}
//----------------------------------------------------------------------------------------------------
uintptr_t get_clock_queue_size()
{
  return clock_counter;
}
//----------------------------------------------------------------------------------------------------
uintptr_t clock_remove()
{
  //printf("[clock_remove] clock_counter = %lu\n",clock_counter );

  if(clock_counter==0)
  {
    return QUEUE_EMPTY;
  }

  while(1)
  {
      // We found the page to replace
      //if(second_chance[pointer]=='n')
      //uintptr_t* cur_ptadr=(uintptr_t*)page_addr_tbl[vpn(replacement_algo_queue_map[pointer])];
      uintptr_t* cur_ptadr=0;

      if(replacement_algo_queue_map[pointer]!=0)
        cur_ptadr= __walk(get_root_page_table_addr(),replacement_algo_queue_map[pointer]);

      if(replacement_algo_queue_map[pointer]!=0    &&  ((*cur_ptadr & PTE_V)==0)   )
      {
        // Replace with new page
        //arr[pointer] = x;
        //cout << "brought -> " << arr[pointer]  << "                    ("<<pointer<<")"<< endl;
        pop_item[1]=replacement_algo_queue_map[pointer];
        replacement_algo_queue_map[pointer]=0;
        clock_counter--;
        return pop_item[0];
        //second_chance[pointer]='n';
      }

      // Mark it 'false' as it got one chance
      // and will be replaced next time unless accessed again

      //second_chance[pointer] = 'n';
      if(replacement_algo_queue_map[pointer]!=0)
        *cur_ptadr= (*cur_ptadr) & (~PTE_V);
      //Pointer is updated in round robin manner
      pointer = (pointer + 1) % frame_size;
      //printf("[clock] %d\n", __LINE__);
  }
  //traverse through the second chance array and find the a page with bit 0 and replace and in case all th elements are bitset then randomly replace some page
}
//----------------------------------------------------------------------------------------------------



void clear_bits()
{
  //printf("[timer] testing timer ");
  if(is_rt==0)
  {
    //printf("[clock] %d ",__LINE__);
    is_rt=1;
    for(uintptr_t i=0;i<clock_counter;i++)
    {
      if(replacement_algo_queue_map[i]!=0)
      {
        uintptr_t *root_page_table_addr=get_root_page_table_addr();root_page_table_addr=root_page_table_addr;
        //uintptr_t *sfa= (uintptr_t*)page_addr_tbl[vpn(replacement_algo_queue_map[i])];sfa=sfa;
        uintptr_t *sfa=__walk(root_page_table_addr,replacement_algo_queue_map[i]);sfa=sfa;
        *sfa= *sfa & (~PTE_V);
      }
      //printf("[clock] %d\n", __LINE__);
    }
  }

  return;
}
//----------------------------------------------------------------------------------------------------







//----------------------------------------------------------------------------------------------------
uintptr_t get_q_size()
{
  if(q_front==-1)
      return 0;
  return (q_rear>=q_front)?  q_rear-q_front+1 : ((MALLOC_SIZE2)-(q_front-q_rear-1));
}
//----------------------------------------------------------------------------------------------------
uintptr_t get_stack_size()
{
  return q_front+1;
}
//----------------------------------------------------------------------------------------------------
intptr_t is_Empty_queue()
{
  return q_front==-1;
}
//----------------------------------------------------------------------------------------------------
uintptr_t is_Full_queue()
{
  return (q_rear+1)%(MALLOC_SIZE2)==q_front;
}
//----------------------------------------------------------------------------------------------------
uintptr_t enque(uintptr_t item_org_va, uintptr_t item_enc_va)
{
  if(is_Full_queue())
  {
    return QUEUE_FULL;
  }
  if(q_front==q_rear && is_Empty_queue() ){
    q_front=q_rear=0;
    //replacement_algo_queue[q_rear]=item_org_va;
    replacement_algo_queue_map[q_rear]=item_enc_va;
    //printf("[PAGE REPLACEMENT] q_front = %d  q_rear = %d val=0x%lx\n",q_front, q_rear,replacement_algo_queue_map[q_rear]);

    return ENQUE_SUCCESS;
  }
  q_rear=(q_rear+1)%MALLOC_SIZE2;

  //replacement_algo_queue[q_rear]=item_org_va;
  replacement_algo_queue_map[q_rear]=item_enc_va;
  //printf("[PAGE REPLACEMENT] q_front = %d  q_rear = %d and val=0x%lx\n",q_front, q_rear,replacement_algo_queue_map[q_rear]);

  return ENQUE_SUCCESS;
}
//----------------------------------------------------------------------------------------------------
uintptr_t deque()
{
  if(is_Empty_queue())
  {
    return QUEUE_EMPTY;
  }
  //pop_item[0]= replacement_algo_queue[q_front];
  pop_item[1]= replacement_algo_queue_map[q_front];
  if(q_front==q_rear)
  {
    q_front=q_rear=-1;
  }
  else
  {
    q_front=(q_front+1)%(MALLOC_SIZE2);
  }
  return pop_item[0];
}
//----------------------------------------------------------------------------------------------------
uintptr_t is_Empty_stack()
{
  return q_front==-1;
}
//----------------------------------------------------------------------------------------------------
uintptr_t is_Full_stack()
{
  return (q_front)==  (MALLOC_SIZE2-1);
}
//----------------------------------------------------------------------------------------------------
uintptr_t push(uintptr_t item_org_va, uintptr_t item_enc_va)
{
  if(is_Full_stack())
  {
    return QUEUE_FULL;
  }
  replacement_algo_queue[++q_front]=item_org_va;
  replacement_algo_queue_map[q_front]=item_enc_va;
  return ENQUE_SUCCESS;
}
//----------------------------------------------------------------------------------------------------
uintptr_t pop()
{
  if(is_Empty_stack())
  {
    return QUEUE_EMPTY;
  }
  pop_item[0]= replacement_algo_queue[q_front];
  pop_item[1]= replacement_algo_queue_map[q_front--];
  return pop_item[0];
}





//PUBLIC FUNCTIONS
//----------------------------------------------------------------------------------------------------
void testing_que()
{
  printf("TESTING QUEUE\n");
}
//----------------------------------------------------------------------------------------------------
uintptr_t place_new_page(uintptr_t item_org_va, uintptr_t item_enc_va)
{
  //return push( item_org_va,  item_enc_va);
  return enque( item_org_va,  item_enc_va);
  //printf("[clock] %d\n", __LINE__);
  //return clock_insert(item_org_va,  item_enc_va);
}
//----------------------------------------------------------------------------------------------------
uintptr_t remove_victim_page()
{
  //return pop();
  return deque();
  //return clock_remove();
}
//----------------------------------------------------------------------------------------------------
uintptr_t get_queue_size()
{
  //return get_stack_size()+1;
  return get_q_size();
  //return get_clock_queue_size();
}

//----------------------------------------------------------------------------------------------------
void show_queue_contents()
{
  for(int i=q_front;i<=14000;i++)
  {
    //printf("0x%lx(0x%lx) \n",replacement_algo_queue_map[i],replacement_algo_queue[i] );
    printf("0x%lx(0x%lx) \n",replacement_algo_queue_map[i],0 );

  }
}
