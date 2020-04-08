#include "mm.h"
#include "rt_util.h"
#include "printf.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_call.h"
#include "aess.h"
#include "ssha3.h"
#include "freemem.h"
#include "vm.h"
#include "page_replacement.h"
#include "roram.h"
#include "index_q.h"


//------------------------------DEFINING REQURIED GLOBAL VARIABLES---------------------------
/*
Block_roram S_roram[STASH_SIZE_RORAM];
Bucket_roram_md S_roram_md[STASH_SIZE_RORAM];
Bucket_roram_md tree_roram_md[RORAM_TREE_SIZE];
*/

Block_roram *S_roram;
Bucket_roram_md *S_roram_md;
Bucket_roram_md *tree_roram_md;

char rd[RISCV_PAGE_SIZE];

int global_j;

int S_roram_len=0;
int Sg_roram_len=0;
int round =0;
Block_roram  blk_i_d_ro;
Bucket_roram_md buc_i_md_ro;
//Bucket_roram buc_i_d_ro;
Bucket_roram *buc_i_d_ro;

int S_o=0;
int G=0;
//char buff[BACKUP_BUFFER_SIZE];
char dum;
char gdum;
int A=0;
Bucket_roram *tmp_buc_d;
//---------------------------------------FUNCTIONS BEGIN-----------------------------------------
void update_max_stash_occ()
{
/*
  uintptr_t c=0;
  for(int i=0;i<STASH_SIZE_RORAM;i++)
  {
    if(S_roram[i].address!=DUMMY_BLOCK_ADDR)
      c++;
  }
  //printf("[ringoram] in mso que size = %lu\n",get_q_size2());
*/
  uintptr_t c=STASH_SIZE_RORAM-get_q_size2();

  if(c>max_stash_occ)
    max_stash_occ=c;

}
//------------------------------------------------------------------------------
uint8_t get_block_offset(uintptr_t a)//ALGO 5.1
{
    uint8_t ptr=0;
    char f='n';
    global_j=-1;
    for(int j=0;j<Z+S_o;j++)
    {
      if((a<<RISCV_PAGE_BITS)==buc_i_md_ro.addr[j] && buc_i_md_ro.valids[buc_i_md_ro.ptrs[j]]=='y')
      {
        f='y';
        ptr=buc_i_md_ro.ptrs[j];
        dum='n';
        global_j=j;
        break;
      }
    }
    if(f=='y')
      return ptr;
    for(int j=0;j<Z+S_o;j++)
    {
      if(buc_i_md_ro.addr[j]==DUMMY_BLOCK_ADDR && buc_i_md_ro.valids[buc_i_md_ro.ptrs[j]]=='y')
      {
        ptr=buc_i_md_ro.ptrs[j];
        dum='y';
        global_j=j;
        break;
      }
    }
    return ptr;
}
//------------------------------------------------------------------------------
void display_page_contents_arr(char *a)
{
  for(int i=0;i<RISCV_PAGE_SIZE;i++)
  {
    printf("0x%lx ",a[i] );
  }
}
//------------------------------------------------------------------------------
void read_path(int* pl,uintptr_t a,char *retdatas)//algo
{

  // the check for bucket_map shud be here..

  if(block_map[a]!=-1)
  {
    buc_i_md_ro= tree_roram_md[block_map[a]];
    dum='y';
    uint8_t offset=get_block_offset(a);
    uintptr_t params[2];
    params[0]=(uintptr_t)block_map[a];
    params[1]=(uintptr_t)offset;
    memcpy( (void*)(&blk_i_d_ro)  ,(void*)&(tree_roram_tree_top[params[0]].blocks[params[1]]), sizeof(Block_roram)    );

    buc_i_md_ro.valids[offset]='n';
    memcpy((void*)retdatas, (void*)(blk_i_d_ro.data), RISCV_PAGE_SIZE);
    gdum='n';
    tree_roram_md[block_map[a]]=buc_i_md_ro;
    // insert the check to update the bucket hashmap here. bucket_map[a]=-1;
    block_map[a]=-1;
    return;

  }



  for(int i=CACHING_LEVEL;i<=L;i++)
  {
    buc_i_md_ro= tree_roram_md[pl[i]];
    dum='y';
    uint8_t offset=get_block_offset(a);
    uintptr_t params[2];
    params[0]=(uintptr_t)pl[i];
    params[1]=(uintptr_t)offset;
    uintptr_t time_read_beg=0,time_read_end=0;

// for external
    if(CACHING_LEVEL==0 || i>(CACHING_LEVEL-1))// TTC
    {

      edge_data_t retdata;
  //remove after time calc
      asm volatile ("rdcycle %0" : "=r" (time_read_beg));

      dispatch_edgecall_ocall(OCALL_RORAM_READ_BLOCK,(void*)params,sizeof(uintptr_t)*2, &retdata,sizeof(retdata),0);
      handle_copy_from_shared((void*)&blk_i_d_ro,retdata.offset,retdata.size);
      pages_read++;


      if(  tree_roram_md[pl[i]].addr[global_j]!=DUMMY_BLOCK_ADDR || tree_roram_md[pl[i]].is_hash[global_j]=='y')// extra for paper
      {
        char hash_calc[HASH_SIZE];
        sha3_ctx_t sha3;
        sha3_init(&sha3, HASH_SIZE);
        char c[16];
        xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
        sha3_update(&sha3, (void*)c, AES_KEYLEN);
        sha3_update(&sha3, (void*)&(blk_i_d_ro.address), sizeof(uintptr_t)*2);
        sha3_update(&sha3, (void*)blk_i_d_ro.data, RISCV_PAGE_SIZE);
        sha3_update(&sha3, (void*)blk_i_d_ro.iv, AES_KEYLEN);
        //add sha3 for indexoftree
        sha3_final((void*)hash_calc, &sha3);
        char c2[16];
        xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
        char hash_calc2[HASH_SIZE];
        sha3_ctx_t sha32;
        sha3_init(&sha32, HASH_SIZE);
        sha3_update(&sha32, (void*)c2, AES_KEYLEN);
        sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
        sha3_final((void*)hash_calc2, &sha32);

        if(  (tree_roram_md[pl[i]].addr[global_j]!=DUMMY_BLOCK_ADDR || tree_roram_md[pl[i]].is_hash[global_j]=='y') &&    !check_hashes(  (void*)hash_calc2  ,HASH_SIZE,  (void*)blk_i_d_ro.p_hash ,HASH_SIZE  )      )
        {
          printf("[runtime] Page corrupted. HMAC integrity check failed.  Fatal error\n");
          sbi_exit_enclave(-1);
        }
       }
       // else// extra for paper
       // {
       //   if(tree_roram_md[pl[i]].is_hash[global_j]=='y')
       //   {
       //     char hash_calc[HASH_SIZE];
       //     sha3_ctx_t sha3;
       //     sha3_init(&sha3, HASH_SIZE);
       //     char c[16];
       //     xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
       //     sha3_update(&sha3, (void*)c, AES_KEYLEN);
       //     sha3_update(&sha3, (void*)&(blk_i_d_ro.address), sizeof(uintptr_t)*2);
       //     sha3_update(&sha3, (void*)blk_i_d_ro.data, RISCV_PAGE_SIZE);
       //     sha3_update(&sha3, (void*)blk_i_d_ro.iv, AES_KEYLEN);
       //     //add sha3 for indexoftree
       //     sha3_final((void*)hash_calc, &sha3);
       //     char c2[16];
       //     xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
       //     char hash_calc2[HASH_SIZE];
       //     sha3_ctx_t sha32;
       //     sha3_init(&sha32, HASH_SIZE);
       //     sha3_update(&sha32, (void*)c2, AES_KEYLEN);
       //     sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
       //     sha3_final((void*)hash_calc2, &sha32);
       //
       //     if(  !check_hashes(  (void*)hash_calc2  ,HASH_SIZE,  (void*)blk_i_d_ro.p_hash ,HASH_SIZE  )      )
       //     {
       //       printf("[runtime] Page corrupted. HMAC integrity check failed.  Fatal error\n");
       //       sbi_exit_enclave(-1);
       //     }
       //   }

       //}

      if(  tree_roram_md[pl[i]].addr[global_j]!=DUMMY_BLOCK_ADDR)
        decrypt_page((uint8_t *) &(blk_i_d_ro.address),sizeof(uintptr_t)*2,key,(uint8_t *)blk_i_d_ro.iv);



      if(  tree_roram_md[pl[i]].addr[global_j]!=DUMMY_BLOCK_ADDR)
      //if(  blk_i_d_ro.address!=DUMMY_BLOCK_ADDR)
      {
        if(confidentiality)
        {
          decrypt_page((uint8_t *) blk_i_d_ro.data,RISCV_PAGE_SIZE,key,(uint8_t *)blk_i_d_ro.iv);
        }
      }
    //check version number
      if(  tree_roram_md[pl[i]].addr[global_j]!=DUMMY_BLOCK_ADDR)// check only for real blocks and not for dummy blocks
      //if(  blk_i_d_ro.address!=DUMMY_BLOCK_ADDR)
      {
        real_pages_read++;
        if(version_numbers[vpn(blk_i_d_ro.address)] !=  blk_i_d_ro.version)
        {
          printf("[runtime] Page corrupted(Possibly a replay attack).  Fatal error\n");
          sbi_exit_enclave(-1);
        }
      }

  //remove after time calc
      asm volatile ("rdcycle %0" : "=r" (time_read_end));
      uintptr_t time_read=time_read_end-time_read_beg;
      if(  tree_roram_md[pl[i]].addr[global_j]!=DUMMY_BLOCK_ADDR)
      //if(  blk_i_d_ro.address!=DUMMY_BLOCK_ADDR)
      {
        if(real_pages_read<=BLOCKS_FOR_TIME_COUNTING)
          time_rblocks_process_r+=time_read;
      }
      else
      {
        if((pages_read-real_pages_read)<=BLOCKS_FOR_TIME_COUNTING)
          time_dblocks_process_r+=time_read;
      }
    }

    //TTC
    else
    {
      if(dum=='n')
      {
        //printf("[roram]line%d index = %lu offset = %lu\n",__LINE__,params[0],params[1]);
        memcpy( (void*)(&blk_i_d_ro)  ,(void*)&(tree_roram_tree_top[params[0]].blocks[params[1]]), sizeof(Block_roram)    );

        // extra
        buc_i_md_ro.valids[offset]='n';
        memcpy((void*)retdatas, (void*)(blk_i_d_ro.data), RISCV_PAGE_SIZE);
        gdum='n';
        tree_roram_md[pl[i]]=buc_i_md_ro;
        // insert the check to update the bucket hashmap here. bucket_map[a]=-1;
        return;
        // extra
      }

    }



// for external tree



    if(CACHING_LEVEL==0 || i>(CACHING_LEVEL-1)  /*|| ( global_j!=-1 &&   buc_i_md_ro.addr[global_j]!=DUMMY_BLOCK_ADDR  ) */   )//extra
    {
      buc_i_md_ro.valids[offset]='n';
    }

    if(dum=='n')
    {
      memcpy((void*)retdatas, (void*)(blk_i_d_ro.data), RISCV_PAGE_SIZE);
      gdum='n';
    }

    if(CACHING_LEVEL==0 || i>(CACHING_LEVEL-1))//extra
    {
      buc_i_md_ro.count++;
    }

    tree_roram_md[pl[i]]=buc_i_md_ro;
  }
}
//------------------------------------------------------------------------------
void roram_writebucket(int indexoftree)//this write bucket function is only used during initialization and is not the write function given in the paper
{
  uintptr_t _indexoftree=(uintptr_t)indexoftree;
  for(int i=0;i<Z+S_o;i++)
  {

//remove after time calc
    unsigned long long time_read_beg=0,time_read_end=0;
    asm volatile ("rdcycle %0" : "=r" (time_read_beg));
    char cc='d';


    rt_util_getrandom((void*) (*buc_i_d_ro).blocks[i].iv, AES_KEYLEN);
    //printf("[roram] iv filling done for i = %d\n",i );
    if((*buc_i_d_ro).blocks[i].address!=DUMMY_BLOCK_ADDR )// not a dummy block
    {
      version_numbers[   vpn((*buc_i_d_ro).blocks[i].address)]++;
      (*buc_i_d_ro).blocks[i].version=version_numbers[   vpn((*buc_i_d_ro).blocks[i].address)];
      cc='r';
    }
    if((*buc_i_d_ro).blocks[i].address!=DUMMY_BLOCK_ADDR )// not a dummy block
    {
      if(confidentiality)
      {
        encrypt_page(    (uint8_t *) (*buc_i_d_ro).blocks[i].data,RISCV_PAGE_SIZE,key,(uint8_t *)(*buc_i_d_ro).blocks[i].iv);
      }
    }
    else// dummy block
    {
      cc='d';
      //rt_util_getrandom((void*) (*buc_i_d_ro).blocks[i].data, RISCV_PAGE_SIZE);
      if(confidentiality)
      {
        fill_page_with_zeroes((*buc_i_d_ro).blocks[i].data);
      }
      //encrypt_page(    (uint8_t *) (*buc_i_d_ro).blocks[i].data,RISCV_PAGE_SIZE,key,(uint8_t *)(*buc_i_d_ro).blocks[i].iv);


      //printf("[roram] data filling done for i = %d\n",i );

    }


    encrypt_page(  (uint8_t *) &((*buc_i_d_ro).blocks[i].address),sizeof(uintptr_t)*2,key,(uint8_t *)(*buc_i_d_ro).blocks[i].iv);


    /*struct AES_ctx ctx_e2;
    AES_init_ctx_ivs(&ctx_e2, key, (uint8_t *)(*buc_i_d_ro).blocks[i].iv);
    AES_CBC_encrypt_buffers(&ctx_e2, in, in_size);
    */


    //printf("[roram] encryption done for i = %d\n",i );
    if(cc=='r')
    {
      char hash_calc[HASH_SIZE];
      sha3_ctx_t sha3;
      sha3_init(&sha3, HASH_SIZE);
      char c[16];
      xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
      sha3_update(&sha3, (void*)c, AES_KEYLEN);
      sha3_update(&sha3, (void*)&((*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[i]].address), sizeof(uintptr_t)*2);
      sha3_update(&sha3, (void*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[i]].data, RISCV_PAGE_SIZE);
      sha3_update(&sha3, (void*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[i]].iv, AES_KEYLEN);
      //add sha3 for indexoftree
      sha3_final((void*)hash_calc, &sha3);
      char c2[16];
      xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
      sha3_ctx_t sha32;
      sha3_init(&sha32, HASH_SIZE);
      sha3_update(&sha32, (void*)c2, AES_KEYLEN);
      sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
      sha3_final((void*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[i]].p_hash, &sha32);
    }
    else
    {
      char chachanonces[16];
      rt_util_getrandom((void*) chachanonces, 16);
      chacha20((uint8_t*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[i]].p_hash, (uint8_t*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[i]].p_hash, HASH_SIZE, (uint8_t*)key_chacha, (uint8_t*)chachanonces, 1);
    }
    //printf("[roram] sha done for i = %d\n",i );

//remove after time calc
    asm volatile ("rdcycle %0" : "=r" (time_read_end));
    uintptr_t time_read=time_read_end-time_read_beg;
    if( cc=='r')
    {
      if(real_pages_written<=BLOCKS_FOR_TIME_COUNTING)
        time_rblocks_process_w+=time_read;
    }
    else
    {
      if((pages_written-real_pages_written)<=BLOCKS_FOR_TIME_COUNTING)
        time_dblocks_process_w+=time_read;
    }


  }
  unsigned long long time_read_beg=0,time_read_end=0;

  asm volatile ("rdcycle %0" : "=r" (time_read_beg));
  memcpy((void*)buff, (void*)&_indexoftree,sizeof(uintptr_t));
  //printf("[roram] copy1 done for \n" );

  memcpy((void*)(buff+sizeof(uintptr_t)), (void*)buc_i_d_ro,sizeof(Bucket_roram));
  //printf("[roram] copy2 done for \n" );

  dispatch_edgecall_ocall(OCALL_RORAM_WRITE_BUCKET,(void*)buff, sizeof(uintptr_t)+ sizeof(Bucket_roram),NULL, 0,0);
  //printf("[roram] ocall \n" );

  pages_written+=(Z+S_o);
  asm volatile ("rdcycle %0" : "=r" (time_read_end));

  time_block_copy_w=   ((time_read_end-time_read_beg)>>6);

}
//------------------------------------------------------------------------------------
void search_in_stash(int a,char* retdata)
{
/*

  for(int i=0;i<STASH_SIZE_RORAM;i++)
  {
    if(S_roram[i].address==(a<<RISCV_PAGE_BITS))
    {
      memcpy((void*)retdata,(void*)S_roram[i].data,RISCV_PAGE_SIZE);
      S_roram[i].address=DUMMY_BLOCK_ADDR;//deleting this
      assert((uintptr_t)i>=0 && (uintptr_t)i < STASH_SIZE_RORAM);
      if(enque2((uintptr_t)i)!=ENQUE_SUCCESS)
      {
        printf("[roram] free index insertion failed\n");
      }

      return;
    }
  }
*/

  assert(a>=1 && a < MALLOC_SIZE);
  int i= stash_loc[a];
  assert((uintptr_t)i>=0 && (uintptr_t)i < STASH_SIZE_RORAM);
  if(i==-1)
    return;
  memcpy((void*)retdata,(void*)S_roram[i].data,RISCV_PAGE_SIZE);
  S_roram[i].address=DUMMY_BLOCK_ADDR;//deleting this

  assert((uintptr_t)i>=0 && (uintptr_t)i < STASH_SIZE_RORAM);
  if(enque2((uintptr_t)i)!=ENQUE_SUCCESS)
  {
    printf("[roram] free index insertion failed\n");
  }
  //printf("[ringoram] in search_in_stash que size = %lu\n",get_q_size2());
  assert(a>=1 && a < MALLOC_SIZE);
  stash_loc[a]=-1;





}
//------------------------------------------------------------------------------------
void add_to_stash(int a,char* retdata)
{

/*
  for(int i=0;i<STASH_SIZE_RORAM;i++)
  {
    if(S_roram[i].address==DUMMY_BLOCK_ADDR)
    {
      memcpy((void*)S_roram[i].data,(void*)retdata,RISCV_PAGE_SIZE);
      S_roram[i].address=(a<<RISCV_PAGE_BITS);//addring this
      stash_loc[a]=i;
      sum_stash_occ++;
      deque2();
      //assert((int)deque2()==i);

      return;
    }
  }
*/


  int i= (int)deque2();i=i;

  //printf("[ringoram] in add_to_stash que size = %lu\n",get_q_size2());

  assert(i>=0 && i < STASH_SIZE_RORAM);
  memcpy((void*)S_roram[i].data,(void*)retdata,RISCV_PAGE_SIZE);
  S_roram[i].address=(a<<RISCV_PAGE_BITS);//addring this
  assert(a>=1 && a < MALLOC_SIZE);
  stash_loc[a]=i;
  sum_stash_occ++;


}
//------------------------------------------------------------------------------------
void read_bucket_roram(int buc_index)
{
  int cz=0;
  for(int j=0;j<Z+S_o && cz<Z;j++)
  {
    if(buc_i_md_ro.valids[buc_i_md_ro.ptrs[j]]=='y'  && buc_i_md_ro.addr[j]!=DUMMY_BLOCK_ADDR)
    {
      uintptr_t params[2];
      params[0]=(uintptr_t)buc_index;
      params[1]=(uintptr_t)buc_i_md_ro.ptrs[j];
      edge_data_t retdata;

      //remove after time calc
      uintptr_t time_read_beg=0,time_read_end=0;
      asm volatile ("rdcycle %0" : "=r" (time_read_beg));



      dispatch_edgecall_ocall(OCALL_RORAM_READ_BLOCK,(void*)params,sizeof(uintptr_t)*2, &retdata,sizeof(retdata),0);
      handle_copy_from_shared((void*)&blk_i_d_ro,retdata.offset,retdata.size);
      pages_read++;

      char hash_calc[HASH_SIZE];
      sha3_ctx_t sha3;
      sha3_init(&sha3, HASH_SIZE);
      char c[16];
      xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
      sha3_update(&sha3, (void*)c, AES_KEYLEN);
      sha3_update(&sha3, (void*)&(blk_i_d_ro.address), sizeof(uintptr_t)*2);
      sha3_update(&sha3, (void*)blk_i_d_ro.data, RISCV_PAGE_SIZE);
      sha3_update(&sha3, (void*)blk_i_d_ro.iv, AES_KEYLEN);
      //add sha3 for indexoftree
      sha3_final((void*)hash_calc, &sha3);
      char c2[16];
      xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
      char hash_calc2[HASH_SIZE];
      sha3_ctx_t sha32;
      sha3_init(&sha32, HASH_SIZE);
      sha3_update(&sha32, (void*)c2, AES_KEYLEN);
      sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
      sha3_final((void*)hash_calc2, &sha32);
      if(!check_hashes(  (void*)hash_calc2  ,HASH_SIZE,  (void*)blk_i_d_ro.p_hash ,HASH_SIZE  )      )
      {
        printf("[runtime] Page corrupted. HMAC integrity check failed.  Fatal error\n");
        sbi_exit_enclave(-1);
      }

      decrypt_page((uint8_t *) &(blk_i_d_ro.address),sizeof(uintptr_t)*2,key,(uint8_t *)blk_i_d_ro.iv);

      if(blk_i_d_ro.address!=DUMMY_BLOCK_ADDR)
      {
        if(confidentiality)
        {
          decrypt_page((uint8_t *) blk_i_d_ro.data,RISCV_PAGE_SIZE,key,(uint8_t *)blk_i_d_ro.iv);
        }
      }
      //check version number
      if( blk_i_d_ro.address!=DUMMY_BLOCK_ADDR)// check only for valid blocks and not for dummy blocks
      {
        real_pages_read++;
        if(version_numbers[vpn(blk_i_d_ro.address)] !=  blk_i_d_ro.version)
        {
          printf("[runtime] Page corrupted(Possibly a replay attack).  Fatal error\n");
          sbi_exit_enclave(-1);
        }
      }

  //remove after time calc
      asm volatile ("rdcycle %0" : "=r" (time_read_end));
      uintptr_t time_read=time_read_end-time_read_beg;
      if( blk_i_d_ro.address!=DUMMY_BLOCK_ADDR)
      {
        if(real_pages_read<=BLOCKS_FOR_TIME_COUNTING)
          time_rblocks_process_r+=time_read;
      }
      else
      {
        if((pages_read-real_pages_read)<=BLOCKS_FOR_TIME_COUNTING)
          time_dblocks_process_r+=time_read;
      }



      add_to_stash(vpn(buc_i_md_ro.addr[j]),blk_i_d_ro.data);
      cz++;
    }
  }
  for(int j=0;j<Z+S_o && cz<Z;j++)
  {
    if(buc_i_md_ro.valids[buc_i_md_ro.ptrs[j]]=='y'  && buc_i_md_ro.addr[j]==DUMMY_BLOCK_ADDR)
    {
      uintptr_t params[2];
      params[0]=(uintptr_t)buc_index;
      params[1]=(uintptr_t)buc_i_md_ro.ptrs[j];
      edge_data_t retdata;
      dispatch_edgecall_ocall(OCALL_RORAM_READ_BLOCK,(void*)params,sizeof(uintptr_t)*2, &retdata,sizeof(retdata),0);
      handle_copy_from_shared((void*)&blk_i_d_ro,retdata.offset,retdata.size);
      pages_read++;
      cz++;

      //extra for paper. check for dummy for is_hash set flag pages
      if(buc_i_md_ro.is_hash[j]=='y')
      {
        char hash_calc[HASH_SIZE];
        sha3_ctx_t sha3;
        sha3_init(&sha3, HASH_SIZE);
        char c[16];
        xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
        sha3_update(&sha3, (void*)c, AES_KEYLEN);
        sha3_update(&sha3, (void*)&(blk_i_d_ro.address), sizeof(uintptr_t)*2);
        sha3_update(&sha3, (void*)blk_i_d_ro.data, RISCV_PAGE_SIZE);
        sha3_update(&sha3, (void*)blk_i_d_ro.iv, AES_KEYLEN);
        //add sha3 for indexoftree
        sha3_final((void*)hash_calc, &sha3);
        char c2[16];
        xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
        char hash_calc2[HASH_SIZE];
        sha3_ctx_t sha32;
        sha3_init(&sha32, HASH_SIZE);
        sha3_update(&sha32, (void*)c2, AES_KEYLEN);
        sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
        sha3_final((void*)hash_calc2, &sha32);
        if(!check_hashes(  (void*)hash_calc2  ,HASH_SIZE,  (void*)blk_i_d_ro.p_hash ,HASH_SIZE  )      )
        {
          printf("[runtime] Page corrupted. HMAC integrity check failed.  Fatal error\n");
          sbi_exit_enclave(-1);
        }
      }

    }
  }
}
//------------------------------------------------------------------------------------
void PRP(uint8_t* arr, int n)
{
  //printf("[runtime] line %d\n",__LINE__ );

  for(int i=0;i<n;i++)
  {
    //printf("[runtime] line %d\n",__LINE__ );


    int rand_num=0;
    //printf("[runtime] line %d\n",__LINE__ );

r:  rt_util_getrandom(&rand_num,sizeof(int));
    //printf("[runtime] line %d\n",__LINE__ );

    if(rand_num<0)
      rand_num=rand_num*-1;
    //printf("[runtime] line %d\n",__LINE__ );

    //rand_num=rand_num%n;//uncomment

    rand_num=i+ rand_num%(n-i);//comment

    //printf("[runtime] line %d\n",__LINE__ );

    if(rand_num < i)
    {
      printf("[runtime] line %d\n",__LINE__ );
      goto r;//uncoment
    }
    uint8_t temp =arr[i];
    //printf("[runtime] line %d\n",__LINE__ );

    arr[i]=arr[rand_num];
    //printf("[runtime] line %d\n",__LINE__ );

    arr[rand_num]=temp;
    //printf("[runtime] line %d\n",__LINE__ );

  }
  //printf("[runtime] line %d\n",__LINE__ );


}
//------------------------------------------------------------------------------------
void write_bucket_roram(int buc_index,int level)
{
  int cz=0;
  int plj[50];
  S_roram[3].address=S_roram[3].address;
  uintptr_t real_blocks_scanned=0;
  //printf("[runtime] line %d\n",__LINE__ );

  uintptr_t qs_cur=get_q_size2();
  //printf("[runtime] line %d\n",__LINE__ );

  int num_pages_hashed=0;// extra for paper
  uintptr_t real_left_in_stash=STASH_SIZE_RORAM-qs_cur;
  for(int j=0;j<STASH_SIZE_RORAM && cz<Z && real_blocks_scanned < real_left_in_stash;j++)
  {
    //printf("[runtime] line %d\n",__LINE__ );

    if(S_roram[j].address!=DUMMY_BLOCK_ADDR)
    {
      //printf("[runtime] line %d\n",__LINE__ );

      real_blocks_scanned++;
      //printf("[runtime] line %d\n",__LINE__ );

      pxget(position[vpn(S_roram[j].address)],plj);
      //printf("[runtime] line %d\n",__LINE__ );

      if(plj[level]==buc_index)
      {
        (*tmp_buc_d).blocks[cz]=S_roram[j];
        //printf("[runtime] line %d\n",__LINE__ );

        buc_i_md_ro.addr[cz]=S_roram[j].address;
        stash_loc[vpn(S_roram[j].address)]=-1;

        buc_i_md_ro.is_hash[cz]='y';// extra for paper
        num_pages_hashed++;// extra for paper

        //printf("[runtime] line %d\n",__LINE__ );

        // insert the check to update the bucket hashmap here. if(CACHING_LEVEL!=0 && level<=(CACHING_LEVEL-1)){bucket_map[vpn(S_roram[j].address)]=buc_index;   }

        if(CACHING_LEVEL!=0 && level<=(CACHING_LEVEL-1))// EXTRA 2
        {
          //printf("[runtime] line %d\n",__LINE__ );

          block_map[vpn(S_roram[j].address)]=buc_index;
          //printf("[runtime] line %d\n",__LINE__ );

        }

        S_roram[j].address=DUMMY_BLOCK_ADDR;



        assert((uintptr_t)j>=0 && (uintptr_t)j < STASH_SIZE_RORAM);
        if(enque2((uintptr_t)j)!=ENQUE_SUCCESS)
        {
          printf("[roram] free index insertion failed\n");
        }
        //printf("[runtime] line %d\n",__LINE__ );

        cz++;
      }
    }
  }
  while(cz<Z+S_o)
  {
    //printf("[runtime] line %d\n",__LINE__ );

    (*tmp_buc_d).blocks[cz].address=DUMMY_BLOCK_ADDR;
    //printf("[runtime] line %d\n",__LINE__ );

    buc_i_md_ro.addr[cz]=DUMMY_BLOCK_ADDR;

    if(num_pages_hashed<MIN_HASH_NUM)// extra for paper
    {
      buc_i_md_ro.is_hash[cz]='y';// extra for paper
      num_pages_hashed++;// extra for paper
    }// extra for paper
    else
    {
      buc_i_md_ro.is_hash[cz]='n';
    }

    //printf("[runtime] line %d\n",__LINE__ );

    cz++;
  }
  for(int k=0;k<Z+S_o;k++)
  {
    //printf("[runtime] line %d\n",__LINE__ );

    buc_i_md_ro.ptrs[k]=k;
    //printf("[runtime] line %d\n",__LINE__ );

  }


  //printf("[runtime] line %d\n",__LINE__ );

  PRP(buc_i_md_ro.ptrs,Z+S_o);
  //printf("[runtime] line %d\n",__LINE__ );


// for outside tree
  if(CACHING_LEVEL==0 || level>(CACHING_LEVEL-1))//TTC
  {
    //PRP(buc_i_md_ro.ptrs,Z+S_o);
    for(int j=0;j<Z+S_o;j++)// preparing to write to external tree by encrypting and sha
    {
      //printf("[runtime] line %d\n",__LINE__ );

      (*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]]= (*tmp_buc_d).blocks[j];
      //printf("[runtime] line %d\n",__LINE__ );

  //remove after time calc
      uintptr_t time_read_beg=0,time_read_end=0;
      //printf("[runtime] line %d\n",__LINE__ );

      asm volatile ("rdcycle %0" : "=r" (time_read_beg));

      //printf("[runtime] line %d\n",__LINE__ );
      char cc='d';
      //printf("[runtime] line %d\n",__LINE__ );

      rt_util_getrandom((void*) (*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].iv, AES_KEYLEN);
      //printf("[runtime] line %d\n",__LINE__ );



      if((*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].address!=DUMMY_BLOCK_ADDR )// not a dummy block
      {
        //printf("[runtime] line %d\n",__LINE__ );

        real_pages_written++;

        version_numbers[   vpn((*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].address)]++;
        //printf("[runtime] line %d\n",__LINE__ );

        (*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].version=version_numbers[   vpn((*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].address)];
        //printf("[runtime] line %d\n",__LINE__ );

      }

      if((*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].address!=DUMMY_BLOCK_ADDR )// not a dummy block
      {
        cc='r';
        if(confidentiality)
        {
          encrypt_page(    (uint8_t *) (*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].data,RISCV_PAGE_SIZE,key,(uint8_t *)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].iv);
        }
      }
      else//dummy block
      {
        cc='d';
        //printf("[runtime] line %d\n",__LINE__ );

        //rt_util_getrandom((void*) (*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].data, RISCV_PAGE_SIZE);
        if(confidentiality)
        {
          fill_page_with_zeroes((*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].data);
        }
        //encrypt_page(    (uint8_t *) (*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].data,RISCV_PAGE_SIZE,key,(uint8_t *)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].iv);

        //printf("[runtime] line %d\n",__LINE__ );

      }

      //printf("[runtime] line %d\n",__LINE__ );

      encrypt_page(  (uint8_t *) &((*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].address),sizeof(uintptr_t)*2,key,(uint8_t *)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].iv);
      //printf("[runtime] line %d\n",__LINE__ );
      if(cc=='r' || buc_i_md_ro.is_hash[j]=='y')// extra for paper
      {
        char hash_calc[HASH_SIZE];
        sha3_ctx_t sha3;
        sha3_init(&sha3, HASH_SIZE);
        char c[16];
        xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
        sha3_update(&sha3, (void*)c, AES_KEYLEN);
        sha3_update(&sha3, (void*)&((*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].address), sizeof(uintptr_t)*2);
        sha3_update(&sha3, (void*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].data, RISCV_PAGE_SIZE);
        sha3_update(&sha3, (void*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].iv, AES_KEYLEN);
        //add sha3 for indexoftree
        sha3_final((void*)hash_calc, &sha3);
        char c2[16];
        xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
        sha3_ctx_t sha32;
        sha3_init(&sha32, HASH_SIZE);
        sha3_update(&sha32, (void*)c2, AES_KEYLEN);
        sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
        sha3_final((void*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].p_hash, &sha32);
      }
      else
      {
        char chachanonces[16];
        rt_util_getrandom((void*) chachanonces, 16);
        chacha20((uint8_t*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].p_hash, (uint8_t*)(*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]].p_hash, HASH_SIZE, (uint8_t*)key_chacha, (uint8_t*)chachanonces, 1);
      }
      //printf("[runtime] line %d\n",__LINE__ );


  //remove after time calc
      asm volatile ("rdcycle %0" : "=r" (time_read_end));
      //printf("[runtime] line %d\n",__LINE__ );

      uintptr_t time_read=time_read_end-time_read_beg;
      if( cc=='r')
      {
        if(real_pages_written<=BLOCKS_FOR_TIME_COUNTING)
          time_rblocks_process_w+=time_read;
        //printf("[runtime] line %d\n",__LINE__ );

      }
      else
      {
        if((pages_written-real_pages_written)<=BLOCKS_FOR_TIME_COUNTING)
          time_dblocks_process_w+=time_read;
        //printf("[runtime] line %d\n",__LINE__ );

      }

    }
  }
// for outside tree


  buc_i_md_ro.count=0;
  for(int k=0;k<Z+S_o;k++)
  {
    //printf("[runtime] line %d\n",__LINE__ );

    buc_i_md_ro.valids[k]='y';
    //printf("[runtime] line %d\n",__LINE__ );

  }
  //printf("[runtime] line %d\n",__LINE__ );

  tree_roram_md[buc_index]=buc_i_md_ro;
  //printf("[runtime] line %d\n",__LINE__ );

  uintptr_t _indexoftree = (uintptr_t)buc_index;


// for outside tree
  if(CACHING_LEVEL==0 || level>(CACHING_LEVEL-1))//TTC
  {
    unsigned long long time_read_beg=0,time_read_end=0;
    asm volatile ("rdcycle %0" : "=r" (time_read_beg));
    //printf("[runtime] line %d\n",__LINE__ );

    memcpy((void*)buff, (void*)&_indexoftree,sizeof(uintptr_t));
    //printf("[runtime] line %d\n",__LINE__ );

    memcpy((void*)(buff+sizeof(uintptr_t)), (void*)(buc_i_d_ro),sizeof(Bucket_roram));
    //printf("[runtime] line %d\n",__LINE__ );

    dispatch_edgecall_ocall(OCALL_RORAM_WRITE_BUCKET,(void*)buff, sizeof(uintptr_t)+ sizeof(Bucket_roram),NULL, 0,0);
    //printf("[runtime] line %d\n",__LINE__ );

    pages_written+=(Z+S_o);

    asm volatile ("rdcycle %0" : "=r" (time_read_end));
    //printf("[runtime] line %d\n",__LINE__ );

    time_block_copy_w=   ((time_read_end-time_read_beg)>>6);
// for outside tree
  }

  //TTC
  else
  {// simply copy the bucket into the internal tree
    for(int j=0;j<Z+S_o;j++)// preparing to write to external tree by encrypting and sha
    {
      //printf("[runtime] line %d\n",__LINE__ );

      (*buc_i_d_ro).blocks[buc_i_md_ro.ptrs[j]]= (*tmp_buc_d).blocks[j];
      //printf("[runtime] line %d\n",__LINE__ );

    }
    //printf("[roram]line%d index = %lu\n",__LINE__,_indexoftree);
    //printf("[runtime] line %d\n",__LINE__ );

    memcpy( (void*)(tree_roram_tree_top+_indexoftree),(void*)(buc_i_d_ro),sizeof(Bucket_roram)    );
    //printf("[runtime] line %d\n",__LINE__ );

  }




}
//------------------------------------------------------------------------------------
void read_bucket_roram_from_internal(int buc_index)
{
  int cz=0;
  for(int j=0;j<Z+S_o && cz<Z;j++)
  {
    if(buc_i_md_ro.valids[buc_i_md_ro.ptrs[j]]=='y'  && buc_i_md_ro.addr[j]!=DUMMY_BLOCK_ADDR)
    {
      uintptr_t params[2];
      params[0]=(uintptr_t)buc_index;
      params[1]=(uintptr_t)buc_i_md_ro.ptrs[j];
      //printf("[roram]line%d index = %lu offset = %lu\n",__LINE__,params[0],params[1]);
      memcpy( (void*)(&blk_i_d_ro)  ,(void*)&(tree_roram_tree_top[params[0]].blocks[params[1]]), sizeof(Block_roram)    );
      add_to_stash(vpn(buc_i_md_ro.addr[j]),blk_i_d_ro.data);
      // insert the check to update the bucket hashmap here. bucket_map[vpn(buc_i_md_ro.addr[j])]=-1;
      block_map[vpn(buc_i_md_ro.addr[j])]=-1;
      cz++;
    }
  }
/*
  for(int j=0;j<Z+S_o && cz<Z;j++)
  {
    if(buc_i_md_ro.valids[buc_i_md_ro.ptrs[j]]=='y'  && buc_i_md_ro.addr[j]==DUMMY_BLOCK_ADDR)
    {
      uintptr_t params[2];
      params[0]=(uintptr_t)buc_index;
      params[1]=(uintptr_t)buc_i_md_ro.ptrs[j];
      memcpy( (void*)(blk_i_d_ro)  ,(void*)&(tree_roram_tree_top[params[0]].blocks[params[1]]), sizeof(Block_roram)    );
      cz++;

    }
  }
*/


}
//------------------------------------------------------------------------------------
void early_reshuffle(int* pl)
{
   for(int i=0;i<=L;i++)
   {
     if(tree_roram_md[pl[i]].count>=S_o)
     {
       buc_i_md_ro= tree_roram_md[pl[i]];
       if(CACHING_LEVEL==0 || i>(CACHING_LEVEL-1))//TTC
       {
         read_bucket_roram(pl[i]);
       }
       else//TTC
       {
         read_bucket_roram_from_internal(pl[i]);
       }

       update_max_stash_occ();
       write_bucket_roram(pl[i],i);
       buc_i_md_ro.count=0;
       tree_roram_md[pl[i]].count=0;
     }
   }
}
//------------------------------------------------------------------------------------
void evict_path()
{
  int pl[50];
  //printf("[runtime] line %d\n",__LINE__ );

  int l= G%((int)pow(ARITY,L));
  //printf("[roram] evicting path %d\n",l );
  G=G+1;
  //printf("[runtime] line %d\n",__LINE__ );

  pxget(l,pl);
  //printf("[runtime] line %d\n",__LINE__ );

  for(int i=0;i<=L;i++)
  {
    //printf("[runtime] line %d\n",__LINE__ );

    buc_i_md_ro= tree_roram_md[pl[i]];
    //printf("[runtime] line %d\n",__LINE__ );

    if(CACHING_LEVEL==0 || i>(CACHING_LEVEL-1))//TTC
    {
      //printf("[runtime] line %d\n",__LINE__ );

      read_bucket_roram(pl[i]);
      //printf("[runtime] line %d\n",__LINE__ );

    }
    else//TTC
    {
      //printf("[runtime] line %d\n",__LINE__ );

      read_bucket_roram_from_internal(pl[i]);
      //printf("[runtime] line %d\n",__LINE__ );

    }

    //printf("[runtime] line %d\n",__LINE__ );

    update_max_stash_occ();
    //printf("[runtime] line %d\n",__LINE__ );

  }
  for(int i=L;i>=0;i--)
  {
    buc_i_md_ro= tree_roram_md[pl[i]];
    //printf("[runtime] line %d\n",__LINE__ );

    write_bucket_roram(pl[i],i);
    //printf("[runtime] line %d\n",__LINE__ );

    buc_i_md_ro.count=0;
    //printf("[runtime] line %d\n",__LINE__ );

    tree_roram_md[pl[i]]=buc_i_md_ro;
    //printf("[runtime] line %d\n",__LINE__ );

  }
  return;
}
//------------------------------------------------------------------------------------
uintptr_t get_stash_count()
{
  /*
  uintptr_t c=0;
  for(int i=0;i<STASH_SIZE_RORAM;i++)
  {
    if(S_roram[i].address!=DUMMY_BLOCK_ADDR)
      c++;
  }
  return c;
  */
  return (STASH_SIZE_RORAM-get_q_size2());
}

//------------------------------------------------------------------------------------
void access_roram(char op, int a, char *datastar, char *ret_pag,int extension)
{
  oram_acc++;
  //printf("[runtime] line %d\n",__LINE__ );

  if(oram_acc%100==0)
  {
    printf("[RO]or_ac= %lu MSO=%lu cur_So= %lu ",oram_acc,max_stash_occ,get_stash_count());
  }
  //printf("[runtime] line %d\n",__LINE__ );
  if(max_stash_occ>=STASH_SIZE_RORAM-200)
  {
    printf("[RORAM] STASH OVERFLOW WITH VALUE OF STASH %lu\n",max_stash_occ );
    sbi_exit_enclave(-1);
    while(get_stash_count()>600)
    {
      evict_path();
    }
  }
  //printf("[runtime] line %d\n",__LINE__ );
  if(firstimeaccess[a]=='y' || (exc==1 && op=='w'))
  {
    if(firstimeaccess[a]=='y')
    {
      position[a]=UniformRandom();
      firstimeaccess[a]='n';
    }
    //printf("[runtime] line %d\n",__LINE__ );
    add_to_stash(a,datastar);
    //printf("[runtime] line %d\n",__LINE__ );
  }
  uintptr_t l=position[a];
  //printf("[runtime] line %d\n",__LINE__ );
  position[a]= UniformRandom();
  //printf("[runtime] line %d\n",__LINE__ );


  //char retdata[RISCV_PAGE_SIZE];// uncomment for the copy optimization

  // comment for copy optimization
  char *retdata;
  if(ret_pag==NULL)
  {
    retdata=rd;
  }
  else
  {
    retdata=ret_pag;
  }


  int pl[50];
  //printf("[runtime] line %d\n",__LINE__ );
  pxget(l,pl);
  //printf("[runtime] line %d\n",__LINE__ );

  gdum='y';

  read_path(pl,a,(char*)retdata);//retdata
  //printf("[runtime] line %d\n",__LINE__ );

  update_max_stash_occ();
  //printf("[runtime] line %d\n",__LINE__ );

  if(gdum=='y')
  {
    search_in_stash(a,retdata);//retdata
    //printf("[runtime] line %d\n",__LINE__ );

  }
  if(op=='r')
  {
    //if(retdata!=ret_pag)

    //memcpy((void*)ret_pag,(void*)retdata,RISCV_PAGE_SIZE);//comment for copy optimization
    if(exc==0)
    {
      //printf("[runtime] line %d\n",__LINE__ );

      add_to_stash(a,retdata);//retdata
      //printf("[runtime] line %d\n",__LINE__ );

      update_max_stash_occ();
      //printf("[runtime] line %d\n",__LINE__ );

    }
  }
  if(op=='w')
  {
    //printf("[runtime] line %d\n",__LINE__ );

    memcpy((void*)retdata,(void*)datastar,RISCV_PAGE_SIZE);//retdata
    //printf("[runtime] line %d\n",__LINE__ );

    add_to_stash(a,retdata);//uncomment for exclusive //retdata
    //printf("[runtime] line %d\n",__LINE__ );

    update_max_stash_occ();
    //printf("[runtime] line %d\n",__LINE__ );

  }

  //add_to_stash(a,retdata);//uncommetn
  //update_max_stash_occ();//uncommetn

  round = (round +1 )%A;
  if(round==0)
  {
    //printf("[runtime] line %d\n",__LINE__ );

    evict_path();
    //printf("[runtime] line %d\n",__LINE__ );

  }
  //printf("[runtime] line %d\n",__LINE__ );

  early_reshuffle(pl);
  //printf("[runtime] line %d\n",__LINE__ );

}

//------------------------------------------------------------------------------------------------
void initialize_roram()
{

  N=RORAM_TREE_SIZE;
  Z=33;//33
  L=3;//3
  S_o=31;//31
  A=31;//31

/*
  Z=7;
  L=7;
  S_o=10;
  A=10;
*/

/*
  Z=2;
  L=7;
  S_o=2;
  A=2;
*/





  round=0;
  buc_i_d_ro=(Bucket_roram *)malloc(sizeof(Bucket_roram));
  tmp_buc_d=(Bucket_roram *)malloc(sizeof(Bucket_roram));

  rt_util_getrandom((void*) key, AES_KEYLEN);
  rt_util_getrandom((void*) key_hmac, AES_KEYLEN);
  rt_util_getrandom((void*) z1, AES_KEYLEN);
  rt_util_getrandom((void*) z2, AES_KEYLEN);
  printf("[RING_ORAM] INIT STARTED\r\n" );

  for(int i=0;i<MALLOC_SIZE;i++)
  {
    firstimeaccess[i]='y';
    version_numbers[i]=0;
    stash_loc[i]=-1;
    block_map[i]=-1;
  }
  //printf("[RING_ORAM] firstimeaccess and vn done\n" );

  buc_i_md_ro.count=0;
  for(int j=0;j<Z+S_o;j++)
  {
    (*buc_i_d_ro).blocks[j].address=0;
  }
  //printf("[RING_ORAM] buc_i_d_ro done\n" );

  for(int i=0;i<N;i++)// initializing the buckets for the outside enclave tree array
  {
    buc_i_md_ro.count=0;
    tree_roram_md[i]=buc_i_md_ro;
    for(int j=0;j<Z+S_o;j++)
    {
      (*buc_i_d_ro).blocks[j].address=DUMMY_BLOCK_ADDR;
      (*buc_i_d_ro).blocks[j].version=0;
      (*buc_i_d_ro).blocks[j].data[0]=0;
      buc_i_md_ro.ptrs[j]=j;
      buc_i_md_ro.valids[j]='y';
    }
    tree_roram_md[i]=buc_i_md_ro;

    if(i<RORAM_TREE_TOP_SIZE)
    {
      //printf("i = %d ",i);
      //memcpy( (void*)(tree_roram_tree_top+i),(void*)(buc_i_d_ro),sizeof(Bucket_roram)    );// uncommetn after checking
    }

    //roram_writebucket(i);// uncommetn after checking

    //printf("[RORAM] DOING INIT FOR NODE %d\n",i);

  }

  front=rear=-1;
  for(int i=0;i<STASH_SIZE_RORAM;i++)
  {
    if(enque2((uintptr_t)i)!=ENQUE_SUCCESS)
    {
      printf("failed for %d\n",i );
    }
  }

//  printf("front = %d rear = %d\n",front,rear);
/*
  for(int i=0;i<STASH_SIZE_RORAM;i++){
    if(!( free_indices[i]>=0 && free_indices[i] < STASH_SIZE_RORAM ))
    {
      printf("at line 648 %d %d ",i,free_indices[i]);
    }
  }
*/
  //printf("[ringoram] que size = %lu\n",get_q_size2());

  printf("[RING_ORAM] INIT DONE\r\n" );
  //sbi_exit_enclave(-1);

}
