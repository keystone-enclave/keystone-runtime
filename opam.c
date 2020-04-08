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
#include "opam.h"
//------------------------------DEFINING REQURIED GLOBAL VARIABLES---------------------------
Block_Opam_md *S_opam_md;
//Block_Opam_md Sg_opam_md[STASH_SIZE];
int S_opam_md_len=0;
//int Sg_opam_md_len=0;
int treearray_opam_md_len=0;
//char buff[BACKUP_BUFFER_SIZE];
Bucket_opam_md buc_i_md;


int treearray_opam_len;

Bucket_opam buc_i_d;


void print_page(char *a)
{
  //printf("[ORAM] STASH CONTENTS\n" );

  for(int i=0;i<32;i++)
  {
    printf("0x%lx ",a[i] );
  }
  printf("\n" );
}

//---------------------------------------FUNCTIONS BEGIN-----------------------------------------
void opam_readbucket_d(int indexoftree,char *ret_buf)
{
  edge_data_t retdata;
  uintptr_t _indexoftree=(uintptr_t)indexoftree;
  dispatch_edgecall_ocall(OCALL_OPAM_READ_BUCKETS_D, &_indexoftree, sizeof(_indexoftree), &retdata, sizeof(edge_data_t),0);
  //uncomment if fails
  //handle_copy_from_shared((void*)ret_buf,retdata.offset,retdata.size);

  handle_copy_from_shared((void*)&buc_i_d,retdata.offset,retdata.size);


  //printf("ret_buf = 0x%lx &buc_i_d=0x%lx buc_i_d.data=0x%lx   retdata.size = %lu\n",ret_buf,(uintptr_t)(&buc_i_d),(uintptr_t)buc_i_d.blocks[0].data,retdata.size);

  char hash_calc[HASH_SIZE];
  sha3_ctx_t sha3;
  sha3_init(&sha3, HASH_SIZE);
  char c[16];
  xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
  sha3_update(&sha3, (void*)c, AES_KEYLEN);
  sha3_update(&sha3, (void*)buc_i_d.blocks[0].data, RISCV_PAGE_SIZE);
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

  //printf("[OPAM] Read contents for address 0x%lx(ind = %lu ) :\n",buc_i_md.blocks[0].address,indexoftree);
  //print_page(buc_i_d.blocks[0].data);


/*
  handle_copy_from_shared((void*)ret_buf,retdata.offset,retdata.size);

  char hash_calc[HASH_SIZE];
  sha3_ctx_t sha3;
  sha3_init(&sha3, HASH_SIZE);
  char c[16];
  xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
  sha3_update(&sha3, (void*)c, AES_KEYLEN);
  sha3_update(&sha3, (void*)ret_buf, RISCV_PAGE_SIZE);
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
*/






  if(!check_hashes(  (void*)hash_calc2  ,HASH_SIZE,  (void*)buc_i_md.blocks[0].p_hash_d ,HASH_SIZE  ))
  {
    printf("[runtime] Page corrupted. HMAC integrity check failed(data).  Fatal error\n");
    sbi_exit_enclave(-1);
  }

  if(confidentiality)
  {
    decrypt_page((uint8_t *) (buc_i_d.blocks[0].data),RISCV_PAGE_SIZE,key,(uint8_t *)buc_i_md.blocks[0].ivd);//
    //decrypt_page((uint8_t *) (ret_buf),RISCV_PAGE_SIZE,key,(uint8_t *)buc_i_md.blocks[0].ivd);//comment if fails
  }
  pages_read+=Z;
  real_pages_read+=Z;
}

//-------------------------------------------------------------------------------------------

void opam_readbucket_md(int indexoftree)
{
    edge_data_t retdata;
    uintptr_t _indexoftree=(uintptr_t)indexoftree;
    dispatch_edgecall_ocall(OCALL_OPAM_READ_BUCKETS_MD, &_indexoftree, sizeof(_indexoftree), &retdata, sizeof(edge_data_t),0);
    handle_copy_from_shared((void*)&buc_i_md,retdata.offset,retdata.size);

    char hash_calc[HASH_SIZE];
    sha3_ctx_t sha3;
    sha3_init(&sha3, HASH_SIZE);
    char c[16];
    xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
    sha3_update(&sha3, (void*)c, AES_KEYLEN);
    sha3_update(&sha3, (void*)&(buc_i_md.blocks[0].address), sizeof(uintptr_t)*2);
    sha3_update(&sha3, (void*)buc_i_md.blocks[0].iv, AES_KEYLEN);
    sha3_update(&sha3, (void*)buc_i_md.blocks[0].ivd, AES_KEYLEN);
    sha3_final((void*)hash_calc, &sha3);
    char c2[16];
    xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
    char hash_calc2[HASH_SIZE];
    sha3_ctx_t sha32;
    sha3_init(&sha32, HASH_SIZE);
    sha3_update(&sha32, (void*)c2, AES_KEYLEN);
    sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
    sha3_final((void*)hash_calc2, &sha32);
    if(!check_hashes(  (void*)hash_calc2  ,HASH_SIZE,  (void*)buc_i_md.blocks[0].p_hash ,HASH_SIZE  )      )
    {
      printf("[runtime] Page corrupted. HMAC integrity check failed(metadata).  Fatal error\n");
      sbi_exit_enclave(-1);
    }
    //----------------------------------------------------------------------
    decrypt_page((uint8_t *) &(buc_i_md.blocks[0].address),sizeof(uintptr_t)*2,key,(uint8_t *)buc_i_md.blocks[0].iv);

    if( buc_i_md.blocks[0].address!=DUMMY_BLOCK_ADDR)// check only for valid blocks and not for dummy blocks
    {
      //real_pages_read++;
      if(version_numbers[vpn(buc_i_md.blocks[0].address)] !=  buc_i_md.blocks[0].version)
      {
        printf("[runtime] Page corrupted(Possibly a replay attack).  Fatal error\n");
        //sbi_exit_enclave(-1);
      }
    }
}

//-----------------------------------------------------------------------------------

void opam_write_bucket_md(int indexoftree)
{
  uintptr_t _indexoftree=(uintptr_t)indexoftree;
  rt_util_getrandom((void*) buc_i_md.blocks[0].iv, AES_KEYLEN);
  if(buc_i_md.blocks[0].address!=DUMMY_BLOCK_ADDR )// not a dummy block
  {
    version_numbers[   vpn(buc_i_md.blocks[0].address)]++;
    buc_i_md.blocks[0].version=version_numbers[   vpn(buc_i_md.blocks[0].address)];
  }

  encrypt_page(  (uint8_t *) &(buc_i_md.blocks[0].address),sizeof(uintptr_t)*2,key,(uint8_t *)buc_i_md.blocks[0].iv);
  //-----------------------------calculating HMAC-----------------------------------------

  char hash_calc[HASH_SIZE];
  sha3_ctx_t sha3;
  sha3_init(&sha3, HASH_SIZE);
  char c[16];
  xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
  sha3_update(&sha3, (void*)c, AES_KEYLEN);
  sha3_update(&sha3, (void*)&(buc_i_md.blocks[0].address), sizeof(uintptr_t)*2);
  sha3_update(&sha3, (void*)buc_i_md.blocks[0].iv, AES_KEYLEN);
  sha3_update(&sha3, (void*)buc_i_md.blocks[0].ivd, AES_KEYLEN);
  sha3_final((void*)hash_calc, &sha3);
  char c2[16];
  xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
  sha3_ctx_t sha32;
  sha3_init(&sha32, HASH_SIZE);
  sha3_update(&sha32, (void*)c2, AES_KEYLEN);
  sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
  sha3_final((void*)buc_i_md.blocks[0].p_hash, &sha32);

 //----------------------------------------------------------------------

  memcpy((void*)buff, (void*)&_indexoftree,sizeof(uintptr_t));
  memcpy((void*)(buff+sizeof(uintptr_t)), (void*)&buc_i_md,sizeof(Bucket_opam_md));
  dispatch_edgecall_ocall(OCALL_OPAM_WRITE_BUCKETS_MD,(void*)buff, sizeof(uintptr_t)+ sizeof(Bucket_opam_md),NULL, 0,0);
}
//------------------------------------------------------------------------------------
void opam_write_bucket_d(int indexoftree)// change
{
  uintptr_t _indexoftree=(uintptr_t)indexoftree;
  memcpy((void*)buff, (void*)&_indexoftree,sizeof(uintptr_t));
  memcpy((void*)(buff+sizeof(uintptr_t)), (void*)&buc_i_d,sizeof(Bucket_opam));
  dispatch_edgecall_ocall(OCALL_OPAM_WRITE_BUCKETS_D,(void*)buff, sizeof(uintptr_t)+ sizeof(Bucket_opam),NULL, 0,0);
  pages_written+=Z;
  real_pages_written+=Z;
}
//------------------------------------------------------------------------------------
void opam_writebucket(int indexoftree)
{
  uintptr_t _indexoftree=(uintptr_t)indexoftree;
  rt_util_getrandom((void*) buc_i_md.blocks[0].iv, AES_KEYLEN);

  // rt_util_getrandom((void*) buc_i_md.blocks[0].ivd, AES_KEYLEN);// uncommetn this

  buc_i_md.blocks[0].tree_index=_indexoftree;
  if(buc_i_md.blocks[0].address!=DUMMY_BLOCK_ADDR )// not a dummy block
  {
    version_numbers[   vpn(buc_i_md.blocks[0].address)]++;
    buc_i_md.blocks[0].version=version_numbers[   vpn(buc_i_md.blocks[0].address)];
  }
  encrypt_page((uint8_t *)&(buc_i_md.blocks[0].address),sizeof(uintptr_t)*2,key,(uint8_t *)buc_i_md.blocks[0].iv);

  //-----------------------------calculating HMAC-----------------------------------------
  char hash_calc[HASH_SIZE];
  sha3_ctx_t sha3;
  sha3_init(&sha3, HASH_SIZE);
  char c[16];
  xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
  sha3_update(&sha3, (void*)c, AES_KEYLEN);
  sha3_update(&sha3, (void*)&(buc_i_md.blocks[0].address), sizeof(uintptr_t)*2);
  sha3_update(&sha3, (void*)buc_i_md.blocks[0].iv, AES_KEYLEN);
  sha3_update(&sha3, (void*)buc_i_md.blocks[0].ivd, AES_KEYLEN);
  sha3_final((void*)hash_calc, &sha3);
  char c2[16];
  xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
  sha3_ctx_t sha32;
  sha3_init(&sha32, HASH_SIZE);
  sha3_update(&sha32, (void*)c2, AES_KEYLEN);
  sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
  sha3_final((void*)buc_i_md.blocks[0].p_hash, &sha32);

  //rt_util_getrandom((void*) buc_i_d.blocks[0].data, RISCV_PAGE_SIZE);// uncomment this

  memcpy((void*)buff, (void*)&_indexoftree,sizeof(uintptr_t));
  memcpy((void*)(buff+sizeof(uintptr_t)), (void*)&buc_i_md,sizeof(Bucket_opam_md));

  //memcpy((void*)(buff+sizeof(uintptr_t)+sizeof(Bucket_opam_md)), (void*)&buc_i_d,sizeof(Bucket_opam));// uncomment this

  //dispatch_edgecall_ocall(OCALL_OPAM_WRITE_BUCKETS,(void*)buff, sizeof(uintptr_t)+ sizeof(Bucket_opam_md)+sizeof(Bucket_opam),NULL, 0,0);// uncomment this
  dispatch_edgecall_ocall(OCALL_OPAM_WRITE_BUCKETS,(void*)buff, sizeof(uintptr_t)+ sizeof(Bucket_opam_md),NULL, 0,0);// comment this

  //pages_written+=Z;// uncommetn this
}

void print_stash()
{
  printf("[ORAM] STASH CONTENTS\n" );
  for(int i=0;i<S_opam_md_len;i++)
  {
    printf("0x%lx ",S_opam_md[i].address );
  }
  printf("\n" );
}
//-----------------------------------------------------------------------------------

int access_opam(char op, int a, char *datastar, char *ret_buf,int extension)
{
  S_opam_md_len=0;
  uintptr_t failed_count=0;
  if(extension==1 || firstimeaccess[a]=='y')
  {
    position[a]=UniformRandom();
  }

  unsigned int x= position[a];
  int px[50]={0,};
  int px_len=0;px_len=px_len;
  if(op=='r')
  {
    position[a]= UniformRandom();//flr:
    if(op=='w')
    {
      x= position[a];
    }
  }

  pxget(x, px);
  uintptr_t aaa=a<<RISCV_PAGE_BITS;

  if(debug && 0)
  {
    printf("[runtime] OPAM.0x%lx Trace for address 0x%lx(%c) extension = %d : Zk= %d ",aaa,a<<RISCV_PAGE_BITS ,op,extension,Z);
    for(int i=L;i>=0;i--)
      printf("%d ",px[i]);
    printf("\n" );
  }

  int dmp=0;// dummy block present flag. we are only reading one dummy block and the rest valid blocks
  S_opam_md_len=0;
  for(int l=L;l>=0;l--)//filling the stash('S')
  {
    opam_readbucket_md(px[l]);
    for(int j=0;j<Z;j++)//reading the blocks from lth read bucket from px[l]th index/bucket
    {
        if(buc_i_md.blocks[j].address!=0  )
          S_opam_md[S_opam_md_len++]= buc_i_md.blocks[j];
    }
  }

  if(op=='w')
  {
    for(int l=0;l<=L;l++)//finding empty slot
    {
      opam_readbucket_md(px[l]);
      for(int j=0;j<Z;j++)//reading the blocks from lth read bucket from px[l]th index/bucket
      {
          if(buc_i_md.blocks[j].address==DUMMY_BLOCK_ADDR  )
          {
            S_opam_md[S_opam_md_len++]= buc_i_md.blocks[j];
            dmp=1;
            goto outside;
          }
      }
     }
  }

outside:if(op=='w' && dmp==0)
  {
    failed_count++;
    //printf("[OPAM] FAILED FOR ADDRESS 0x%lx\n",a<<RISCV_PAGE_BITS );
    //print_stash();
    //goto flr;
    return 0;
  }

  int datapos=-1;
  for(int j=0;j< S_opam_md_len;j++)
  {
      if( (S_opam_md[j].address==  (a<<RISCV_PAGE_BITS) ) ||  (  (firstimeaccess[a]=='y' || op=='w')  && S_opam_md[j].address==DUMMY_BLOCK_ADDR ) )//datapos will store the position where the required block('a')
      // is present OR a position where a first time read block can be placed by replacing a dummy block
      {
          if(ret_buf!=NULL)
          {
            buc_i_md.blocks[0]=S_opam_md[j];
            opam_readbucket_d(S_opam_md[j].tree_index,ret_buf);

            unsigned long long cycles1,cycles2;
            asm volatile ("rdcycle %0" : "=r" (cycles1));

            memcpy((void*)ret_buf,(void*)buc_i_d.blocks[0].data,BLOCK_SIZE);   //uncomment if fails

            asm volatile ("rdcycle %0" : "=r" (cycles2));
            copy_waste+=(cycles2-cycles1);




            S_opam_md[j].address=0;
            buc_i_md.blocks[0]=S_opam_md[j];
            //printf("[OPAM] CALLING WRITE BUCKET DURING DELETION OF READ BUCKET addr = 0x%lx\n",a<<RISCV_PAGE_BITS );
            opam_write_bucket_md(S_opam_md[j].tree_index);
            goto p1;
          }
          datapos=j;
          S_opam_md[j].address=  (a<<RISCV_PAGE_BITS);
p1:       firstimeaccess[a]='n';
          break;
      }
  }

  int write_pos=-1;

  for(int l=L;l>=0;l--)
  {
    int Sbar_len=0;
    for(int i=0;i<S_opam_md_len && Sbar_len<Z ;i++)
    {
      int abar= (S_opam_md[i].address)>> RISCV_PAGE_BITS;
      if(S_opam_md[i].address!=DUMMY_BLOCK_ADDR)
      {
        int ppositionabar[ARRAY_SIZE];
        pxget(position[abar],ppositionabar);
        if (px[l] == ppositionabar[l])
        {
          buc_i_md.blocks[Sbar_len] = S_opam_md[i];
          if(S_opam_md[i].address== (a<<RISCV_PAGE_BITS) && op=='w')
          {
              rt_util_getrandom((void*) buc_i_md.blocks[Sbar_len].iv, AES_KEYLEN);
              memcpy((void*)S_opam_md[i].iv,(void*)buc_i_md.blocks[Sbar_len].iv, AES_KEYLEN );
              write_pos=px[l];
          }
          S_opam_md[i].address=DUMMY_BLOCK_ADDR;
          Sbar_len++;
        }
      }
    }
    Sbar_len = Z<=Sbar_len ? Z:Sbar_len;
    int noofdummyblocks = Z - Sbar_len;

    for(int db=0;db <noofdummyblocks;db++)
    {
      buc_i_md.blocks[Sbar_len].address=DUMMY_BLOCK_ADDR;
      buc_i_md.blocks[Sbar_len].tree_index= px[l];
      rt_util_getrandom((void*) buc_i_md.blocks[Sbar_len].iv, AES_KEYLEN);
      Sbar_len++;
    }
    //printf("[OPAM] CALLING WRITE BUCKET DURING shuffling \n" );
    opam_write_bucket_md(px[l]);
  }

  if(op=='w' && write_pos!=-1)
  {
      buc_i_md.blocks[0] =  S_opam_md[datapos];

      unsigned long long cycles1,cycles2;
      asm volatile ("rdcycle %0" : "=r" (cycles1));

      memcpy((void*)buc_i_d.blocks[0].data,(void*)datastar,BLOCK_SIZE);
      asm volatile ("rdcycle %0" : "=r" (cycles2));
      copy_waste+=(cycles2-cycles1);

      buc_i_md.blocks[0].address=a<<RISCV_PAGE_BITS;
      buc_i_md.blocks[0].tree_index=write_pos;
      rt_util_getrandom((void*) buc_i_md.blocks[0].ivd, AES_KEYLEN);

      if(confidentiality)
      {
        encrypt_page((uint8_t *)(buc_i_d.blocks[0].data),RISCV_PAGE_SIZE,key,(uint8_t *)buc_i_md.blocks[0].ivd);//UC
      }
      //-----------------------------calculating HMAC-----------------------------------------
      char hash_calc[HASH_SIZE];
      sha3_ctx_t sha3;
      sha3_init(&sha3, HASH_SIZE);
      char c[16];
      xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
      sha3_update(&sha3, (void*)c, AES_KEYLEN);
      sha3_update(&sha3, (void*)buc_i_d.blocks[0].data, RISCV_PAGE_SIZE);
      sha3_final((void*)hash_calc, &sha3);
      char c2[16];
      xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
      sha3_ctx_t sha32;
      sha3_init(&sha32, HASH_SIZE);
      sha3_update(&sha32, (void*)c2, AES_KEYLEN);
      sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
      sha3_final((void*)buc_i_md.blocks[0].p_hash_d, &sha32);

      opam_write_bucket_md(write_pos);
      opam_write_bucket_d(write_pos);

      if(failed_count>0)
      {
        //printf("[OPAM] ADDRESS 0x%lx failed %lu times but then succeded atlast\n", buc_i_md.blocks[0].address,failed_count);
      }
      S_opam_md[datapos].address=0;

  }

  oram_acc++;
  if(oram_acc%500==0)
  {
    printf("[OPAM]oram_acc= %lu ",oram_acc );
  }

  return 1;
}
//-----------------------------------------------------------------------------------

void initialize_opam()
{
  N=OPAM_TREE_SIZE;//till now 1<<14 is fine
  Z=1;
  L=17;
  rt_util_getrandom((void*) key, AES_KEYLEN);
  rt_util_getrandom((void*) key_hmac, AES_KEYLEN);
  rt_util_getrandom((void*) z1, AES_KEYLEN);
  rt_util_getrandom((void*) z2, AES_KEYLEN);
  printf("[OPAM] Initializtion started\r\n" );
  for(int i=0;i<MALLOC_SIZE;i++)
  {
    firstimeaccess[i]='y';
    version_numbers[i]=0;
    //position[i]=UniformRandom();
  }

  for(int j=0;j<Z;j++)
  {
    buc_i_md.blocks[j].address=DUMMY_BLOCK_ADDR;
    buc_i_md.blocks[j].version=0;
  }

  for(int i=0;i<N;i++)// initializing the buckets for the outside enclave tree array
  {
    for(int j=0;j<Z;j++)
    {
      buc_i_md.blocks[j].address=DUMMY_BLOCK_ADDR;
      buc_i_md.blocks[j].version=0;
      buc_i_md.blocks[j].tree_index=i;
      buc_i_d.blocks[j].data[0]=0;
    }
    opam_writebucket(i);
  }
  printf("[OPAM] init done\r\n" );

}
//-----------------------------------------------------------------------------------
void remap_all()
{

  for(uintptr_t i=q_front;1==1;i=(i+1)%MALLOC_SIZE2)
  {
    position[ vpn(replacement_algo_queue_map[i])      ]=UniformRandom();
    if(i==q_rear)
    {
      return;
    }
  }
}
