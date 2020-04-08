#include "mm.h"
#include "rt_util.h"
#include "printf.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_call.h"
#include "aess.h"
#include "ssha3.h"
#include "oram.h"
#include "freemem.h"
#include "vm.h"
#include "page_replacement.h"
#include "index_q.h"

//------------------------------DEFINING REQURIED GLOBAL VARIABLES----------------------------------
//Block S[STASH_SIZE];
//Block Sg[STASH_SIZE];
Block *S;
Block *Sg;

int S_len=0;
int Sg_len=0;
int treearray_len=0;
Bucket buc_i;


Bucket_md buc_i_po_md;
Bucket_md *tree_po_md;

//char buff[BACKUP_BUFFER_SIZE];
//char buff[BACKUP_BUFFER_SIZE];
//--------------------------------------FUNCTIONS BEGIN----------------------------------------------
//-----------------------------------------------------------------------------------
void readbucket(int indexoftree)
{
   edge_data_t retdata;
   uintptr_t _indexoftree=(uintptr_t)indexoftree;
   dispatch_edgecall_ocall(OCALL_READ_BUCKETS, &_indexoftree, sizeof(_indexoftree), &retdata, sizeof(edge_data_t),0);
   handle_copy_from_shared((void*)&buc_i,retdata.offset,retdata.size);
   buc_i_po_md= tree_po_md[_indexoftree];
   pages_read+=Z;
   //((char*)(&buc_i))[0]++;// used to tamper a read block to check authenctication functionality
   for(int i=0;i<Z;i++)
   {
     //-----------------------------calculating HMAC-----------------------------------------
     //if(!tracing)
     if(  buc_i_po_md.blocks[i].address!=DUMMY_BLOCK_ADDR)
     {
      char hash_calc[HASH_SIZE];
      sha3_ctx_t sha3;
      sha3_init(&sha3, HASH_SIZE);
      char c[16];
      xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
      sha3_update(&sha3, (void*)c, AES_KEYLEN);
      sha3_update(&sha3, (void*)&(buc_i.blocks[i].address), sizeof(uintptr_t)*2);
      sha3_update(&sha3, (void*)buc_i.blocks[i].data, RISCV_PAGE_SIZE);
      sha3_update(&sha3, (void*)buc_i.blocks[i].iv, AES_KEYLEN);
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
      if(  buc_i_po_md.blocks[i].address!=DUMMY_BLOCK_ADDR &&  !check_hashes(  (void*)hash_calc2  ,HASH_SIZE,  (void*)buc_i.blocks[i].p_hash ,HASH_SIZE  )      )
      {
        printf("[runtime] Page corrupted. HMAC integrity check failed.  Fatal error\n");
        sbi_exit_enclave(-1);
      }
     }

      //----------------------------------------------------------------------
      if(tree_po_md[indexoftree].blocks[i].address!=DUMMY_BLOCK_ADDR)
        decrypt_page((uint8_t *) &(buc_i.blocks[i].address),sizeof(uintptr_t)*2,key,(uint8_t *)buc_i.blocks[i].iv);

      //if(buc_i.blocks[i].address!=DUMMY_BLOCK_ADDR)
      if(tree_po_md[indexoftree].blocks[i].address!=DUMMY_BLOCK_ADDR)
      {
        if(confidentiality)
        {
          decrypt_page((uint8_t *) buc_i.blocks[i].data,RISCV_PAGE_SIZE,key,(uint8_t *)buc_i.blocks[i].iv);
        }
      }


      //check version number
      //if( buc_i.blocks[i].address!=DUMMY_BLOCK_ADDR)// check only for valid blocks and not for dummy blocks
      if(tree_po_md[indexoftree].blocks[i].address!=DUMMY_BLOCK_ADDR)
      {
        real_pages_read++;
        if(version_numbers[vpn(buc_i.blocks[i].address)] !=  buc_i.blocks[i].version)
        {
          printf("[runtime] Page corrupted(Possibly a replay attack).  Fatal error\n");
          sbi_exit_enclave(-1);
        }
      }

   }
   //printf(".");
   //printf("%d ",__LINE__);


}
//-----------------------------------------------------------------------------------
void writebucket(int indexoftree)
{

    //printf("[runtime] start write bucket for \n" );

    uintptr_t _indexoftree=(uintptr_t)indexoftree;
    pages_written+=Z;

    for(int i=0;i<Z;i++)
    {
       rt_util_getrandom((void*) buc_i.blocks[i].iv, AES_KEYLEN);
       //update the version number of a valid block
       //if(!tracing)

       if(buc_i.blocks[i].address!=DUMMY_BLOCK_ADDR )// not a dummy block
       {
         real_pages_written++;
         version_numbers[   vpn(buc_i.blocks[i].address)]++;
         buc_i.blocks[i].version=version_numbers[   vpn(buc_i.blocks[i].address)];
       }

       if(buc_i.blocks[i].address!=DUMMY_BLOCK_ADDR)
       {
         if(confidentiality)
         {
           encrypt_page(    (uint8_t *) buc_i.blocks[i].data,RISCV_PAGE_SIZE,key,(uint8_t *)buc_i.blocks[i].iv);
         }
       }
       else
       {
         if(confidentiality)
         {
           //rt_util_getrandom((void*) buc_i.blocks[i].data, RISCV_PAGE_SIZE);
           fill_page_with_zeroes((char*)buc_i.blocks[i].data);
         }
       }
       encrypt_page(  (uint8_t *) &(buc_i.blocks[i].address),sizeof(uintptr_t)*2,key,(uint8_t *)buc_i.blocks[i].iv);

       //-----------------------------calculating HMAC-----------------------------------------

       char hash_calc[HASH_SIZE];
       sha3_ctx_t sha3;
       sha3_init(&sha3, HASH_SIZE);
       char c[16];
       xor_op((char*)key_hmac,(char*)z2,c,AES_KEYLEN);
       sha3_update(&sha3, (void*)c, AES_KEYLEN);
       sha3_update(&sha3, (void*)&(buc_i.blocks[i].address), sizeof(uintptr_t)*2);
       sha3_update(&sha3, (void*)buc_i.blocks[i].data, RISCV_PAGE_SIZE);
       sha3_update(&sha3, (void*)buc_i.blocks[i].iv, AES_KEYLEN);
       //add sha3 for indexoftree
       sha3_final((void*)hash_calc, &sha3);
       char c2[16];
       xor_op((char*)key_hmac,(char*)z1,c2,AES_KEYLEN);
       sha3_ctx_t sha32;
       sha3_init(&sha32, HASH_SIZE);
       sha3_update(&sha32, (void*)c2, AES_KEYLEN);
       sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
       sha3_final((void*)buc_i.blocks[i].p_hash, &sha32);


      //----------------------------------------------------------------------
    }
    //printf("[runtime] end of loop " );
    memcpy((void*)buff, (void*)&_indexoftree,sizeof(uintptr_t));
    memcpy((void*)(buff+sizeof(uintptr_t)), (void*)&buc_i,sizeof(Bucket));
    unsigned long ss=9;ss=ss;
    dispatch_edgecall_ocall(OCALL_WRITE_BUCKETS,(void*)buff, sizeof(uintptr_t)+sizeof(Bucket),NULL, 0,0);

    tree_po_md[_indexoftree]=buc_i_po_md;//extra


    //printf("[runtime] end write bucket for " );
    return;
}
//-----------------------------------------------------------------------------------
int Contains(unsigned int Stemp[ARRAY_SIZE], int Stemp_len, uintptr_t address)
{
    if (Stemp==NULL || Stemp_len==0)
    {
        return 0;
    }
    for(int i=0;i< Stemp_len;i++)
    {
        if(address== Stemp[i])
            return 1;
    }
    return 0;
}
//-----------------------------------------------------------------------------------
void access(char op, int a, char *datastar, char *ret_buf,int extension)
{
    S_len=0;

    //search in stash
    assert(a>=1 && a < MALLOC_SIZE);
    int i= stash_loc[a];
    //
    if(i!=-1)
    {
      assert((uintptr_t)i>=0 && (uintptr_t)i < ORAM_STASH_SIZE);
      if(ret_buf!=NULL)
      {
          memcpy((void*)ret_buf, (void*)(S[i].data),BLOCK_SIZE);
          //add the condition for exclusivity here


          if(exc==1)
          {
            stash_loc[vpn(S[i].address)]=-1;

            if(enque2((uintptr_t)i)!=ENQUE_SUCCESS)
            {
              printf("[path oram] free index insertion failed\n");
            }

            S[i].address=DUMMY_BLOCK_ADDR;
          }


      }
      if(op=='w')
      {
          memcpy(S[i].data,datastar,BLOCK_SIZE);
          S[i].address=a<<RISCV_PAGE_BITS;
      }
      return;
    }

    if(oram_acc%500==0)
    {
      printf("or_ac= %lu MSO=%lu pf_count = %d ",oram_acc,max_stash_occ,countpf );
    }

    if(firstimeaccess[a]=='y')
    {
      position[a]=UniformRandom();
    }
    //printf("%d ",__LINE__);

    unsigned int x= position[a];
    int px[50]={0,};
    int px_len=0;px_len=px_len;
    //if(firstimeaccess[a]=='n')//comment it
    position[a]= UniformRandom();
    pxget(x, px);

    if(debug)
    {
      printf("[runtime] ORAM Trace for address 0x%lx(%c) extension = %d : Zk= %d ",a<<RISCV_PAGE_BITS ,op,extension,Z);
      for(int i=L;i>=0;i--)
        printf("%d ",px[i]);
      printf("\n" );
    }

    //int dmp=0;// dummy block present flag. we are only reading one dummy block an the rest valid blocks
    for(int l=0;l<=L;l++)//filling the stash('S')
    {
        readbucket(px[l]);
        //printf("%d ",__LINE__);
        //printf("[ORAM]readbucket done for l=%d\n",l );
        for(int j=0;j<Z;j++)//reading the blocks from lth read bucket from px[l]th index/bucket
        {
            //if(buc_i.blocks[j].address!=DUMMY_BLOCK_ADDR  )
            if(buc_i_po_md.blocks[j].address!=DUMMY_BLOCK_ADDR)
            {
              //S[S_len++]= buc_i.blocks[j];//add to stash and update S_len for sum_stash and delete i from free list
              int i= (int)deque2();i=i;
              assert(i>=0 && i < ORAM_STASH_SIZE);
              S[i]= buc_i.blocks[j];
              stash_loc[vpn(buc_i.blocks[j].address)]=i;


              //printf("%d ",__LINE__);
            }

        }
        //printf("%d ",__LINE__);
    }


    //printf("[ORAM]complete reading done\n");
    int datapos=-1;

    //search in stash
    i= stash_loc[a];
    datapos=i;
    firstimeaccess[a]='n';

    if(i!=-1)
    {
      assert((uintptr_t)i>=0 && (uintptr_t)i < ORAM_STASH_SIZE);
      if(ret_buf!=NULL)
      {
          memcpy((void*)ret_buf, (void*)(S[i].data),BLOCK_SIZE);
          //add the condition for exclusivity here


          if(exc==1)
          {
            stash_loc[vpn(S[i].address)]=-1;

            if(enque2((uintptr_t)i)!=ENQUE_SUCCESS)
            {
              printf("[path oram] free index insertion failed\n");
            }

            S[i].address=DUMMY_BLOCK_ADDR;
          }

      }
    }



    if(op=='w')
    {
        //printf("[runtime] before writing\n" );
        datapos=stash_loc[a];
        if(datapos==-1)
        {
          int i= (int)deque2();i=i;
          assert(i>=0 && i < ORAM_STASH_SIZE);
          stash_loc[a]=i;
          datapos=i;


        }

        memcpy(S[datapos].data,datastar,BLOCK_SIZE);
        S[datapos].address=a<<RISCV_PAGE_BITS;
        //printf("[runtime] after writing\n" );

    }

    uintptr_t qs=get_q_size2();
    uintptr_t c=ORAM_STASH_SIZE-qs;
    //unsigned int Stemp[ARRAY_SIZE];
    int Stemp_len=0;Stemp_len=Stemp_len;
    for(int l=L;l>=0;l--)
    {
        //Block Sbar[80];Sbar[0].address=0;Sbar[0].address++;// its not required but still kept else system is crashing
        int Sbar_len=0;
        uintptr_t real_blocks_scanned=0;

        uintptr_t qs_cur=get_q_size2();
        uintptr_t real_left_in_stash=ORAM_STASH_SIZE-qs_cur;
        for(int i=0;i<ORAM_STASH_SIZE && Sbar_len<Z && real_blocks_scanned < real_left_in_stash;i++)// move upto stash max len
        {
            //Block b= S[i];
            int abar= (S[i].address)>> RISCV_PAGE_BITS;
            if(S[i].address!=DUMMY_BLOCK_ADDR)
            {
                real_blocks_scanned++;
                int ppositionabar[50];
                pxget(position[abar],ppositionabar);
                if (px[l] == ppositionabar[l] /*&& !Contains(Stemp,Stemp_len, S[i].address)*/  ) {
					        buc_i.blocks[Sbar_len] = S[i];// delete the stash_loc after this and also free i

                  buc_i_po_md.blocks[Sbar_len++].address = S[i].address;

                  stash_loc[vpn(S[i].address)]=-1;

                  if(enque2((uintptr_t)i)!=ENQUE_SUCCESS)
                  {
                    printf("[path oram] free index insertion failed\n");
                  }

                  S[i].address=DUMMY_BLOCK_ADDR;

				        }
            }
         }
         //printf("[runtime] after bucket fill for l=%d\n",l );

        Sbar_len = Z<=Sbar_len ? Z:Sbar_len;

        int noofdummyblocks = Z - Sbar_len;
        for(int db=0;db <noofdummyblocks;db++)
        {
            buc_i.blocks[Sbar_len].address=DUMMY_BLOCK_ADDR;
            buc_i_po_md.blocks[Sbar_len].address=DUMMY_BLOCK_ADDR;
            //memset(buc_i.blocks[Sbar_len].data,0,BLOCK_SIZE);
            Sbar_len++;
        }
        //printf("[runtime] befre write bucket for l=%d\n",l );
        writebucket(px[l]);
        //printf("[runtime] after write bucket for l=%d\n",l );
    }



    if(c>max_stash_occ)
      max_stash_occ=c;

    sum_stash_occ = sum_stash_occ+c;
    oram_acc = oram_acc+1;
}
//-----------------------------------------------------------------------------------
void initalize_oram()
{
  N=ORAM_TREE_SIZE;
  Z=4;
  L=4;
  printf("ORAM INIT started\r\n" );

  max_stash_occ=0;
  sum_stash_occ=0;
  oram_acc=0;
  real_pages_read=0;
  real_pages_written=0;
 rt_util_getrandom((void*) key, AES_KEYLEN);
 rt_util_getrandom((void*) key_hmac, AES_KEYLEN);
 rt_util_getrandom((void*) z1, AES_KEYLEN);
 rt_util_getrandom((void*) z2, AES_KEYLEN);
 if(debug)
   printf("V35\n" );

 for(int i=0;i<MALLOC_SIZE;i++)
 {
   firstimeaccess[i]='y';
   version_numbers[i]=0;
   stash_loc[i]=-1;
 }
 //Bucket b;b=b;
 for(int j=0;j<Z;j++)
 {
   buc_i.blocks[j].address=DUMMY_BLOCK_ADDR;
   buc_i.blocks[j].version=0;
   buc_i_po_md.blocks[j].address=DUMMY_BLOCK_ADDR;


   //b.blocks[j].address=DUMMY_BLOCK_ADDR;
   //b.blocks[j].version=0;
 }

 for(int i=0;i<N;i++)// initializing the buckets for the outside enclave tree array
 {
   for(int j=0;j<Z;j++)
   {
     buc_i.blocks[j].address=DUMMY_BLOCK_ADDR;
     buc_i.blocks[j].version=0;
     buc_i_po_md.blocks[j].address=DUMMY_BLOCK_ADDR;

   }
   tree_po_md[i]=buc_i_po_md;

   //writebucket(i);
 }

 front=rear=-1;
 for(int i=0;i<ORAM_STASH_SIZE;i++)
 {
   if(enque2((uintptr_t)i)!=ENQUE_SUCCESS)
   {
     printf("failed for %d\n",i );
   }
 }


 printf("ORAM INIT DONE\r\n" );
}
//-----------------------------------------------------------------------------------
