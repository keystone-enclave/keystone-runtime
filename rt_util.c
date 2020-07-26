 //******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
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
#include "opam.h"
#include "roram.h"
#include "freemem.h"
#include "vm.h"
#include "page_replacement.h"
#include "malloc.h"
#include "index_q.h"
#include "uaccess.h"
#include "interrupt.h"
#include "woram.h"
#include "victim_cache.h"

uintptr_t prev_addr=0;
uintptr_t *prev_addr_status=NULL;

int fcc=0;


#define OCALL_GET_CONTENT_FROM_UTM 8
#define OCALL_STORE_CONTENT_TO_UTM 9
#define OCALL_GET_TESTING_PARAMS 5
#define OCALL_STORE_CONTENT_TO_UTM_ENC_PFH 18
#define OCALL_GET_CONTENT_FROM_UTM_ENC_PFH 17
#define OCALL_PRINT_COUNTERS 6

#define THRESHOLD_PAGES 120000
#define INTERVAL 40
uintptr_t alloc=0;
#define FULL_TRACE 34

//#define FULL_TRACE_CHUNK 400000
#define FULL_TRACE_CHUNK 50

enclave_options args_user;
uintptr_t buff_size;
int fault_lim;

uintptr_t fault_mode;
uintptr_t* trace_buff;
uintptr_t trace_buff_cnt=0;
uintptr_t total_trace_buff_cnt=0;
uintptr_t oram_init_time=0;
uintptr_t copy_waste=0;


int first_fault=1;//dont change
int first_page_replacement = 1; //used for victim cache
int enable_oram=1;
int count_ext=0;
int confidentiality=1;
int authentication =1;
int v_cache=0;
int tracing =0;
int debug =0;
int exc=0;
counter counters[NO_OF_COUNTERS];
pages_at vic_page_at;
pages_at brought_page_at;
pages vic_page;
pages brought_page;
char *buff;
char *backup_shared_memory;

uintptr_t pages_read=0;//0
uintptr_t real_pages_read=0;//1
uintptr_t pages_written=0;//2
uintptr_t real_pages_written=0;//3
uintptr_t max_stash_occ=0;//4
uintptr_t sum_stash_occ=0;//5
uintptr_t oram_acc=0;//6
uintptr_t free_pages_fr=0;//7
uintptr_t init_num_pages=0;//8
int countpf=0;//9

uintptr_t time_rblocks_process_r=0;
uintptr_t time_rblocks_process_w=0;
uintptr_t time_dblocks_process_r=0;
uintptr_t time_dblocks_process_w=0;

uintptr_t time_block_copy_r=0;
uintptr_t time_block_copy_w=0;






uint8_t key_chacha[]={0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

uint8_t key_aes[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t iv_aes[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t Key_hmac[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t z_1[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t z_2[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t key_hmac[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t z1[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t z2[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

char sss[30];

//#define THRESHOLD_OPS 200000
//#define THRESHOLD_OPS 130000
#define THRESHOLD_OPS 120000

uintptr_t unplaced_pages_count=0;


//-----------------------------------------------------------------------------------

char enczer0[RISCV_PAGE_SIZE]={0,};
char chachakey[32];
char chachanonce[16];

char test_org[4096];
char test_enc[4096];
char test_dec[4096];

//extern void chacha20(uint8_t *out, const uint8_t *in, size_t inlen, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
void fill_page_with_zeroes(char* page_addrs)
{

    //unsigned long long chacha_s,chacha_e, rand_s,rand_e,hash_s,hash_e;//coment

    //asm volatile ("rdcycle %0" : "=r" (chacha_s));//coment

    //rt_util_getrandom((void*) chachakey, 32);
    rt_util_getrandom((void*) chachanonce, 16);

    chacha20((uint8_t*)page_addrs, (uint8_t*)enczer0, RISCV_PAGE_SIZE, (uint8_t*)key_chacha, (uint8_t*)chachanonce, 1);


//-----------------------------tesing chacha20--------------------
    //
    // for(int i=0;i<4096;i++)
    // {
    //   test_org[i]=(char)i;
    // }
    // printf("Original content : ");
    //
    // for(int i=0;i<20;i++)
    // {
    //  printf("%d ",(int)(test_org[i]));
    // }
    // printf("\n---------\nAfter Encyption\n");
    // chacha20((uint8_t*)test_enc, (uint8_t*)test_org, 4096, (uint8_t*)chachakey, (uint8_t*)chachanonce, 1);
    //
    // for(int i=0;i<20;i++)
    // {
    //  printf("%d ",(int)(test_enc[i]));
    // }
    // printf("\n---------\nAfter Decyption\n");
    // chacha20((uint8_t*)test_dec, (uint8_t*)test_enc, 4096, (uint8_t*)chachakey, (uint8_t*)chachanonce, 1);
    //
    // for(int i=0;i<20;i++)
    // {
    //  printf("%d ",(int)(test_dec[i]));
    // }
    // printf("\n---------\nAfter 1st Decyption Original content\n");
    //
    // for(int i=0;i<20;i++)
    // {
    //  printf("%d ",(int)(test_org[i]));
    // }
    //
    // printf("\n---------\nAfter Encryption Inplace\n");
    //
    // chacha20((uint8_t*)test_org, (uint8_t*)test_org, 4096, (uint8_t*)chachakey, (uint8_t*)chachanonce, 1);
    // for(int i=0;i<20;i++)
    // {
    //  printf("%d ",(int)(test_org[i]));
    // }
    //
    // int flag=0;
    // for(int i=0;i<4096;i++)
    // {
    //   if(test_org[i]!=test_enc[i])
    //   {
    //     flag=1;
    //     break;
    //   }
    // }
    // if(flag==0)
    //   printf("inplace and outof place encryption are same\n");
    // else
    //   printf("inplace and outof place encryption are NOT SAME\n");
    //
    //
    // printf("\n---------\nAfter Decryption Inplace\n");
    // chacha20((uint8_t*)test_org, (uint8_t*)test_org, 4096, (uint8_t*)chachakey, (uint8_t*)chachanonce, 1);
    // for(int i=0;i<20;i++)
    // {
    //  printf("%d ",(int)(test_org[i]));
    // }
    // sbi_exit_enclave(-1);
    // // //-----------------------------tesing chacha20 ends--------------------
    // //
    //



    //asm volatile ("rdcycle %0" : "=r" (chacha_e));//coment


    // asm volatile ("rdcycle %0" : "=r" (rand_s));
    // rt_util_getrandom((void*) enczer0, RISCV_PAGE_SIZE);//coment
    // asm volatile ("rdcycle %0" : "=r" (rand_e));//coment





    //memcpy((void*)page_addrs,(void*)enczer0,RISCV_PAGE_SIZE);

    return;//coment

/*
    asm volatile ("rdcycle %0" : "=r" (hash_s));
    uintptr_t start_zero[2];
    rt_util_getrandom((void*) &start_zero[0], 2*sizeof(uintptr_t));

    for(int i=0;i<4096/64;i++)
    {
      int copy=start_zero[0];
      sha3_ctx_t sha3;
      sha3_init(&sha3, 64);
      sha3_update(&sha3, (void*)&(start_zero[0]), 2*sizeof(uintptr_t));
      sha3_final((void*)(page_addrs+i*64), &sha3);
      start_zero[0]=copy;
      start_zero[0]++;
    }
    asm volatile ("rdcycle %0" : "=r" (hash_e));

    printf("[dummy details] chacha = %lu\n rand = %lu\n hash=%lu\n",(chacha_e-chacha_s),(rand_e-rand_s),(hash_e-hash_s));



    sbi_exit_enclave(-1);//coment
*/

}



//-----------------------------------------------------------------------------------
int pow(uintptr_t a, uintptr_t b)
{
  int res=1;
  //return 64;
  for(int i=1;i<=b;i++)
  {
    res=res*(int)a;
  }
  //printf("[POW] %d %d %d\n",a,b,res);
  return res;
}


//-----------------------------------------------------------------------------------
void  pxget(int leafindex , int Px[ARRAY_SIZE])
{
    int  treeindex = leafindex + (( (int)( pow(ARITY,L)  )-1)/(ARITY-1));
    int i=0;
    while(treeindex>=0)
    {
        Px[L-i]=treeindex;
        //printf("%d ",treeindex);
        i++;
        treeindex = (int)(  ceil( treeindex/ARITY  ) -1 );
    }
    //printf("\n" );
}

//-----------------------------------------------------------------------------------
unsigned int UniformRandom()
{
    unsigned int limit= (int)(   pow(ARITY,L)  );
    unsigned int rn=0;

    //unsigned int rn2=0;//comment later after traces
    rt_util_getrandom(&rn,sizeof(unsigned int));
    //rt_util_getrandom(&rn2,sizeof(unsigned int));//comment later after traces


    //rt_util_getrandom((void*) chachanonce, 16);//comment later after traces
    //chacha20((uint8_t*)&rn, (uint8_t*)&rn, sizeof(unsigned int), (uint8_t*)key_chacha, (uint8_t*)chachanonce, 1);//comment later after traces
    //chacha20((uint8_t*)&rn2, (uint8_t*)&rn2, sizeof(unsigned int), (uint8_t*)key_chacha, (uint8_t*)chachanonce, 1);//comment later after traces



    //return (rn^rn2)%limit;
    return rn%limit;
}
//-----------------------------------------------------------------------------------

int get_tree_index(int x)
{
  //return x + (int)( pow(ARITY,L)  ) - 1 ;
  return x+  (( (int)( pow(ARITY,L)  )-1)/(ARITY-1));
}
//-----------------------------------------------------------------------------------
double log2(int x)
{
    double count =0;
    while(x!=1)
    {
       count++;
       x=x/2;
    }
    return count;
}
//-----------------------------------------------------------------------------------
double ceil(double x)
{
    double t =  (double)(    (int)x);
    if(t==x)
      return t;
    else
        return t+1;
}


//char firstimeaccess[ARRAY_SIZE]={'y',};
char *firstimeaccess;
//--------------------------------------------------------------------------------------------------------------------------------------


// int rt_util_getrandom(void* vaddr, size_t buflen){
//   //TODO: Warning, this may not be safe to cross pages!
//   uintptr_t buf_trans = translate((uintptr_t)vaddr);
//   uintptr_t ret = SBI_CALL_2(SBI_SM_ENCLAVE_GETRANDOM, buf_trans, buflen);
//
//   return ret;
// }


size_t rt_util_getrandom(void* vaddr, size_t buflen){
  size_t remaining = buflen;
  uintptr_t rnd;
  uintptr_t* next = (uintptr_t*)vaddr;
  // Get data
  while(remaining > sizeof(uintptr_t)){
    rnd = sbi_random();
    ALLOW_USER_ACCESS( *next = rnd );
    remaining -= sizeof(uintptr_t);
    next++;
  }
  // Cleanup
  if( remaining > 0 ){
    rnd = sbi_random();
    copy_to_user(next, &rnd, remaining);
  }
  size_t ret = buflen;
  return ret;
}




//--------------------------------------------------------------------------------------------------------------------------------------
void rt_util_misc_fatal(){
  //Better hope we can debug it!
  sbi_exit_enclave(-1);
}
//--------------------------------------------------------------------------------------------------------------------------------------
void not_implemented_fatal(struct encl_ctx_t* ctx){
#ifdef FATAL_DEBUG
    unsigned long addr, cause, pc;
    pc = ctx->regs.sepc;
    addr = ctx->sbadaddr;
    cause = ctx->scause;
    csr_write(sstatus, csr_read(sstatus) | 0x6000);// uncomment after checking
    //init_timer();
    return;


    printf("[runtime] non-handlable interrupt/exception at 0x%lx on 0x%lx (scause: 0x%lx)\r\n", pc, addr, cause);
    printf("[RUNITME] QUEUE CONTETNS\n" );
    //show_queue_contents();

#endif
    // Bail to m-mode
    asm volatile ("csrr a0, scause\r\nli a7, 1111\r\n ecall");// uncomment this
    return;
}
//--------------------------------------------------------------------------------------------------------------------------------------

void ocall_get_page_contents_from_utm(edge_data_t* retdata,uintptr_t args){
  uintptr_t args_= args;
  dispatch_edgecall_ocall(OCALL_GET_CONTENT_FROM_UTM, &args_, sizeof(args_), retdata, sizeof(edge_data_t),0);
  return;
}
//--------------------------------------------------------------------------------------------------------------------------------------
void ocall_get_page_contents_from_utm_enc_pfh(edge_data_t* retdata,uintptr_t args){
  uintptr_t args_= args;
  dispatch_edgecall_ocall(OCALL_GET_CONTENT_FROM_UTM_ENC_PFH, &args_, sizeof(args_), retdata, sizeof(edge_data_t),0);
  return;
}
//--------------------------------------------------------------------------------------------------------------------------------------


void ocall_store_page_contents_to_utm(edge_data_t* retdata,uintptr_t args){// ocall that will bring a page
  //char victim_page_contents[sizeof(pages)];
  //memcpy((void*)victim_page_contents , (void*)args,sizeof(pages));
  printf("[dispatch ocall] pkgstr = retdata and args = vic_page\n");
  dispatch_edgecall_ocall(OCALL_STORE_CONTENT_TO_UTM, (void*)args, sizeof(pages), retdata, sizeof(edge_data_t),0);
  return;
}
//--------------------------------------------------------------------------------------------------------------------------------------

void ocall_store_page_contents_to_utm_enc_pfh(edge_data_t* retdata,uintptr_t args){// ocall that will bring a page
  //char victim_page_contents[sizeof(pages_at)];
  //memcpy((void*)victim_page_contents , (void*)args,sizeof(pages_at));
  dispatch_edgecall_ocall(OCALL_STORE_CONTENT_TO_UTM_ENC_PFH, (void*)args, sizeof(pages_at), NULL, 0,0);
  return;
}
//--------------------------------------------------------------------------------------------------------------------------------------

void display_page_contents(uintptr_t start)
{
   for (size_t i = 0; i < (RISCV_PAGE_SIZE); i++) {
     printf("0x%lx ",  (uintptr_t) *(char*)(start+i)      );
   }
   printf("\n" );
}

void calculate_hmac(pages* p, char* hm, uintptr_t hm_len)
{
  char hash_calc[HASH_SIZE];
  sha3_ctx_t sha3;
  sha3_init(&sha3, HASH_SIZE);
  char c[16];
  xor_op((char*)Key_hmac,(char*)z_2,c,AES_KEYLEN);
  sha3_update(&sha3, (void*)c, AES_KEYLEN);
  sha3_update(&sha3, (void*)(*p).data, RISCV_PAGE_SIZE);
  sha3_update(&sha3, (void*)&((*p).ver_num), 2*sizeof(uintptr_t));

  sha3_final((void*)hash_calc, &sha3);
  char c2[16];
  xor_op((char*)Key_hmac,(char*)z_1,c2,AES_KEYLEN);
  sha3_ctx_t sha32;
  sha3_init(&sha32, HASH_SIZE);
  sha3_update(&sha32, (void*)c2, AES_KEYLEN);
  sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
  sha3_final((void*)hm, &sha32);
}
//--------------------------------------------------------------------------------------------------------------------------------------
void calculate_hmac_for_enc_pfh(pages_at* p, char* hm, uintptr_t hm_len)
{
  char hash_calc[HASH_SIZE];
  sha3_ctx_t sha3;
  sha3_init(&sha3, HASH_SIZE);
  char c[16];
  xor_op((char*)Key_hmac,(char*)z_2,c,AES_KEYLEN);
  sha3_update(&sha3, (void*)c, AES_KEYLEN);
  sha3_update(&sha3, (void*)(*p).data, RISCV_PAGE_SIZE);
  sha3_update(&sha3, (void*)&((*p).address), 2*sizeof(uintptr_t));

  sha3_final((void*)hash_calc, &sha3);
  char c2[16];
  xor_op((char*)Key_hmac,(char*)z_1,c2,AES_KEYLEN);
  sha3_ctx_t sha32;
  sha3_init(&sha32, HASH_SIZE);
  sha3_update(&sha32, (void*)c2, AES_KEYLEN);
  sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
  sha3_final((void*)hm, &sha32);
}
//--------------------------------------------------------------------------------------------------------------------------------------


void print_details()
{


  counters[PAGES_READ].count=pages_read;
  counters[PAGES_WRITTEN].count=pages_written;
  counters[INIT_NUM_PAGES].count=init_num_pages;
  counters[PAGE_FAULT_COUNT].count=countpf;
  counters[FREE_PAGES_FR].count=free_pages_fr;
  counters[EXTENSIONS].count=count_ext;
  counters[TOTAL_PAGES].count=counters[INIT_NUM_PAGES].count+counters[EXTENSIONS].count;
  counters[REAL_PAGES_READ].count=pages_read;
  counters[REAL_PAGES_WRITTEN].count=pages_written;
  counters[ORAM_INIT].count=oram_init_time;
  counters[COPY_WASTE].count=copy_waste;

  if(enable_oram==OPAM ||enable_oram==PATH_ORAM || enable_oram==RORAM)
  {
    counters[REAL_PAGES_READ].count=real_pages_read;
    counters[REAL_PAGES_WRITTEN].count=real_pages_written;
    counters[DUMMY_PAGES_READ].count=counters[PAGES_READ].count-counters[REAL_PAGES_READ].count;
    counters[DUMMY_PAGES_WRITTEN].count=counters[PAGES_WRITTEN].count-counters[REAL_PAGES_WRITTEN].count;
    counters[MAX_STASH_OCC].count=max_stash_occ;
    counters[SUM_STASH_OCC].count=sum_stash_occ;
    counters[ORAM_ACC].count=oram_acc;


}


  printf("\n----------------------------\n");
  /*
  printf("[runtime] initial number of pages = %d\n",init_num_pages );
  printf("[runtime] EXTENSIONS = %d\n",count_ext );
  printf("[runtime] Total pages(P) = %d\n",init_num_pages+count_ext );
  printf("[runtime] Page fault count %d\n",countpf);
  printf("[runtime] Number of pages reads %d\n",pages_read);
  printf("[runtime] Number of pages written %d\n",pages_written);
  if(enable_oram==PATH_ORAM)
  {
    printf("[runtime] Max stash occupancy %d\n",max_stash_occ);
    printf("[runtime] Avg stash occupancy %lu/%lu\n",sum_stash_occ,oram_acc);
    printf("[runtime] Number of real pages reads %d\n",real_pages_read);
    printf("[runtime] Number of real pages written %d\n",real_pages_written);
    printf("[runtime] Number of dummy pages reads %d\n",pages_read-real_pages_read);
    printf("[runtime] Number of dummy pages written %d\n",pages_written-real_pages_written);
  }
  */


/*
  for(int i=0;i<NO_OF_COUNTERS;i++)
  {
    if(i<=6)
      printf("%s:%lu\n",counters[i].name,counters[i].count);
    else  if(enable_oram==OPAM ||enable_oram==PATH_ORAM || enable_oram==RORAM)
      printf("%s:%lu\n",counters[i].name,counters[i].count);
  }
*/


  //
  // printf("real block read cycles %lu\n",time_rblocks_process_r);
  // printf("real block write cycles %lu\n",    ( (time_rblocks_process_w>>13   )+time_block_copy_w )           );
  // printf("dummy block read cycles %lu\n",time_dblocks_process_r);
  // printf("dummy block write cycles %lu\n",( (time_dblocks_process_w>>13   )+time_block_copy_w ) );
  //printf("----------------------------\n");



  dispatch_edgecall_ocall(OCALL_PRINT_COUNTERS,counters,NO_OF_COUNTERS*sizeof(counter),NULL,0,0);


}
//--------------------------------------------------------------------------------------------------------------------------------------
void display_test_params()
{
  if(enable_oram==PATH_ORAM)
    printf("[runtime] Oram Enabled " );
  if(confidentiality)
    printf("[runtime] Confidentiality Enabled " );
  if(authentication)
    printf("[runtime] authentication Enabled " );
  if(tracing)
      printf("[runtime] tracing Enabled " );
  //sbi_exit_enclave(-1);
}
//--------------------------------------------------------------------------------------------------------------------------------------
void deplete_free_pages_for_testing(uintptr_t left)//this is only for testing
{
    uintptr_t total_left=spa_available();
    if(left> total_left)
      return;
    for(int i=0;i<total_left-left;i++)
    {
      uintptr_t da=spa_get();da=da;
      assert(da >= freemem_va_start && da < (freemem_va_start  + freemem_size));
      //printf("[runtime] i=%lu ",i);
    }
}

//------------------------------------------------------------------------------

char sourcet[4096];
char destt[4096];
char key_testing[AES_KEYLEN];
char iv_testing[16];


void do_something_extra()
{
  printf("started extra\r\n");
  rt_util_getrandom((void*) key_testing, AES_KEYLEN);
  rt_util_getrandom((void*) iv_testing, AES_KEYLEN);
  rt_util_getrandom((void*) key_hmac, AES_KEYLEN);
  rt_util_getrandom((void*) z_1, AES_KEYLEN);
  rt_util_getrandom((void*) z_2, AES_KEYLEN);

  rt_util_getrandom((void*) sourcet, 4096);
  rt_util_getrandom((void*) destt, 4096);

  int times=1024;//change it to 1024

  //------------------------encryppting aes---------------------
  unsigned long long aes_enc_s,aes_enc_e;

  asm volatile ("rdcycle %0" : "=r" (aes_enc_s));
  for(int i=0;i< times;i++)
  {
    encrypt_page((uint8_t*)sourcet,RISCV_PAGE_SIZE,(uint8_t*)key_testing,(uint8_t*)iv_testing);

  }
  asm volatile ("rdcycle %0" : "=r" (aes_enc_e));
  printf("encryppting aes done\r\n");
  //------------------------encryppting aes DONE---------------------
//******************************************************************************************************************

  //------------------------decrypting aes---------------------
  unsigned long long aes_dec_s,aes_dec_e;

  asm volatile ("rdcycle %0" : "=r" (aes_dec_s));
  for(int i=0;i< times;i++)
  {
    decrypt_page((uint8_t*)sourcet,RISCV_PAGE_SIZE,(uint8_t*)key_testing,(uint8_t*)iv_testing);

  }
  asm volatile ("rdcycle %0" : "=r" (aes_dec_e));
  printf("decrypting aes done\r\n");
  //------------------------decrypting aes DONE---------------------
  //******************************************************************************************************************



  //------------------------chacha ---------------------
  unsigned long long chacha_s,chacha_e;

  asm volatile ("rdcycle %0" : "=r" (chacha_s));
  for(int i=0;i< times;i++)
  {
    fill_page_with_zeroes(sourcet);
  }
  asm volatile ("rdcycle %0" : "=r" (chacha_e));
  printf("chacha done\r\n");
  //------ ------------------chacha done ---------------------
  //******************************************************************************************************************


  //---------------------------------copy-----------------------------
  unsigned long long copy_s,copy_e;

  asm volatile ("rdcycle %0" : "=r" (copy_s));
  for(int i=0;i< times;i++)
  {
    memcpy((void*)sourcet,(void*)destt,4096);
  }
  asm volatile ("rdcycle %0" : "=r" (copy_e));
  printf("copying done\r\n");
  //---------------------------------copy done-----------------------------
  //******************************************************************************************************************



  //---------------------------------hmac -----------------------------
  unsigned long long hmac_s,hmac_e;

  asm volatile ("rdcycle %0" : "=r" (hmac_s));
  for(int i=0;i< times;i++)
  {
    char hash_calc[HASH_SIZE];
    sha3_ctx_t sha3;
    sha3_init(&sha3, HASH_SIZE);
    char c[16];
    xor_op((char*)key_hmac,(char*)z_2,c,AES_KEYLEN);
    sha3_update(&sha3, (void*)sourcet, 4096);

    sha3_final((void*)hash_calc, &sha3);
    char c2[16];
    xor_op((char*)key_hmac,(char*)z_1,c2,AES_KEYLEN);
    sha3_ctx_t sha32;
    sha3_init(&sha32, HASH_SIZE);
    sha3_update(&sha32, (void*)c2, AES_KEYLEN);
    sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
    sha3_final((void*)destt, &sha32);

  }
  asm volatile ("rdcycle %0" : "=r" (hmac_e));
  printf("hmac done\r\n");
  //---------------------------------hmac done-----------------------------
  //******************************************************************************************************************


  // time calcs
  int bits=10;
  unsigned long long aes_enc= (aes_enc_e-aes_enc_s)>>bits;
  unsigned long long aes_dec=(aes_dec_e-aes_dec_s)>>bits;
  unsigned long long chacha=(chacha_e-chacha_s)>>bits;
  unsigned long long copy=(copy_e-copy_s)>>bits;
  unsigned long long hmac=(hmac_e-hmac_s)>>bits;
  printf("AFTER %d times\n",times);
  printf("aes_enc = %lu\n",aes_enc );
  printf("aes_dec = %lu\n", aes_dec);
  printf("chacha = %lu\n",chacha );
  printf("copy = %lu\n", copy);
  printf("hmac = %lu\n",hmac );
  printf("PRINTED ALL STATS\n");
  sbi_exit_enclave(-1);

}

/* Convert enclave VA to runtime VA */
uintptr_t get_runtime_addr(uintptr_t victim_page_enc)
{
  uintptr_t *root_page_table_addr = get_root_page_table_addr();
  uintptr_t *pte = __walk(root_page_table_addr,victim_page_enc);
  uintptr_t va_runtime = __va(  ( (*pte)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS); //zero out the offset
  return va_runtime;
}

//NOTE - JUST WRITES TO WORAM RIGHT NOW
//REQUIREMENT - Victim Cache size should be atleast 1
void write_to_victim_cache_handle_full(uintptr_t addr, uintptr_t req_addr) 
{
  printf("addr 0x%zx req_addr 0x%zx\n", addr, req_addr);
  // Step 1 - Get LRU Page from cache
  uintptr_t page_out = get_lru_victim_from_cache();
  if(page_out >> RISCV_PAGE_BITS == req_addr >> RISCV_PAGE_BITS)
  {
    printf("Access lru page 0x%zx to prevent its replacement\n", req_addr);
    move_lru_to_mru_in_cache();
    page_out = get_lru_victim_from_cache();
  }
  uintptr_t page_out_va = get_runtime_addr(page_out);
  printf("Lru page enclave addr 0x%zx runtime va 0x%zx\n", page_out, page_out_va);

  /* 
    WRITE TO OTHER ORAM TYPES CAN BE HANDLED HERE IN STEP 2
     BY PASSING A FLAG TO THIS FUNCTION
  */
  // Step 2 - Write the page contents to ORAM
  store_victim_page_to_woram(page_out, page_out_va, confidentiality, authentication);
  pages_written++;
  printf("Moved 0x%zx to oram\n", page_out);

  printf("Removing lru from the cache\n");
  // Step 3 - Remove the page from cache
  remove_lru_page_from_cache();

  printf("Freed page 0x%zx\n", page_out);
  // Step 4 - Free the page (Cache has 1 free page now)
  free_page(vpn(page_out));

  // Step 5 - Add replaced page to cache 
  move_page_to_cache_from_enclave(addr);
}

void setup_keys_and_buffer()
{
  rt_util_getrandom((void*) key_aes, AES_KEYLEN);
  rt_util_getrandom((void*) iv_aes, AES_KEYLEN);
  rt_util_getrandom((void*) key_hmac, AES_KEYLEN);
  rt_util_getrandom((void*) z_1, AES_KEYLEN);
  rt_util_getrandom((void*) z_2, AES_KEYLEN);

  buff_size=BACKUP_BUFFER_SIZE_OTHERS;
  buff=(char*)malloc(BACKUP_BUFFER_SIZE_OTHERS*sizeof(char));

  if(buff==NULL)
  {
    printf("[runtime] buff allocation failed\n" );
    sbi_exit_enclave(-1);
  }
  backup_shared_memory=(char*)malloc(BACKUP_BUFFER_SIZE_OTHERS*sizeof(char));

  if(backup_shared_memory==NULL)
  {
    printf("[runtime] backup_shared_memory allocation failed\n" );
    sbi_exit_enclave(-1);
  }
}

void allocate_fresh_page(uintptr_t new_alloc_page, uintptr_t *status_find_address)
{
  // printf("[runtime] Extension is 1. Hence just alloacte zero page\n");
  memset((void*)new_alloc_page, 0, RISCV_PAGE_SIZE);
  //updating the page table entry with the address of the newly allcated page
  unsigned long int flags = PTE_D|PTE_A | PTE_V| PTE_R | PTE_X | PTE_W | PTE_U | PTE_L ;
  *status_find_address = pte_create( ppn(__pa((uintptr_t)new_alloc_page) ), flags );
  // *status_find_address =(*status_find_address)|PTE_E|PTE_V; //DELETE AFTER TAKING TRACES
  asm volatile ("fence.i\t\nsfence.vma\t\n");
}

void setup_page_fault_handler(uintptr_t addr, uintptr_t *status_find_address)
{
  unsigned long long cycles1,cycles2;

  asm volatile ("rdcycle %0" : "=r" (cycles1));
  strcpy(sss,"firstimeaccess");
  rt_util_getrandom((void*) key_chacha, 32);
  strcpy(sss,"version_numbers");

  version_numbers=(uintptr_t*)malloc(MALLOC_SIZE*sizeof(uintptr_t));
  trace_buff=(uintptr_t*)malloc(FULL_TRACE_CHUNK*sizeof(uintptr_t));

  if(version_numbers==NULL)
  {
    printf("[runtime] version_numbers allocation failed\n" );
    sbi_exit_enclave(-1);
  }

  for(int i=0;i<NO_OF_COUNTERS;i++)
    counters[i].count=0;
  pages_read=0;
  pages_written=0;
  init_num_pages=(uintptr_t)get_queue_size();
  alloc=init_num_pages;

  edge_data_t pkgstr;
  dispatch_edgecall_ocall(OCALL_GET_TESTING_PARAMS,NULL,0,&pkgstr,sizeof(edge_data_t),(uintptr_t)&args_user);

  enable_oram=args_user.page_fault_handler;
  authentication=args_user.integrity_protection;
  confidentiality=args_user.confidentiality;
  free_pages_fr=args_user.num_free_pages;
  v_cache=args_user.victim_cache;
  tracing=args_user.page_addr_tracing;
  debug=args_user.debug_mode;
  exc=args_user.tree_exc;
  fault_lim= args_user.fault_limit;
  frame_size=free_pages_fr;
  //display_test_params();
  //printf("[RUNTIME] fault limit %d \n",fault_lim );
  //sbi_exit_enclave(-1);

  strcpy(counters[PAGES_READ].name,"PAGES_READ");
  strcpy(counters[PAGES_WRITTEN].name,"PAGES_WRITTEN");
  strcpy(counters[INIT_NUM_PAGES].name,"INIT_NUM_PAGES");
  strcpy(counters[PAGE_FAULT_COUNT].name,"PAGE_FAULT_COUNT");
  strcpy(counters[FREE_PAGES_FR].name,"FREE_PAGES_FR");
  strcpy(counters[EXTENSIONS].name,"EXTENSIONS");
  strcpy(counters[TOTAL_PAGES].name,"TOTAL_PAGES");
  strcpy(counters[REAL_PAGES_READ].name,"REAL_PAGES_READ");
  strcpy(counters[REAL_PAGES_WRITTEN].name,"REAL_PAGES_WRITTEN");
  strcpy(counters[DUMMY_PAGES_READ].name,"DUMMY_PAGES_READ");
  strcpy(counters[DUMMY_PAGES_WRITTEN].name,"DUMMY_PAGES_WRITTEN");
  strcpy(counters[MAX_STASH_OCC].name,"MAX_STASH_OCC");
  strcpy(counters[SUM_STASH_OCC].name,"SUM_STASH_OCC");
  strcpy(counters[ORAM_ACC].name,"ORAM_ACC");
  strcpy(counters[ORAM_INIT].name,"ORAM_INIT");

  if(debug)
    display_test_params();
  uintptr_t left =free_pages_fr-init_num_pages; left=left;
  //deplete_free_pages_for_testing(left);
  if(debug)
    printf("[runtime] free pages left %lu\n",spa_available() );
  if(enable_oram==PATH_ORAM)
  {
    //unsigned long long cycles1,cycles2;

    //asm volatile ("rdcycle %0" : "=r" (cycles1));

    S=(Block*)malloc(ORAM_STASH_SIZE*sizeof(Block));
    Sg=(Block*)malloc(ORAM_STASH_SIZE*sizeof(Block));

    firstimeaccess=(char*)malloc(MALLOC_SIZE);
    if(firstimeaccess==NULL)
    {
      printf("[runtime] firstimeaccess allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    position=(uintptr_t*)malloc(MALLOC_SIZE*sizeof(uintptr_t));
    if(position==NULL)
    {
      printf("[runtime] position map allocation failed\n" );
      sbi_exit_enclave(-1);
    }
    tree_po_md=(Bucket_md *)malloc(ORAM_TREE_SIZE*sizeof(Bucket_md));
    if(tree_po_md==NULL)
    {
      printf("[runtime] tree_po_md allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    buff_size=BACKUP_BUFFER_SIZE_ORAM;
    buff=(char*)malloc(BACKUP_BUFFER_SIZE_ORAM*sizeof(char));

    if(buff==NULL)
    {
      printf("[runtime] buff allocation failed\n" );
      sbi_exit_enclave(-1);
    }
    backup_shared_memory=(char*)malloc(BACKUP_BUFFER_SIZE_ORAM*sizeof(char));

    if(backup_shared_memory==NULL)
    {
      printf("[runtime] backup_shared_memory allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    free_indices=(uintptr_t*)malloc(ORAM_STASH_SIZE*sizeof(uintptr_t));
    if(free_indices==NULL)
    {
      printf("[runtime] free_indices allocation failed\n" );
      sbi_exit_enclave(-1);
    }


    stash_loc=(int*)malloc(MALLOC_SIZE*sizeof(uintptr_t));
    if(stash_loc==NULL)
    {
      printf("[runtime] stash_loc allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    initalize_oram();

  }
  else if(enable_oram==NO_ORAM)
  {
    printf("[runtime] First fault No ORAM. Allocating Buffer stuff\n");
    // printf("[keytest] 0x%zx 0x%zx\n", key_chacha[0], key_chacha[1]);
    setup_keys_and_buffer();
  }
  else if(enable_oram==ENC_PFH)
  {
    p_ivs=(iv_page*)malloc(MALLOC_SIZE*sizeof(iv_page));
    if(p_ivs==NULL)
    {
      printf("[runtime] knocked_page_addr allocation failed\n" );
      sbi_exit_enclave(-1);
    }
    setup_keys_and_buffer();
  }
  else if(enable_oram==OPAM)
  {
    //unsigned long long cycles1,cycles2;
    //asm volatile ("rdcycle %0" : "=r" (cycles1));

    S_opam_md=(Block_Opam_md*)malloc(OPAM_STASH_SIZE*sizeof(Block_Opam_md));
    firstimeaccess=(char*)malloc(MALLOC_SIZE);
    if(firstimeaccess==NULL)
    {
      printf("[runtime] firstimeaccess allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    position=(uintptr_t*)malloc(MALLOC_SIZE*sizeof(uintptr_t));
    if(position==NULL)
    {
      printf("[runtime] position map allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    buff_size=BACKUP_BUFFER_SIZE_OTHERS;

    buff=(char*)malloc(BACKUP_BUFFER_SIZE_OTHERS*sizeof(char));

    if(buff==NULL)
    {
      printf("[runtime] buff allocation failed\n" );
      sbi_exit_enclave(-1);
    }
    backup_shared_memory=(char*)malloc(BACKUP_BUFFER_SIZE_OTHERS*sizeof(char));

    if(backup_shared_memory==NULL)
    {
      printf("[runtime] backup_shared_memory allocation failed\n" );
      sbi_exit_enclave(-1);
    }


    initialize_opam();
    //asm volatile ("rdcycle %0" : "=r" (cycles2));

    //printf("[OPAM] time to initialize %lu\n",(cycles2-cycles1));
    //oram_init_time=cycles2-cycles1;

    //sbi_exit_enclave(-1);
  }
  else if(enable_oram==RORAM)
  {
    //unsigned long long cycles1,cycles2;

    //asm volatile ("rdcycle %0" : "=r" (cycles1));
    S_roram=(Block_roram*)malloc(STASH_SIZE_RORAM*sizeof(Block_roram));
    if(S_roram==NULL)
    {
      printf("[runtime] S_roram allocation failed\n" );
      sbi_exit_enclave(-1);
    }


    S_roram_md=(Bucket_roram_md*)malloc(STASH_SIZE_RORAM*sizeof(Bucket_roram_md));
    if(S_roram_md==NULL)
    {
      printf("[runtime] S_roram_md allocation failed\n" );
      sbi_exit_enclave(-1);
    }


    tree_roram_md=(Bucket_roram_md*)malloc(RORAM_TREE_SIZE*sizeof(Bucket_roram_md));
    if(tree_roram_md==NULL)
    {
      printf("[runtime] tree_roram_md allocation failed\n" );
      sbi_exit_enclave(-1);
    }

// /tree_roram_tree_top
    tree_roram_tree_top=(Bucket_roram*)malloc(RORAM_TREE_TOP_SIZE*sizeof(Bucket_roram));
    if(tree_roram_tree_top==NULL)
    {
      printf("[runtime] tree_roram_tree_top allocation failed\n" );
      sbi_exit_enclave(-1);
    }



    firstimeaccess=(char*)malloc(MALLOC_SIZE);
    if(firstimeaccess==NULL)
    {
      printf("[runtime] firstimeaccess allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    position=(uintptr_t*)malloc(MALLOC_SIZE*sizeof(uintptr_t));
    if(position==NULL)
    {
      printf("[runtime] position map allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    free_indices=(uintptr_t*)malloc(STASH_SIZE_RORAM*sizeof(uintptr_t));
    if(free_indices==NULL)
    {
      printf("[runtime] free_indices allocation failed\n" );
      sbi_exit_enclave(-1);
    }



    stash_loc=(int*)malloc(MALLOC_SIZE*sizeof(uintptr_t));
    if(stash_loc==NULL)
    {
      printf("[runtime] stash_loc allocation failed\n" );
      sbi_exit_enclave(-1);
    }

    block_map=(int*)malloc(MALLOC_SIZE*sizeof(int));
    if(block_map==NULL)
    {
      printf("[runtime] block_map allocation failed\n" );
      sbi_exit_enclave(-1);

    }

    buff_size=BACKUP_BUFFER_SIZE_RORAM;

    buff=(char*)malloc(BACKUP_BUFFER_SIZE_RORAM*sizeof(char));

    if(buff==NULL)
    {
      printf("[runtime] buff allocation failed\n" );
      sbi_exit_enclave(-1);
    }
    backup_shared_memory=(char*)malloc(BACKUP_BUFFER_SIZE_RORAM*sizeof(char));

    if(backup_shared_memory==NULL)
    {
      printf("[runtime] backup_shared_memory allocation failed\n" );
      sbi_exit_enclave(-1);
    }
    initialize_roram();

  }
  else if(enable_oram == WORAM)
  {
    printf("[runtime] First fault WORAM. Allocating buffer stuff\n");
    setup_keys_and_buffer();
    initialize_woram_array();
    setup_key_utilities(key_chacha,key_aes,iv_aes,Key_hmac,z_1,z_2,key,key_hmac,z1,z2);
    printf("[runtime] victim cache on/off %zd\n", v_cache);
  }

  first_fault=0;
  asm volatile ("rdcycle %0" : "=r" (cycles2));
  oram_init_time=cycles2-cycles1;
}

void handle_page_fault(uintptr_t addr, uintptr_t *status_find_address)
{
  printf("[runtime] Handle Page Fault called for addr 0x%zx\n", addr);
  if(first_fault)
  {
    setup_page_fault_handler(addr, status_find_address);
  }

  uintptr_t *root_page_table_addr = get_root_page_table_addr();
  if(status_find_address==0)
        status_find_address=__walk(root_page_table_addr,addr);

  if(status_find_address==0)
  {
    printf("[runtime] Unmapped address. Fatal error. Exiting.\n");
    sbi_exit_enclave(-1);
  }

    if( (*status_find_address) & PTE_L  )// it is legal page but not present in memory
    {
      countpf++;
      uintptr_t source_page_VA=(*status_find_address)>>PTE_PPN_SHIFT; //get the physical address
      int enable_swap_out = 1;enable_swap_out=enable_swap_out;
      int threshold_number_of_pages=650000;threshold_number_of_pages=threshold_number_of_pages;// max number of user pages to be allocated at a time
      uintptr_t current_q_size=0;// stores number of user pages currently allocated
      current_q_size=(uintptr_t)get_queue_size();

      //if(current_q_size>=threshold_number_of_pages &&  enable_swap_out)
      //if(spa_available()<6500 )// no more physical pages are available. so we need to swap out a page
      uintptr_t allocated_pages_count= 130560+300 - spa_available()+6500-init_num_pages-6000;allocated_pages_count=allocated_pages_count;
      // printf("[runtime] curr q size %zd, init_num_pages %zd, free_pages %zd, cache %zd\n", current_q_size, init_num_pages, free_pages_fr, MAX_VICTIM_CACHE_PAGES);
      unsigned long int victim_cache_assigned_pages = 0;
      if(v_cache) victim_cache_assigned_pages =  MAX_VICTIM_CACHE_PAGES;
      if(current_q_size + init_num_pages + victim_cache_assigned_pages >=free_pages_fr)
      {
        // printf("[runtime] No free page\n");
        if(first_page_replacement == 1)
        {
          // printf("[runtime] First page replacement\n");
          first_page_replacement = 0;
          if(v_cache)
            initialize_victim_cache();
        }
        uintptr_t victim = remove_victim_page();
        //uintptr_t victim_page_org=pop_item[0];
        uintptr_t victim_page_enc=pop_item[1];//UC THIS
        uintptr_t victim_page_org=0;//UC THIS
        if(victim != QUEUE_EMPTY)
        {
          // get the pte of this victim page by doing a pge table walk
          uintptr_t stored_victim_page_addr=1;
          uintptr_t *status_find_pte_victim = __walk(root_page_table_addr,victim_page_enc);
          victim_page_org=__va(  ( (*status_find_pte_victim)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS);//UC THIS
          int victim_page_dirty = 1;
          if( (    (*status_find_pte_victim) & PTE_D ) || enable_oram==OPAM || enable_oram==ENC_PFH  ||  (   (exc==1) && (enable_oram==PATH_ORAM || enable_oram==RORAM )  )   )
          {
            // printf("[runtime] P.A of 0x%lx is 0x%lx\n",victim_page_enc, ( (*status_find_pte_victim)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS);
            // printf("[runtime] P.A of 0x%lx is 0x%lx\n",addr, ( (*status_find_address)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS);

             if(debug)
              printf("[runtime] addr = 0x%lx dirty\n",victim_page_enc );
             if(enable_oram==NO_ORAM)
             {
              //  printf("[nooram] Entry point for Page Replacement\n");
               pages_written++;
               edge_data_t pkgstr;
               vic_page.address=victim_page_enc;
               memcpy((void*)vic_page.data,(void*)victim_page_org,RISCV_PAGE_SIZE  );
              //  printf("[nooram] victim page addr 0x%lx\n", vic_page.address);
               version_numbers[vpn(victim_page_enc)]++;//uncomment this

               vic_page.ver_num=version_numbers[vpn(victim_page_enc)];
               if(confidentiality)
               {
                 encrypt_page((uint8_t*)vic_page.data,RISCV_PAGE_SIZE,(uint8_t*)key_aes,(uint8_t*)iv_aes);
                 encrypt_page((uint8_t*)&vic_page.ver_num,2*sizeof(uintptr_t),(uint8_t*)key_aes,(uint8_t*)iv_aes);
               }
               if(authentication)
               {
                  calculate_hmac(&vic_page,vic_page.hmac,HASH_SIZE);
               }
               ocall_store_page_contents_to_utm((void*)&pkgstr,(uintptr_t)&vic_page);
               handle_copy_from_shared((void*)&stored_victim_page_addr,pkgstr.offset,pkgstr.size);
             }

             else if(enable_oram==ENC_PFH)
             {
               pages_written++;
               edge_data_t pkgstr;
               memcpy((void*)vic_page_at.data,(void*)victim_page_org,RISCV_PAGE_SIZE  );
               vic_page_at.address=vpn(victim_page_enc)<<RISCV_PAGE_BITS;
               vic_page_at.dummy=0;
               version_numbers[vpn(victim_page_enc)]++;
               rt_util_getrandom((void*) p_ivs[vpn(victim_page_enc)].iv, AES_KEYLEN);
               if(confidentiality)
               {
                 encrypt_page((uint8_t*)vic_page_at.data,RISCV_PAGE_SIZE,(uint8_t*)key_aes,(uint8_t*) p_ivs[vpn(victim_page_enc)].iv);
               }
               encrypt_page((uint8_t*)&vic_page_at.address,2*sizeof(uintptr_t),(uint8_t*)key_aes,(uint8_t*)p_ivs[vpn(victim_page_enc)].iv);
               calculate_hmac_for_enc_pfh(&vic_page_at,vic_page_at.hmac,HASH_SIZE);
               ocall_store_page_contents_to_utm_enc_pfh((void*)&pkgstr,(uintptr_t)&vic_page_at);
               if(tracing && (pages_written+pages_read)>THRESHOLD_OPS)
               {
                 sbi_exit_enclave(-1);

               }
             }
             else if(enable_oram==PATH_ORAM)// by ORAM
             {
               access('w',vpn(victim_page_enc),(char*)__va(  ( (*status_find_pte_victim)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS),NULL,0);
             }
             else if(enable_oram==OPAM)// by OPAM
             {
               int success=0;
               uintptr_t fail_cnt=0;
ff:            success=access_opam('w',vpn(victim_page_enc),(char*)__va(  ( (*status_find_pte_victim)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS),NULL,0);


               if(!success)
               {
                 place_new_page(  victim_page_org,victim_page_enc);
                 fail_cnt++;
                 if(fail_cnt>=(get_queue_size()-3))
                 {
                   remap_all();
                   fail_cnt=0;
                 }
                 victim = remove_victim_page();
                 //victim_page_org=pop_item[0];
                 victim_page_enc=pop_item[1];
                 status_find_pte_victim = __walk(root_page_table_addr,victim_page_enc);
                 victim_page_org=__va(  ( (*status_find_pte_victim)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS);
                 goto ff;
               }
               if(tracing && (   (real_pages_written+real_pages_read)>THRESHOLD_OPS  ) )
               {
                 sbi_exit_enclave(-1);

               }

             }
             else if(enable_oram==RORAM)// by RING ORAM
             {
               access_roram('w',vpn(victim_page_enc),(char*)__va(  ( (*status_find_pte_victim)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS),NULL,0);
               if(tracing && (pages_written+pages_read)>THRESHOLD_OPS)
               {
                 sbi_exit_enclave(-1);
               }

             }
             else if(enable_oram==WORAM)
             {
                /* -----------------------------------------------------------------------------------
                                          ONLY FOR WORAM
                --------------------------------------------------------------------------------------
                If Victim Cache is enabled,
                  a) Check if it is full
                  b) If full, 
                      1. Get LRU page from cache and move it to woram to free space in cache
                      2. Move the replaced(victim) page to victim cache
                  c) If not full, move the replaced page(victim) to victim cache
                  d) Invalidate the replaced(victim) page's pte entry

                If Victim Cache is disabled, store the replaced(victim) to woram

                --------------------------------------------------------------------------------------
                */
                if(v_cache) // If Victim Cache is enabled
                {
                   int is_full = is_victim_cache_full();
                   printf("[runtime] Cache full? %d\n", is_full);
                   if(is_full)
                     write_to_victim_cache_handle_full(victim_page_enc, addr); 
                   else 
                     move_page_to_cache_from_enclave(victim_page_enc);   
                  printf("[runtime] Invalidating replaced page 0x%zx -> 0x%zx", victim_page_enc, *status_find_pte_victim);
                  *status_find_pte_victim = *status_find_pte_victim & ~PTE_V; //invalidate page
                  printf("[runtime] After invalidation replaced page 0x%zx -> 0x%zx", victim_page_enc, *status_find_pte_victim);

                }
                else // If Victim Cache is disabled
                {
                  store_victim_page_to_woram(victim_page_enc, victim_page_org, confidentiality, authentication);
                  pages_written++;
                }
                
             }
          }
          else // Victim Page isn't Dirty
          {
            victim_page_dirty = 0; //mark it as not dirty
            // we invalidate the victim page's entry in case of WORAM 
            if(debug)
            {
              printf("[runtime] addr = 0x%lx(0x%lx) NOT dirty\n",victim_page_enc ,victim_page_org);
              printf("[runtime] didn't knock addr 0x%lx(0x%lx)\n", victim_page_enc,victim_page_org);
            }
          }

          if ( enable_oram == WORAM && (!v_cache || !victim_page_dirty))
          {
            /* -----------------------------------------------------------------------------------
                                          ONLY FOR WORAM
            --------------------------------------------------------------------------------------
              Free replaced page if
                a) Either Victim Cache is disabled OR 
                b) Victim cache is enabled but page to be replaced is not dirty
              Else the replaced page resides in the victim cache inside the enclave
              and hence shouldn't be freed. It's PTE entry has already been invalidated.
            --------------------------------------------------------------------------------------
            */

            free_page(vpn(victim_page_enc));
            alloc--;

          }
          if( enable_oram != WORAM) //original code for other page fault handlers
          {
            free_page(vpn(victim_page_enc));
            alloc--;
            *status_find_pte_victim = (stored_victim_page_addr << PTE_PPN_SHIFT) | (PTE_D| PTE_A | PTE_R | PTE_X | PTE_W | PTE_U | PTE_L);
          }
          
          //access_counter[vpn(victim_page_enc)]=0;
          asm volatile ("fence.i\t\nsfence.vma\t\n");
          //memset((void*)victim_page_org, 0, RISCV_PAGE_SIZE);
        }
        else
        {
          printf("[runtime] Page replacement queue empty. Can't handle. \n" );
          sbi_exit_enclave(-1);
        }
      }

      /* -----------------------------------------------------------------------------------------
                                          ONLY FOR WORAM
      --------------------------------------------------------------------------------------------
      If Victim Cache is enabled and this is not the first page replacement that is occuring then 
        a) check if required page 'addr' is in the victim cache or not.
        b) If present (Cache Hit)
            1. Move Page from cache to enclave and update PTE entry
            2. Add the page to page replacement queue
            3. RETURN
        c) If not present (Cache Miss), do nothing at this point.
      ---------------------------------------------------------------------------------------------
      */
      if(v_cache && !first_page_replacement) //first page replacement has occured
      {
        int cache_hit = is_in_victim_cache(addr);
        printf("[runtime] Addr 0x%zx is in victim cache? %d\n", addr, cache_hit);
        if(cache_hit && enable_oram == WORAM)
        {
          move_page_to_enclave_from_cache(addr);
          printf("[runtime] Before validating pte entry of 0x%zx -> 0x%zx", addr, *status_find_address);
          *status_find_address = *status_find_address | PTE_V | PTE_E;
          printf("[runtime] After validating pte entry of 0x%zx -> 0x%zx", addr, *status_find_address);
          uintptr_t va_runtime = __va(((*status_find_address)>>PTE_PPN_SHIFT)<<RISCV_PAGE_BITS);
          if(place_new_page(va_runtime, vpn(addr)<<RISCV_PAGE_BITS)!=ENQUE_SUCCESS)
          {
            printf("[runtime] Page replacement queue full. Can't handle. \n" );
            sbi_exit_enclave(-1);
          }
          return;
        }
      } 

      /* Allocate new page for addr */
      uintptr_t new_alloc_page = 0;
      new_alloc_page = spa_get();// get new page from the list of free pages
      alloc++;
      // printf("[runtime] New page from list of free pages acquired 0x%lx\n", new_alloc_page);


      //if((count_ext+init_num_pages)>=THRESHOLD_PAGES)
      //if(  vpn(addr)%INTERVAL==0 /*&& THRESHOLD_PAGES+current_q_size<free_pages_fr*/ )
      {
        //printf("[runtime] clock_counter = %lu init+all= %lu free_pages_fr = %lu\n", clock_counter,)
        if(place_new_page(  new_alloc_page,vpn(addr)<<RISCV_PAGE_BITS    )!=ENQUE_SUCCESS)
        {
          printf("[runtime] Page replacement queue full. Can't handle. \n" );
          sbi_exit_enclave(-1);
        }
      }
      //uncomment this segmetn



      int extension=0;
      if(source_page_VA!=0)
            extension=0;
      else
      {
        extension=1;
        count_ext++;
      }
      if(enable_oram==NO_ORAM)
      {
        if(extension==1)
        {
          allocate_fresh_page(new_alloc_page, status_find_address);
        }
        else
        {
          pages_read++;
          edge_data_t pkgstr;
          ocall_get_page_contents_from_utm((void*)&pkgstr,(vpn(addr))<<RISCV_PAGE_BITS);
          handle_copy_from_shared((void*)&brought_page,pkgstr.offset,pkgstr.size);
          if(authentication)
          {
            char calc_hmac[HASH_SIZE];
            calculate_hmac(&brought_page,calc_hmac,HASH_SIZE);
            if(!check_hashes((void*)calc_hmac ,HASH_SIZE, (void*)brought_page.hmac ,HASH_SIZE ))
            {
              printf("[runtime] Page corrupted. HMAC integrity check failed.  Fatal error for address 0x%lx\n",brought_page.address);
              sbi_exit_enclave(-1);
            }
          }
          if(confidentiality)
          {
            decrypt_page((uint8_t*)brought_page.data,RISCV_PAGE_SIZE,(uint8_t*)key_aes,(uint8_t*)iv_aes);
            decrypt_page((uint8_t*)&brought_page.ver_num,2*sizeof(uintptr_t),(uint8_t*)key_aes,(uint8_t*)iv_aes);
          }
          if(authentication && version_numbers[vpn(addr)] !=  brought_page.ver_num)
          {
            printf("[runtime] Page corrupted(Possibly a replay attack).  Fatal error for address 0x%lx and brought_page.ver_num= 0x%lx and version_num[]=0x%lx\n",brought_page.address,brought_page.ver_num,version_numbers[vpn(addr)]);
            sbi_exit_enclave(-1);
          }
          // now check version numbers
          memcpy((void*)new_alloc_page,(void*)brought_page.data,RISCV_PAGE_SIZE);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ), PTE_D|PTE_A | PTE_V|PTE_R | PTE_X | PTE_W | PTE_U  | PTE_L );//updating the page table entry with the address of the newly allcated page

          *status_find_address =(*status_find_address)|PTE_V|PTE_E;
          prev_addr_status=status_find_address;
          asm volatile ("fence.i\t\nsfence.vma\t\n");


        }
      }

      if(enable_oram==ENC_PFH)
      {
        if(extension==1)
        {
          memset((void*)new_alloc_page, 0, RISCV_PAGE_SIZE);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ), PTE_D|PTE_A | PTE_R | PTE_X | PTE_W | PTE_U | PTE_V | PTE_L|PTE_E );//updating the page table entry with the address of the newly allcated page
          asm volatile ("fence.i\t\nsfence.vma\t\n");
        }
        else
        {
          pages_read++;
          edge_data_t pkgstr;
          uintptr_t adr[2];
          adr[0]=vpn(addr)<<RISCV_PAGE_BITS;
          adr[1]=0;
          encrypt_page((uint8_t*)adr,2*sizeof(uintptr_t),(uint8_t*)key_aes,(uint8_t*)p_ivs[vpn(addr)].iv);
          ocall_get_page_contents_from_utm_enc_pfh((void*)&pkgstr,adr[0]);
          //pages_at brought_page_at;
          //char brought_page[RISCV_PAGE_SIZE];
          handle_copy_from_shared((void*)&brought_page_at,pkgstr.offset,pkgstr.size);


          char calc_hmac[HASH_SIZE];
          calculate_hmac_for_enc_pfh(&brought_page_at,calc_hmac,HASH_SIZE);
          if(!check_hashes((void*)calc_hmac ,HASH_SIZE, (void*)brought_page_at.hmac ,HASH_SIZE ))
          {
            printf("[runtime] Page corrupted. HMAC integrity check failed.  Fatal error\n");
            sbi_exit_enclave(-1);
          }

          if(confidentiality)
          {
            //printf("[runtime] received encrypted address 0x%lx \n",brought_page.address);
            decrypt_page((uint8_t*)brought_page_at.data,RISCV_PAGE_SIZE,(uint8_t*)key_aes,(uint8_t*)p_ivs[vpn(addr)].iv);
            //printf("[runtime] decrypting\n" );
          }

          decrypt_page((uint8_t*)&brought_page_at.address,2*sizeof(uintptr_t),(uint8_t*)key_aes,(uint8_t*)p_ivs[vpn(addr)].iv);
          memcpy((void*)new_alloc_page,(void*)brought_page_at.data,RISCV_PAGE_SIZE);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ), PTE_A| PTE_D | PTE_R | PTE_X | PTE_W | PTE_U | PTE_V | PTE_L|PTE_E );//updating the page table entry with the address of the newly allcated page
          asm volatile ("fence.i\t\nsfence.vma\t\n");
          if(tracing && (   (pages_written+pages_read)>THRESHOLD_OPS  ||  (real_pages_written+real_pages_read)>THRESHOLD_OPS  ) )
          {
            sbi_exit_enclave(-1);

          }

        }
      }

      else if(enable_oram==PATH_ORAM)
      {
        if(extension==0)
        {
          access('r',vpn(addr),NULL,(char*)new_alloc_page,extension);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ),  PTE_A |PTE_D| PTE_R | PTE_X | PTE_W | PTE_U | PTE_V | PTE_L|PTE_E );//updating the page table entry with the address of the newly allcated page
          asm volatile ("fence.i\t\nsfence.vma\t\n");
        }
        else
        {
          //memset((void*)new_alloc_page,0,RISCV_PAGE_SIZE);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ), PTE_D| PTE_A | PTE_R | PTE_X | PTE_W | PTE_U | PTE_V | PTE_L|PTE_E );//updating the page table entry with the address of the newly allcated page
          asm volatile ("fence.i\t\nsfence.vma\t\n");
        }
      }


      else if(enable_oram==OPAM)
      {
        if(extension==0)
        {
          access_opam('r',vpn(addr),NULL,(char*)new_alloc_page,extension);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ),  PTE_A | PTE_D| PTE_R | PTE_X | PTE_W | PTE_U | PTE_V | PTE_L|PTE_E );//updating the page table entry with the address of the newly allcated page
          asm volatile ("fence.i\t\nsfence.vma\t\n");
          //printf("[runtime] read+write= = %lu\n", (real_pages_written+real_pages_read));

          if(tracing && (   (real_pages_written+real_pages_read)>THRESHOLD_OPS  ) )
          {
            sbi_exit_enclave(-1);

          }


        }
        else
        {
          memset((void*)new_alloc_page,0,RISCV_PAGE_SIZE);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ), PTE_D| PTE_A | PTE_R | PTE_X | PTE_W | PTE_U | PTE_V | PTE_L|PTE_E );//updating the page table entry with the address of the newly allcated page
          asm volatile ("fence.i\t\nsfence.vma\t\n");
        }
      }
      else if(enable_oram==RORAM)
      {
        if(extension==0)
        {
          access_roram('r',vpn(addr),NULL,(char*)new_alloc_page,extension);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ),  PTE_A | PTE_D| PTE_R | PTE_X | PTE_W | PTE_U | PTE_V | PTE_L|PTE_E );//updating the page table entry with the address of the newly allcated page
          asm volatile ("fence.i\t\nsfence.vma\t\n");
          if(tracing && (pages_written+pages_read)>THRESHOLD_OPS)
          {
            sbi_exit_enclave(-1);
          }
        }
        else
        {
          memset((void*)new_alloc_page,0,RISCV_PAGE_SIZE);
          *status_find_address = pte_create( ppn(__pa(new_alloc_page) ), PTE_D| PTE_A | PTE_R | PTE_X | PTE_W | PTE_U | PTE_V | PTE_L|PTE_E );//updating the page table entry with the address of the newly allcated page
          asm volatile ("fence.i\t\nsfence.vma\t\n");
          if(tracing && (pages_written+pages_read)>THRESHOLD_OPS)
          {
            sbi_exit_enclave(-1);
          }
        }
      }
      else if(enable_oram==WORAM)
      {
        /* --------------------------------------------------------------------------------------
                                          ONLY FOR WORAM
        -----------------------------------------------------------------------------------------

        a) If Extension = 1, this means that an extended(malloced) address is being accessed for
           the first time. Allocate a fresh zeroed out page for it. 
        b) If Extention = 0, Get the page from woram. 
           (The Code reaches this point only when there was a cache miss for the page)
        -----------------------------------------------------------------------------------------
        */
        if(extension==1) 
        {
          allocate_fresh_page(new_alloc_page, status_find_address);
          prev_addr_status=status_find_address; //This can be removed, possibly used by nirjhar somewhere
        }
        else
        {
          get_page_from_woram(addr, new_alloc_page, status_find_address, fault_mode, confidentiality, authentication);
          prev_addr_status=status_find_address; //This can be removed, possibly used by nirjhar somewhere
          pages_read++;
        }
      }


      if(debug)
      {
         print_details();
      }
      //check for required number of page faults and print details and stop

      //printf("[runtime] replacement_algo_queue = 0x%lx\n", replacement_algo_queue);
      asm volatile ("fence.i\t\nsfence.vma\t\n");

      if(fault_lim!=0 )
      {
        if(countpf>=fault_lim)
        {
          print_details();
          sbi_exit_enclave(-1);
        }
      }



      return;
    }
    else// actual page fault(seg fault) NOT LEGAL
    {
      //printf("[runtime] A real page fault on 0x%lx\n",addr);// uncomment
      if(debug)
      {
         print_details();
      }
      print_details(); //uncomment
      sbi_exit_enclave(-1);
      //comment This
    }
  printf("PAGE FAULT\n");
  sbi_exit_enclave(-1);
}

//------------------------------------------------------------------------------
uintptr_t rt_handle_sbrk(size_t bytes)
{
    is_rt=1;
    uintptr_t old_pbrk = get_program_break();
    uintptr_t new_pbrk = PAGE_UP(old_pbrk + bytes);
    if(debug && old_pbrk!=new_pbrk)
    {
      printf("[SBREAK] OLD P_BRK = 0x%lx and NEW P_BREAK = 0x%lx(APP) \n",old_pbrk, new_pbrk);
    }
    uintptr_t *root_page_table_addr=get_root_page_table_addr();
    for(uintptr_t extend_addr = old_pbrk; extend_addr<new_pbrk; extend_addr += RISCV_PAGE_SIZE)
    {
      uintptr_t *status_find_address = __walk_create(root_page_table_addr,extend_addr);

      if(status_find_address==0)
      {
        printf("[runtime] Unmapped address. Fatal error during sbreak. Exiting.\n");
        sbi_exit_enclave(-1);
      }
      *status_find_address = 0| PTE_D|PTE_A | PTE_R | PTE_X | PTE_W | PTE_U | PTE_L   ;//updating the page table entry with the address of the newly allcated page

      //page_addr_tbl[vpn(extend_addr)]=(uintptr_t)status_find_address;

      asm volatile ("fence.i\t\nsfence.vma\t\n");
      if(debug)
      {
        uintptr_t *status_find_address_d = __walk(root_page_table_addr,extend_addr);
        if(status_find_address_d==0)
        {
          printf("[RUNTIME] sbreak failed\n" );
        }
        else
        {
          //printf("[RUNTIME] sbreak SUCESS WITH VALUE 0x%lx and value 0x%lx\n",status_find_address_d,*status_find_address_d );
        }
      }
    }

    set_program_break(new_pbrk);
    if(debug)
    {
        //printf("[SBREAK] Done for address 0x%lx\n",new_pbrk);
    }
    is_rt=0;
    //init_timer();
    csr_set(sie, SIE_STIE | SIE_SSIE);
    return old_pbrk;
}
//------------------------------------------------------------------------------
uintptr_t rt_handle_sbrk_rt(size_t bytes)
{
    uintptr_t old_pbrk = get_program_break_rt();
    uintptr_t new_pbrk = PAGE_UP(old_pbrk + bytes);
    if(debug && old_pbrk!=new_pbrk)
    {
      //printf("[SBREAK.RUNTIME] SBREAK CALLED FOR RUNTIME for %s\n\n",sss );
    }
    if(debug && old_pbrk!=new_pbrk)
    {
      //printf("[SBREAK] OLD P_BRK = 0x%lx and NEW P_BREAK = 0x%lx \n",old_pbrk, new_pbrk);
    }
    uintptr_t *root_page_table_addr=get_root_page_table_addr();
    for(uintptr_t extend_addr = old_pbrk; extend_addr<new_pbrk; extend_addr += RISCV_PAGE_SIZE)
    {
      uintptr_t *status_find_address = __walk_create(root_page_table_addr,extend_addr);
      if(status_find_address==0)
      {
        printf("[runtime] Unmapped address. Fatal error during sbreak. Exiting.\n");
        sbi_exit_enclave(-1);
      }
      //*status_find_address = 0| PTE_D|PTE_A | PTE_R | PTE_X | PTE_W | PTE_L   ;//updating the page table entry with the address of the newly allcated page
      uintptr_t new_alloc_page = 0;
      new_alloc_page = spa_get();
      *status_find_address = pte_create( ppn(__pa(new_alloc_page) ), PTE_D|PTE_A | PTE_R | PTE_X | PTE_W | PTE_V | PTE_L );//updating the page table entry with the address of the newly allcated page
      asm volatile ("fence.i\t\nsfence.vma\t\n");
    }
    set_program_break_rt(new_pbrk);
    if(debug)
    {
        //printf("[SBREAK] Done for address(runtime) 0x%lx\n",new_pbrk);
    }
    return old_pbrk;
}
//------------------------------------------------------------------------------
void rt_page_fault(struct encl_ctx_t* ctx)
{

#ifdef FATAL_DEBUG
  unsigned long addr, cause, pc;
  pc = ctx->regs.sepc;
  addr = ctx->sbadaddr;
  cause = ctx->scause;
  //printf("entred inside\n" );
  if(cause==0xf)
    fault_mode=1;//write
  else
    fault_mode=0;//read
  if(addr>0xfffffffffffff)
  {
    printf("[runtime] bad adress fatal 0x%zx\n", addr);
    //show_queue_contents();

    sbi_exit_enclave(-1);
  }

  if(first_fault)
  {
    enclave_options args_user;
    edge_data_t pkgstr;
    dispatch_edgecall_ocall(OCALL_GET_TESTING_PARAMS,NULL,0,&pkgstr,sizeof(edge_data_t),(uintptr_t)&args_user);

    enable_oram=args_user.page_fault_handler;
    authentication=args_user.integrity_protection;
    confidentiality=args_user.confidentiality;
    free_pages_fr=args_user.num_free_pages;
    tracing=args_user.page_addr_tracing;
    debug=args_user.debug_mode;
    //printf("fp=%d\n",free_pages_fr );
  }





   printf("[runtime] page fault at 0x%lx on 0x%lx (scause: 0x%lx)\n ", pc, addr, cause);
  // printf("[runtime] number of pages left in spa = %u\r\n",spa_available());
  // printf("[runtime] queue size = %lu\r\n",get_queue_size());
  is_rt=1;
  handle_page_fault((uintptr_t) addr,0);
  is_rt=0;
  //init_timer();
#endif
}
//------------------------------------------------------------------------------
