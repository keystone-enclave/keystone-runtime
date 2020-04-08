#include "rt_util.h"


#define OCALL_RORAM_READ_BUCKET_METADATA 19
#define OCALL_RORAM_READ_BLOCK 20
#define OCALL_RORAM_READ_BUCKET 21
#define OCALL_RORAM_WRITE_BUCKET_METADATA 22
#define OCALL_RORAM_WRITE_BLOCK 23
#define OCALL_RORAM_WRITE_BUCKET 24

#define STASH_SIZE_RORAM 9500//6000 10000
#define RORAM_BUCKET_SIZE 64//64 17
//16 8 4
#define RORAM_TREE_SIZE 4400//4400 4690 21900

#define RORAM_TREE_TOP_SIZE  20//20 75 345

#define CACHING_LEVEL  2//2 is the required one

#define MIN_HASH_NUM 8//8 original


typedef struct Block_roram
{
    uintptr_t address;
    uintptr_t version;
    char data[RISCV_PAGE_SIZE];
    uint8_t iv[16];// IV is length 16 bytes
    char p_hash[32];// 32 bytes of hmac is used
} Block_roram;


typedef struct Bucket_roram
{
    Block_roram blocks[RORAM_BUCKET_SIZE];
} Bucket_roram;


typedef struct Bucket_roram_md
{
    uintptr_t count;
    char valids[RORAM_BUCKET_SIZE];
    uintptr_t addr[RORAM_BUCKET_SIZE];
    //uintptr_t leaves[RORAM_BUCKET_SIZE];
    uint8_t ptrs[RORAM_BUCKET_SIZE];
    //uint8_t iv[16];// IV is length 16 bytes
    //char p_hash[32];// 32 bytes of hmac is used
    char is_hash[RORAM_BUCKET_SIZE];//// extra for paper
} Bucket_roram_md;

extern Bucket_roram_md buc_i_md_ro;


extern Block_roram  blk_i_d_ro;
//extern Bucket_roram buc_i_d_ro;
extern Bucket_roram *buc_i_d_ro;


//extern Block_roram S_roram[STASH_SIZE_RORAM];
Block_roram *S_roram;// stash pointer
//extern Block_roram Sg_roram[STASH_SIZE_RORAM];

extern int S_roram_len;
extern int Sg_roram_len;

//extern Bucket_roram_md S_roram_md[STASH_SIZE_RORAM];
Bucket_roram_md *S_roram_md;// not used
//extern Bucket_roram_md Sg_roram_md[STASH_SIZE_RORAM];
extern int A;
extern int S_o;
extern int G;
extern int round;

//extern Bucket_roram_md tree_roram_md[RORAM_TREE_SIZE];
Bucket_roram_md *tree_roram_md;

Bucket_roram *tree_roram_tree_top;

void initialize_roram();
void access_roram(char op, int a, char *datastar, char *ret_buf,int extension);
