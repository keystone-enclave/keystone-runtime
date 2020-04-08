//-------------------------------------Declaring required data structures and macros--------------
#include "rt_util.h"
//#define pow(a,b) (1<<b)

#define OCALL_READ_BUCKETS 10
#define OCALL_WRITE_BUCKETS 0



#define ORAM_STASH_SIZE 9500//6000
#define ORAM_TREE_SIZE 70000//70000 87390 1400

typedef struct Block
{
    uintptr_t address;
    uintptr_t version;
    char data[BLOCK_SIZE];
    uint8_t iv[16];// IV is length 16 bytes
    char p_hash[32];// 32 bytes of hmac is used
} Block;

typedef struct Bucket
{
    Block blocks[4];
}Bucket;

//extern Block S[ORAM_STASH_SIZE];
//extern Block Sg[ORAM_STASH_SIZE];

extern Block *S;
extern Block *Sg;
extern int S_len;
extern int Sg_len;
extern int treearray_len;



typedef struct Block_md
{
    uintptr_t address;
    //uintptr_t version;
    //uint8_t iv[16];// IV is length 16 bytes
    //char p_hash[32];// 32 bytes of hmac is used
} Block_md;

typedef struct Bucket_md
{
    Block_md blocks[4];
}Bucket_md;


extern Bucket_md buc_i_po_md;
extern Bucket_md *tree_po_md;












//extern char firstimeaccess[ARRAY_SIZE];
extern Bucket buc_i;
//-----------------------------public functions-----------------------
void access(char op, int a, char datastar[BLOCK_SIZE+1], char ret_buf[ARRAY_SIZE],int extension);
void initalize_oram();
