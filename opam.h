#include "rt_util.h"


#define OCALL_OPAM_READ_BUCKETS 11
#define OCALL_OPAM_WRITE_BUCKETS 12
#define OCALL_OPAM_READ_BUCKETS_MD 13
#define OCALL_OPAM_WRITE_BUCKETS_MD 14
#define OCALL_OPAM_READ_BUCKETS_D 15
#define OCALL_OPAM_WRITE_BUCKETS_D 16

#define OPAM_STASH_SIZE 9500
#define OPAM_TREE_SIZE  262144 // 1<<18

typedef struct Block_Opam_md
{
    uintptr_t address;
    uintptr_t version;
    uintptr_t tree_index;
    uintptr_t stash_index;
    uint8_t iv[16];// IV is length 16 bytes
    char p_hash[32];// 32 bytes of hmac is used
    uint8_t ivd[16];// IV is length 16 bytes
    char p_hash_d[32];
} Block_Opam_md;

typedef struct Bucket_opam_md
{
    Block_Opam_md blocks[1];

}Bucket_opam_md;

//extern Block_Opam_md S_opam_md[STASH_SIZE];
extern Block_Opam_md *S_opam_md;

//extern Block_Opam_md Sg_opam_md[STASH_SIZE];
extern int S_opam_md_len;
//extern int Sg_opam_md_len;
extern int treearray_opam_md_len;

extern Bucket_opam_md buc_i_md;



typedef struct Block_Opam
{
    char data[BLOCK_SIZE];
} Block_Opam;

typedef struct Bucket_opam
{
    Block_Opam blocks[1];
}Bucket_opam;

extern int treearray_opam_len;

extern Bucket_opam buc_i_d;

//-----------------------------public functions-----------------------
int access_opam(char op, int a, char datastar[BLOCK_SIZE+1], char ret_buf[ARRAY_SIZE],int extension);
void initialize_opam();
void remap_all();
