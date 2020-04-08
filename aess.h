
#define CBC 1



#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only


#define AES_KEYLEN 16   // Key length in bytes
#define AES_keyExpSize 176


struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];

  uint8_t Iv[AES_BLOCKLEN];

};



void AES_init_ctx_ivs(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_CBC_decrypt_buffers(struct AES_ctx* ctx, uint8_t* buf,  uint32_t length);
void AES_CBC_encrypt_buffers(struct AES_ctx* ctx, uint8_t* buf,  uint32_t length);
void encrypt_page(uint8_t* in, uintptr_t in_size,uint8_t *key,uint8_t *iv);
void decrypt_page(uint8_t* in, uintptr_t in_size,uint8_t *key,uint8_t *iv);
extern uint8_t key[16];// AES key length is 16 bytes
extern uint8_t key_chacha[32];
