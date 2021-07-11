// Adapted from Yubico's HMAC implementation. Licensed under BSD 2-clause
// license. Copyright (c) 2006-2013 Yubico AB

#ifndef _SHA_H_
#define _SHA_H_

#include <stdint.h>

#ifndef _SHA_enum_
#define _SHA_enum_
/*
 *  All SHA functions return one of these values.
 */
enum {
  shaSuccess = 0,
  shaNull,         /* Null pointer parameter */
  shaInputTooLong, /* input data too long */
  shaStateError,   /* called Input after FinalBits or Result */
  shaBadParam      /* passed a bad parameter */
};
#endif /* _SHA_enum_ */

#include "sha256.h"
#define _USHAHashSize 32
#define USHA_Message_Block_Size 64
#define USHAReset(...) (sha256_init(__VA_ARGS__), 0)
#define USHAInput(...) (sha256_update(__VA_ARGS__), 0)
#define USHAResult(...) (sha256_final(__VA_ARGS__), 0)
#define USHABlockSize() USHA_Message_Block_Size
#define USHAHashSize() _USHAHashSize
#define USHAHashSizeBits() (USHAHashSize() * 8)

/*
 *  This structure will hold context information for the HMAC
 *  keyed hashing operation.
 */
typedef struct HMACContext {
  int hashSize;          /* hash size of SHA being used */
  int blockSize;         /* block size of SHA being used */
  SHA256_CTX shaContext; /* SHA context */
  unsigned char k_opad[USHA_Message_Block_Size];
  /* outer padding - key XORd with opad */
} HMACContext;

typedef SHA256_CTX USHAContext;

/*
 *  Function Prototypes
 */

/*
 * HMAC Keyed-Hashing for Message Authentication, RFC2104,
 * for all SHAs.
 * This interface allows a fixed-length text input to be used.
 */
extern int
hmac(
    const unsigned char* text,      /* pointer to data stream */
    int text_len,                   /* length of data stream */
    const unsigned char* key,       /* pointer to authentication key */
    int key_len,                    /* length of authentication key */
    uint8_t digest[_USHAHashSize]); /* caller digest to fill in */

/*
 * HMAC Keyed-Hashing for Message Authentication, RFC2104,
 * for all SHAs.
 * This interface allows any length of text input to be used.
 */
extern int
hmacReset(HMACContext* ctx, const unsigned char* key, int key_len);
extern int
hmacInput(HMACContext* ctx, const unsigned char* text, int text_len);

extern int
hmacResult(HMACContext* ctx, uint8_t digest[_USHAHashSize]);

#endif /* _SHA_H_ */
