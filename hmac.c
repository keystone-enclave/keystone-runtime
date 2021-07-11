// Adapted from Yubico's HMAC implementation. Licensed under BSD 2-clause
// license. Copyright (c) 2006-2013 Yubico AB

/**************************** hmac.c ****************************/
/******************** See RFC 4634 for details ******************/
/*
 *  Description:
 *      This file implements the HMAC algorithm (Keyed-Hashing for
 *      Message Authentication, RFC2104), expressed in terms of the
 *      various SHA algorithms.
 */

#ifdef USE_PAGE_HASH

#include "hmac.h"

/*
 *  hmac
 *
 *  Description:
 *      This function will compute an HMAC message digest.
 *
 *  Parameters:
 *      key: [in]
 *          The secret shared key.
 *      key_len: [in]
 *          The length of the secret shared key.
 *      message_array: [in]
 *          An array of characters representing the message.
 *      length: [in]
 *          The length of the message in message_array
 *      digest: [out]
 *          Where the digest is returned.
 *          NOTE: The length of the digest is determined by
 *              the value of whichSha.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hmac(
    const unsigned char* text, int text_len, const unsigned char* key,
    int key_len, uint8_t digest[_USHAHashSize]) {
  HMACContext ctx;
  return hmacReset(&ctx, key, key_len) || hmacInput(&ctx, text, text_len) ||
         hmacResult(&ctx, digest);
}

/*
 *  hmacReset
 *
 *  Description:
 *      This function will initialize the hmacContext in preparation
 *      for computing a new HMAC message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      key: [in]
 *          The secret shared key.
 *      key_len: [in]
 *          The length of the secret shared key.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hmacReset(HMACContext* ctx, const unsigned char* key, int key_len) {
  int i, blocksize, hashsize;

  /* inner padding - key XORd with ipad */
  unsigned char k_ipad[USHA_Message_Block_Size];

  /* temporary buffer when keylen > blocksize */
  unsigned char tempkey[_USHAHashSize];

  if (!ctx) return shaNull;

  blocksize = ctx->blockSize = USHABlockSize();
  hashsize = ctx->hashSize = USHAHashSize();

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if (key_len > blocksize) {
    USHAContext tctx;
    int err = USHAReset(&tctx) || USHAInput(&tctx, key, key_len) ||
              USHAResult(&tctx, tempkey);
    if (err != shaSuccess) return err;

    key     = tempkey;
    key_len = hashsize;
  }

  /*
   * The HMAC transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, text))
   *
   * where K is an n byte key.
   * ipad is the byte 0x36 repeated blocksize times
   * opad is the byte 0x5c repeated blocksize times
   * and text is the data being protected.
   */

  /* store key into the pads, XOR'd with ipad and opad values */
  for (i = 0; i < key_len; i++) {
    k_ipad[i]      = key[i] ^ 0x36;
    ctx->k_opad[i] = key[i] ^ 0x5c;
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for (; i < blocksize; i++) {
    k_ipad[i]      = 0x36;
    ctx->k_opad[i] = 0x5c;
  }

  /* perform inner hash */
  /* init context for 1st pass */
  return USHAReset(&ctx->shaContext) ||
         /* and start with inner pad */
         USHAInput(&ctx->shaContext, k_ipad, blocksize);
}

/*
 *  hmacInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The HMAC context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hmacInput(HMACContext* ctx, const unsigned char* text, int text_len) {
  if (!ctx) return shaNull;
  /* then text of datagram */
  return USHAInput(&ctx->shaContext, text, text_len);
}

/*
 * HMACResult
 *
 * Description:
 *   This function will return the N-byte message digest into the
 *   Message_Digest array provided by the caller.
 *   NOTE: The first octet of hash is stored in the 0th element,
 *      the last octet of hash in the Nth element.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the HMAC hash.
 *   digest: [out]
 *     Where the digest is returned.
 *   NOTE 2: The length of the hash is determined by the value of
 *      whichSha that was passed to hmacReset().
 *
 * Returns:
 *   sha Error Code.
 *
 */
int
hmacResult(HMACContext* ctx, uint8_t* digest) {
  if (!ctx) return shaNull;

  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  return USHAResult(&ctx->shaContext, digest) ||
         /* perform outer SHA */
         /* init context for 2nd pass */
         USHAReset(&ctx->shaContext) ||
         /* start with outer pad */
         USHAInput(&ctx->shaContext, ctx->k_opad, ctx->blockSize) ||
         /* then results of 1st hash */
         USHAInput(&ctx->shaContext, digest, ctx->hashSize) ||
         /* finish up 2nd pass */
         USHAResult(&ctx->shaContext, digest);
}

#endif  // USE_PAGE_HASH
