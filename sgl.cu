#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include "sgl.h"


#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Define the SHA shift, rotate left, and rotate right macros */
#define SHA256_SHR(bits,word)      ((word) >> (bits))
#define SHA256_ROTL(bits,word)                         \
  (((word) << (bits)) | ((word) >> (32-(bits))))
#define SHA256_ROTR(bits,word)                         \
  (((word) >> (bits)) | ((word) << (32-(bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA256_SIGMA0(word)   \
  (SHA256_ROTR( 2,word) ^ SHA256_ROTR(13,word) ^ SHA256_ROTR(22,word))
#define SHA256_SIGMA1(word)   \
  (SHA256_ROTR( 6,word) ^ SHA256_ROTR(11,word) ^ SHA256_ROTR(25,word))
#define SHA256_sigma0(word)   \
  (SHA256_ROTR( 7,word) ^ SHA256_ROTR(18,word) ^ SHA256_SHR( 3,word))
#define SHA256_sigma1(word)   \
  (SHA256_ROTR(17,word) ^ SHA256_ROTR(19,word) ^ SHA256_SHR(10,word))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static uint32_t addTemp;
#define SHA224_256AddLength(context, length)               \
  (addTemp = (context)->Length_Low, (context)->Corrupted = \
    (((context)->Length_Low += (length)) < addTemp) &&     \
    (++(context)->Length_High == 0) ? shaInputTooLong :    \
                                      (context)->Corrupted )

/* Local Function Prototypes */
static void SHA224_256ProcessMessageBlock(SHA256Context *context);
static void SHA224_256Finalize(SHA256Context *context,
  uint8_t Pad_Byte);
static void SHA224_256PadMessage(SHA256Context *context,
  uint8_t Pad_Byte);

/* Initial Hash Values: FIPS 180-3 section 5.3.3 */
static uint32_t SHA256_H0[SHA256HashSize/4] = {
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

/*
 * SHA256Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_array[ ]: [in]
 *     An array of octets representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA256Input(SHA256Context *context, const uint8_t *message_array,
    unsigned int length)
{
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
            *message_array;

    if ((SHA224_256AddLength(context, 8) == shaSuccess) &&
      (context->Message_Block_Index == SHA256_Message_Block_Size))
      SHA224_256ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;

}


/*
 * SHA224_256Reset
 *
 * Description:
 *   This helper function will initialize the SHA256Context in
 *   preparation for computing a new SHA-224 or SHA-256 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *   H0[ ]: [in]
 *     The initial hash value array to use.
 *
 * Returns:
 *   sha Error Code.
 */
static int SHA256Reset(SHA256Context *context)
{
  if (!context) return shaNull;

  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index  = 0;

  context->Intermediate_Hash[0] = SHA256_H0[0];
  context->Intermediate_Hash[1] = SHA256_H0[1];
  context->Intermediate_Hash[2] = SHA256_H0[2];
  context->Intermediate_Hash[3] = SHA256_H0[3];
  context->Intermediate_Hash[4] = SHA256_H0[4];
  context->Intermediate_Hash[5] = SHA256_H0[5];
  context->Intermediate_Hash[6] = SHA256_H0[6];
  context->Intermediate_Hash[7] = SHA256_H0[7];

  context->Computed  = 0;
  context->Corrupted = shaSuccess;

  return shaSuccess;
}

/*
 * SHA224_256ProcessMessageBlock
 *
 * Description:
 *   This helper function will process the next 512 bits of the
 *   message stored in the Message_Block array.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *
 * Returns:
 *   Nothing.
 *
 * Comments:
 *   Many of the variable names in this code, especially the
 *   single character names, were used because those were the
 *   names used in the Secure Hash Standard.
 */
static void SHA224_256ProcessMessageBlock(SHA256Context *context)
{
  /* Constants defined in FIPS 180-3, section 4.2.2 */
  static const uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
      0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
      0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };
  int        t, t4;                   /* Loop counter */
  uint32_t   temp1, temp2;            /* Temporary word value */
  uint32_t   W[64];                   /* Word sequence */
  uint32_t   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = t4 = 0; t < 16; t++, t4 += 4)
    W[t] = (((uint32_t)context->Message_Block[t4]) << 24) |
           (((uint32_t)context->Message_Block[t4 + 1]) << 16) |
           (((uint32_t)context->Message_Block[t4 + 2]) << 8) |
           (((uint32_t)context->Message_Block[t4 + 3]));

  for (t = 16; t < 64; t++)
    W[t] = SHA256_sigma1(W[t-2]) + W[t-7] +
        SHA256_sigma0(W[t-15]) + W[t-16];

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = 0; t < 64; t++) {
    temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
    temp2 = SHA256_SIGMA0(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;

  context->Message_Block_Index = 0;
}

/*
 * SHA224_256Finalize
 *
 * Description:
 *   This helper function finishes off the digest calculations.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   sha Error Code.
 */
static void SHA224_256Finalize(SHA256Context *context,
    uint8_t Pad_Byte)
{
  int i;
  SHA224_256PadMessage(context, Pad_Byte);
  /* message may be sensitive, so clear it out */
  for (i = 0; i < SHA256_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
  context->Length_High = 0;     /* and clear length */
  context->Length_Low = 0;
  context->Computed = 1;
}

/*
 * SHA224_256PadMessage
 *
 * Description:
 *   According to the standard, the message must be padded to the next
 *   even multiple of 512 bits.  The first padding bit must be a '1'.
 *   The last 64 bits represent the length of the original message.
 *   All bits in between should be 0.  This helper function will pad
 *   the message according to those rules by filling the
 *   Message_Block array accordingly.  When it returns, it can be
 *   assumed that the message digest has been computed.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to pad.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   Nothing.
 */
static void SHA224_256PadMessage(SHA256Context *context,
    uint8_t Pad_Byte)
{

  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA256_Message_Block_Size-8)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA256_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;
    SHA224_256ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA256_Message_Block_Size-8))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 8 octets
   */
  context->Message_Block[56] = (uint8_t)(context->Length_High >> 24);
  context->Message_Block[57] = (uint8_t)(context->Length_High >> 16);
  context->Message_Block[58] = (uint8_t)(context->Length_High >> 8);
  context->Message_Block[59] = (uint8_t)(context->Length_High);
  context->Message_Block[60] = (uint8_t)(context->Length_Low >> 24);
  context->Message_Block[61] = (uint8_t)(context->Length_Low >> 16);
  context->Message_Block[62] = (uint8_t)(context->Length_Low >> 8);
  context->Message_Block[63] = (uint8_t)(context->Length_Low);

  SHA224_256ProcessMessageBlock(context);
}

/*
 * SHA224_256ResultN
 *
 * Description:
 *   This helper function will return the 224-bit or 256-bit message
 *   digest into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 27/31.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *   HashSize: [in]
 *     The size of the hash, either 28 or 32.
 *
 * Returns:
 *   sha Error Code.
 */
static int SHA256Result(SHA256Context *context,
    uint8_t Message_Digest[SHA256HashSize])
{
  int i;

  if (!context) return shaNull;
  if (!Message_Digest) return shaNull;
  if (context->Corrupted) return context->Corrupted;

  if (!context->Computed)
    SHA224_256Finalize(context, 0x80);

  for (i = 0; i < SHA256HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));

  return shaSuccess;
}

int hmacReset(HMACContext *context,
    const unsigned char *key, int key_len)
{
  int i, blocksize, hashsize, ret;

  /* inner padding - key XORd with ipad */
  unsigned char k_ipad[SHA256_Message_Block_Size];

  /* temporary buffer when keylen > blocksize */
  unsigned char tempkey[SHA256HashSize];


  if (!context) return shaNull;
  context->Computed = 0;
  context->Corrupted = shaSuccess;

  blocksize = context->blockSize = SHA256_Message_Block_Size;
  hashsize = context->hashSize = SHA256HashSize;

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if (key_len > blocksize) {
    SHA256Context tcontext;
    int err = SHA256Reset(&tcontext) ||
              SHA256Input(&tcontext, key, key_len) ||
              SHA256Result(&tcontext, tempkey);
    if (err != shaSuccess) return err;

    key = tempkey;
    key_len = hashsize;
  }

  /*
   * The HMAC transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, text))
   *
   * where K is an n byte key, 0-padded to a total of blocksize bytes,
   * ipad is the byte 0x36 repeated blocksize times,
   * opad is the byte 0x5c repeated blocksize times,
   * and text is the data being protected.
   */

  /* store key into the pads, XOR'd with ipad and opad values */
  for (i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36;
    context->k_opad[i] = key[i] ^ 0x5c;
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for ( ; i < blocksize; i++) {
    k_ipad[i] = 0x36;
    context->k_opad[i] = 0x5c;
  }

  /* perform inner hash */
  /* init context for 1st pass */
  ret = SHA256Reset(&context->shaContext) ||
        /* and start with inner pad */
        SHA256Input(&context->shaContext, k_ipad, blocksize);
  return context->Corrupted = ret;
}

int hmacInput(HMACContext *context, const unsigned char *text,
    int text_len)
{
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  /* then text of datagram */
  return context->Corrupted =
    SHA256Input(&context->shaContext, text, text_len);
}

int hmacResult(HMACContext *context, uint8_t *digest)
{
  int ret;
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;

  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  ret =
    SHA256Result(&context->shaContext, digest) ||

         /* perform outer SHA */
         /* init context for 2nd pass */
         SHA256Reset(&context->shaContext) ||

         /* start with outer pad */
         SHA256Input(&context->shaContext, context->k_opad,
                   context->blockSize) ||

         /* then results of 1st hash */
         SHA256Input(&context->shaContext, digest, context->hashSize) ||
         /* finish up 2nd pass */
         SHA256Result(&context->shaContext, digest);

  context->Computed = 1;
  return context->Corrupted = ret;
}

int hmac(
    const unsigned char *message_array, int length,
    const unsigned char *key, int key_len,
    uint8_t digest[SHA256HashSize])
{
  HMACContext context;
  return hmacReset(&context, key, key_len) ||
         hmacInput(&context, message_array, length) ||
         hmacResult(&context, digest);
}

void HexToBytes(const std::string& hex, unsigned char * &newsalt) {
    for (unsigned int i = 0; i < hex.length(); i += 2) {
      std::string byteString = hex.substr(i, 2);
      char byte = (char) strtol(byteString.c_str(), NULL, 16);
      newsalt[i/2] = byte;
    }
}

// Compile with: nvcc sgl.cu -o build/sgl

void pbkdf2(std::string password, std::string salt, uint8_t digest[SHA256HashSize]) {

    // Hashing function will be sha256. hlen will therefore be 32, same as keyLen.
    // Desired key length will be 32.
    // iterations will be 100000.
    int rounds = 100000;
    unsigned char * pw = (unsigned char *)password.c_str();
    int pwsize = password.size();

    uint8_t dk[SHA256HashSize];

    unsigned char * newsalt = (unsigned char *)malloc(16);
    HexToBytes(salt, newsalt);
    newsalt[16] = (1 >> 24) & 0xff;
    newsalt[17] = (1 >> 16) & 0xff;
    newsalt[18] = (1 >> 8) & 0xff;
    newsalt[19] = (1 >> 0) & 0xff;

    hmac(
        newsalt,
        20,
        pw,
        pwsize,
        digest
    );

    for (int a = 0; a < 32; a++) {
        dk[a] = digest[a];
    }

    uint8_t newdigest[32];
    uint8_t runningkey[32];
    memcpy(runningkey, dk, 32);
    for (int i = 2; i <= rounds; i++) {
        hmac(
            runningkey,
            32,
            pw,
            pwsize,
            newdigest
        );

        for (int j = 0; j < 32; j++) {
            dk[j] = dk[j] ^ newdigest[j];
            runningkey[j] = newdigest[j];
        }
    }

    for (int b = 0; b < 32; b++) {
        digest[b] = dk[b];
    }
}



int main(void)
{
    std::cout << "Running" << std::endl;

    std::string testpw = "glassy ubiquity absence";
    std::string testsalt = "2db485972861e63479528bf382d1bc04";
    std::string testhash = "3c453512d47b37352bf2c5c1408ea4d9f46c48878782843a685c0c7e54232ba0";

    unsigned char * newsalt = (unsigned char *)malloc(16);
    HexToBytes(testsalt, newsalt);

    uint8_t prk[SHA256HashSize];

    hmac(
        newsalt,
        16,
        (unsigned char *)testpw.c_str(),
        testpw.size(),
        prk
    );

    //char * hex_str = "";
    //hex_str = itoa(*prk, hex_str, 16);
    //sprintf(hex_str.c_str(),"%x", *prk);
    
    for (int i = 0; i < SHA256HashSize; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(prk[i]);
    }
    std::cout << std::endl;

    std::cout << "hmac Done" << std::endl;

    uint8_t pdprk[SHA256HashSize];

    pbkdf2(testpw, testsalt, pdprk);

    for (int i = 0; i < SHA256HashSize; i++) {
        //printf("%x", prk[i]);
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pdprk[i]);
    }
    std::cout << std::endl;

    std::cout << "pbkdf2 Done" << std::endl;

    return 0;
}

