#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>

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

/* Local Function Prototypes */
__host__ __device__ void SHA224_256ProcessMessageBlock(SHA256Context *context);
__host__ __device__  void SHA224_256Finalize(SHA256Context *context,
  uint8_t Pad_Byte);
__host__ __device__  void SHA224_256PadMessage(SHA256Context *context,
  uint8_t Pad_Byte);


// How many to run in parallel.
const int IN_PARALLEL = 256;

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
 __host__ __device__ void SHA256Input(SHA256Context *context, const uint8_t *message_array,
    unsigned int length)
{
  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
            *message_array;

    uint32_t addTemp = context->Length_Low;
    if (((context->Length_Low += 8) < addTemp) && (++context->Length_High == 0)) {
      context->Corrupted = shaInputTooLong;
    }

    if ((context->Corrupted == shaSuccess) &&
      (context->Message_Block_Index == SHA256_Message_Block_Size))
      SHA224_256ProcessMessageBlock(context);

    message_array++;
  }
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
 __host__ __device__ void SHA256Reset(SHA256Context *context)
{
  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index  = 0;

  context->Intermediate_Hash[0] = 0x6A09E667;
  context->Intermediate_Hash[1] = 0xBB67AE85;
  context->Intermediate_Hash[2] = 0x3C6EF372;
  context->Intermediate_Hash[3] = 0xA54FF53A;
  context->Intermediate_Hash[4] = 0x510E527F;
  context->Intermediate_Hash[5] = 0x9B05688C;
  context->Intermediate_Hash[6] = 0x1F83D9AB;
  context->Intermediate_Hash[7] = 0x5BE0CD19;

  context->Computed  = 0;
  context->Corrupted = shaSuccess;
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
 __host__ __device__ void SHA224_256ProcessMessageBlock(SHA256Context *context)
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
 __host__ __device__ void SHA224_256Finalize(SHA256Context *context,
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
 __host__ __device__ void SHA224_256PadMessage(SHA256Context *context,
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
 __host__ __device__ void SHA256Result(SHA256Context *context,
    uint8_t Message_Digest[SHA256HashSize])
{
  int i;
  SHA224_256Finalize(context, 0x80);

  for (i = 0; i < SHA256HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));
}


__host__ __device__ void hmac_combined(
  const unsigned char *message_array, int length,
  const unsigned char *key, int key_len,
  uint8_t digest[SHA256HashSize])
{
  int i;

  unsigned char k_ipad[SHA256_Message_Block_Size];
  unsigned char k_opad[SHA256_Message_Block_Size];

  for (i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36;
    k_opad[i] = key[i] ^ 0x5c;
  }
  for ( ; i < SHA256_Message_Block_Size; i++) {
    k_ipad[i] = 0x36;
    k_opad[i] = 0x5c;
  }

  SHA256Context shaContext;
  SHA256Context * context = &shaContext; 

  // Reset
  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index  = 0;
  context->Intermediate_Hash[0] = 0x6A09E667;
  context->Intermediate_Hash[1] = 0xBB67AE85;
  context->Intermediate_Hash[2] = 0x3C6EF372;
  context->Intermediate_Hash[3] = 0xA54FF53A;
  context->Intermediate_Hash[4] = 0x510E527F;
  context->Intermediate_Hash[5] = 0x9B05688C;
  context->Intermediate_Hash[6] = 0x1F83D9AB;
  context->Intermediate_Hash[7] = 0x5BE0CD19;
  context->Computed  = 0;
  context->Corrupted = shaSuccess;

  //SHA256Input(&shaContext, k_ipad, SHA256_Message_Block_Size);
  for (i = 0; i < SHA256_Message_Block_Size; i++) {
    context->Message_Block[context->Message_Block_Index++] = k_ipad[i];

    uint32_t addTemp = context->Length_Low;
    if (((context->Length_Low += 8) < addTemp) && (++context->Length_High == 0)) {
      context->Corrupted = shaInputTooLong;
    }

    if ((context->Corrupted == shaSuccess) &&
      (context->Message_Block_Index == SHA256_Message_Block_Size))
      SHA224_256ProcessMessageBlock(context);
  }

  //SHA256Input(&shaContext, message_array, length);
  for (i = 0; i < length; i++) {
    context->Message_Block[context->Message_Block_Index++] = message_array[i];

    uint32_t addTemp = context->Length_Low;
    if (((context->Length_Low += 8) < addTemp) && (++context->Length_High == 0)) {
      context->Corrupted = shaInputTooLong;
    }

    if ((context->Corrupted == shaSuccess) &&
      (context->Message_Block_Index == SHA256_Message_Block_Size))
      SHA224_256ProcessMessageBlock(context);
  }

  // Result
  SHA224_256Finalize(context, 0x80);
  for (i = 0; i < SHA256HashSize; ++i) {
    digest[i] = (uint8_t)(context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));
  }

  // Reset
  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index  = 0;
  context->Intermediate_Hash[0] = 0x6A09E667;
  context->Intermediate_Hash[1] = 0xBB67AE85;
  context->Intermediate_Hash[2] = 0x3C6EF372;
  context->Intermediate_Hash[3] = 0xA54FF53A;
  context->Intermediate_Hash[4] = 0x510E527F;
  context->Intermediate_Hash[5] = 0x9B05688C;
  context->Intermediate_Hash[6] = 0x1F83D9AB;
  context->Intermediate_Hash[7] = 0x5BE0CD19;
  context->Computed  = 0;
  context->Corrupted = shaSuccess;

  //SHA256Input(&shaContext, k_opad, SHA256_Message_Block_Size);
  for (i = 0; i < SHA256_Message_Block_Size; i++) {
    context->Message_Block[context->Message_Block_Index++] = k_opad[i];

    uint32_t addTemp = context->Length_Low;
    if (((context->Length_Low += 8) < addTemp) && (++context->Length_High == 0)) {
      context->Corrupted = shaInputTooLong;
    }

    if ((context->Corrupted == shaSuccess) &&
      (context->Message_Block_Index == SHA256_Message_Block_Size))
      SHA224_256ProcessMessageBlock(context);
  }

  //SHA256Input(&shaContext, digest, SHA256HashSize);
  for (i = 0; i < SHA256HashSize; i++) {
    context->Message_Block[context->Message_Block_Index++] = digest[i];

    uint32_t addTemp = context->Length_Low;
    if (((context->Length_Low += 8) < addTemp) && (++context->Length_High == 0)) {
      context->Corrupted = shaInputTooLong;
    }

    if ((context->Corrupted == shaSuccess) &&
      (context->Message_Block_Index == SHA256_Message_Block_Size))
      SHA224_256ProcessMessageBlock(context);
  }

  // Result
  SHA224_256Finalize(context, 0x80);
  for (i = 0; i < SHA256HashSize; ++i) {
    digest[i] = (uint8_t)(context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));
  }
}


__host__ __device__ void hmac(
    const unsigned char *message_array, int length,
    const unsigned char *key, int key_len,
    uint8_t digest[SHA256HashSize])
{
  int i;

  /* inner padding - key XORd with ipad */
  unsigned char k_ipad[SHA256_Message_Block_Size];

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

   unsigned char k_opad[SHA256_Message_Block_Size];

  /* store key into the pads, XOR'd with ipad and opad values */
  for (i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36;
    k_opad[i] = key[i] ^ 0x5c;
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for ( ; i < SHA256_Message_Block_Size; i++) {
    k_ipad[i] = 0x36;
    k_opad[i] = 0x5c;
  }

  SHA256Context shaContext; 

  /* perform inner hash */
  /* init context for 1st pass */
  SHA256Reset(&shaContext);
  /* and start with inner pad */
  SHA256Input(&shaContext, k_ipad, SHA256_Message_Block_Size);

  // Run on the message array.
  SHA256Input(&shaContext, message_array, length);
  
  SHA256Result(&shaContext, digest);
  /* perform outer SHA */
  /* init context for 2nd pass */
  SHA256Reset(&shaContext);
  /* start with outer pad */
  SHA256Input(&shaContext, k_opad, SHA256_Message_Block_Size);
  /* then results of 1st hash */
  SHA256Input(&shaContext, digest, SHA256HashSize);
  /* finish up 2nd pass */
  SHA256Result(&shaContext, digest);
}

void HexToBytes(const std::string& hex, unsigned char * &newsalt) {
    for (unsigned int i = 0; i < hex.length(); i += 2) {
      std::string byteString = hex.substr(i, 2);
      char byte = (char) strtol(byteString.c_str(), NULL, 16);
      newsalt[i/2] = byte;
    }
}

// Compile with: nvcc sgl.cu -o build/sgl

__host__ __device__ void pbkdf2(unsigned char * password, int pwsize, unsigned char * salt, uint8_t digest[SHA256HashSize]) {

    // Hashing function will be sha256. hlen will therefore be 32, same as keyLen.
    // Desired key length will be 32.
    // iterations will be 100000.
    int rounds = 100000;

    hmac(
        salt,
        20,
        password,
        pwsize,
        digest
    );

    uint8_t newdigest[32];
    uint8_t runningkey[32];

    memcpy(runningkey, digest, 32);
    /*for (int i = 0; i < 32; i++) {
      runningkey[i] = newdigest[i];
    }*/

    for (int i = 2; i <= rounds; i++) {
        //hmac(runningkey, 32, password, pwsize, newdigest);
        hmac_combined(runningkey, 32, password, pwsize, newdigest);

        for (int j = 0; j < 32; j++) {
            digest[j] = digest[j] ^ newdigest[j];
            runningkey[j] = newdigest[j];
        }
    }
}

void createPbkdfSalt(unsigned char* newsalt, std::string salt) {
  HexToBytes(salt, newsalt);
  newsalt[16] = (1 >> 24) & 0xff;
  newsalt[17] = (1 >> 16) & 0xff;
  newsalt[18] = (1 >> 8) & 0xff;
  newsalt[19] = (1 >> 0) & 0xff;
}

void runIteration(std::string words[18328], unsigned char * salt, unsigned char * expected) {
  int rand1 = rand() % 18327;
  int rand2 = rand() % 18327;
  int rand3 = rand() % 18327;
  std::string password = words[rand1] + " " + words[rand2] + " " + words[rand3];

  uint8_t result[SHA256HashSize];

  pbkdf2((unsigned char *)password.c_str(), password.size(), salt, result);
  
  bool match = true;
  for (int j = 0; j < SHA256HashSize; j++) {
    if (result[j] != expected[j]) {
      match = false;
      break;
    }
  }

  if (match) {
    std::cout << "MATCH!!!: " << password << std::endl;
  }
}


__global__
void runIterationKernel(unsigned char* passwords, int * pwsizes, unsigned char * salt, unsigned char * expected, bool matches[IN_PARALLEL]) {

  uint8_t result[SHA256HashSize];

  int index = blockIdx.x * blockDim.x + threadIdx.x;
  int stride = blockDim.x * gridDim.x;

  for (int i = index; i < IN_PARALLEL; i += stride) {
    unsigned char * password;
    password = passwords + i * 40;
    pbkdf2(password, pwsizes[i], salt, result);
    
    bool match = true;
    for (int j = 0; j < SHA256HashSize; j++) {
      if (result[j] != expected[j]) {
        match = false;
        break;
      }
    }

    if (match) {
      matches[i] = true;
    }
  }
}

void runInParallel() {

  std::cout << "Setting up parallel run" << std::endl;

  std::string words[18328];

  std::string line;
  std::ifstream myfile;
  myfile.open ("AgileWords.txt");
  if (myfile.is_open())
  {
      int i = 0;
    while ( getline (myfile,line) )
    {
      words[i] = line;
      i++;
    }
    myfile.close();
  }

  // ID: DOHB6DC7 -- overwritten for testing !!!!!
  //std::string saltstring = "9dc661ec09c948dd16710439d157cef2";
  std::string saltstring = "2db485972861e63479528bf382d1bc04";
  std::string expected = "3c453512d47b37352bf2c5c1408ea4d9f46c48878782843a685c0c7e54232ba0";
  //std::string expected = "4073c5e1cbd7790347b26e0447795220cd933689219b3446da294f509a583d48";



  cudaDeviceProp properties;
  cudaGetDeviceProperties(&properties, 0);
  std::cout << properties.name << std::endl;
  std::cout << "Threads per block: " << properties.maxThreadsPerBlock << std::endl;

  auto started = std::chrono::high_resolution_clock::now();

  std::string originals[IN_PARALLEL];
  unsigned char * passwords;
  int *pwsizes;
  bool *matches;
  unsigned char * salt;
  unsigned char * expectedBytes;
  cudaMallocManaged(&passwords, IN_PARALLEL * 40 * IN_PARALLEL * sizeof(char));
  cudaMallocManaged(&pwsizes, IN_PARALLEL * sizeof(int));
  cudaMallocManaged(&matches, IN_PARALLEL * sizeof(bool));
  cudaMallocManaged(&salt, 20 * sizeof(char));
  cudaMallocManaged(&expectedBytes, 32 * sizeof(char));

  createPbkdfSalt(salt, saltstring);
  HexToBytes(expected, expectedBytes);

  for (int i = 0; i < IN_PARALLEL; i++) {

    if (i == 16) {
      originals[i] = "glassy ubiquity absence";

    } else {
      int rand1 = rand() % 18327;
      int rand2 = rand() % 18327;
      int rand3 = rand() % 18327;
      originals[i] = words[rand1] + " " + words[rand2] + " " + words[rand3];
      
    }

    pwsizes[i] = originals[i].size();
    unsigned char * password = (unsigned char *)originals[i].c_str();
    for (int j = 0; j < 40; j++) {
      if (j < pwsizes[i]) {
        passwords[i*40 + j] = password[j];
      } else {
        passwords[i*40 + j] = 0x00000000;
      }
      
    }
    matches[i] = false;
  }

  unsigned char * password = passwords + 16 * 40;

  for (int i = 0; i < pwsizes[16]; i++) {
    std::cout << password[i];
  }
  std::cout << std::endl;

  cudaError_t error;

  int numblocks = 4;
  int blocksize = IN_PARALLEL / numblocks;

  runIterationKernel<<<numblocks, blocksize>>>(passwords, pwsizes, salt, expectedBytes, matches);
  std::cout << "Running parallel" << std::endl;
  cudaDeviceSynchronize();
  error = cudaGetLastError();
  std::cout << cudaGetErrorName(error) << ": " << cudaGetErrorString(error) << std::endl;
  std::cout << "Synchronized" << std::endl;

  for (int k = 0; k < IN_PARALLEL; k++) {
    if (matches[k]) {
      std::cout << "MATCH!!!: " << originals[k] << std::endl;
    } else {
      //std::cout << "Did not match: " << originals[k] << std::endl;
    }
  }

  cudaFree(passwords);
  cudaFree(pwsizes);
  cudaFree(matches);
  cudaFree(salt);
  cudaFree(expectedBytes);

  auto done = std::chrono::high_resolution_clock::now();
  double totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(done-started).count();
  totalTime = totalTime / 1000;
  std::cout << "Total time taken: " << std::fixed << totalTime << "s" << std::endl;

	// Number of combinations = 6,156,660,800,000
	// if 5/sec is 39,000 years
	// if 1000 takes 1min30sec then 17570
	// if 10000 takes 5min then 5856 years
  // And now with parallel cuda
  // about 1500/sec? = 130 years...
}

void loadWords() {
    std::string words[18328];

    std::string line;
    std::ifstream myfile;
    myfile.open ("AgileWords.txt");
    if (myfile.is_open())
    {
        int i = 0;
      while ( getline (myfile,line) )
      {
        words[i] = line;
        i++;
      }
      myfile.close();
    }

    std::cout << "Words loaded" <<std::endl;

    // ID: DOHB6DC7
    std::string saltstring = "9dc661ec09c948dd16710439d157cef2";
    unsigned char * salt = (unsigned char *)malloc(20);
    createPbkdfSalt(salt, saltstring);
    std::string expected = "4073c5e1cbd7790347b26e0447795220cd933689219b3446da294f509a583d48";
    unsigned char * expectedBytes = (unsigned char *)malloc(32);
    HexToBytes(expected, expectedBytes);

    int attempts = 10;

    std::cout << "About to start loop" <<std::endl;

    auto started = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < attempts; i++) {
      runIteration(words, salt, expectedBytes);
    }

    auto done = std::chrono::high_resolution_clock::now();

    std::cout << "Loop done" <<std::endl;

    double totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(done-started).count();
    totalTime = totalTime / 1000;

    std::cout << "Total time taken: " << std::fixed << totalTime << "s" << std::endl;
}



__global__
void increase(int n, int *x, bool *b)
{
  for (int i = 0; i < n; i++) {
    if (b[i]) {
      x[i] = x[i] + 20;
    }
  }
}

void testCuda() {
  
  int N = 5;
  int *x;
  bool *b;

  cudaMallocManaged(&x, N*sizeof(int));
  cudaMallocManaged(&b, N*sizeof(bool));

  for (int i = 0; i < N; i++) {
    x[i] = i;
    if (i % 3 == 0) {
      b[i] = false;
    } else {
      b[i] = true;
    }
  }

  increase<<<1,1>>>(N, x, b);

  cudaDeviceSynchronize();

  for (int i = 0; i < N; i++) {
    std::cout << std::dec << x[i] << std::endl;
  }

  cudaFree(x);
  cudaFree(b);
}


int main(void)
{
    std::cout << "Running" << std::endl;

    std::string testpw = "glassy ubiquity absence";
    std::string testsalt = "2db485972861e63479528bf382d1bc04";
    std::string testhash = "3c453512d47b37352bf2c5c1408ea4d9f46c48878782843a685c0c7e54232ba0";

    unsigned char * newsalt = (unsigned char *)malloc(20);
    createPbkdfSalt(newsalt, testsalt);

    uint8_t prk[SHA256HashSize];

    hmac(
        newsalt,
        16,
        (unsigned char *)testpw.c_str(),
        testpw.size(),
        prk
    );
    
    for (int i = 0; i < SHA256HashSize; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(prk[i]);
    }
    std::cout << std::endl;

    std::cout << "hmac Done" << std::endl;

    uint8_t pdprk[SHA256HashSize];

    pbkdf2((unsigned char *)testpw.c_str(), testpw.size(), newsalt, pdprk);

    for (int i = 0; i < SHA256HashSize; i++) {
        //printf("%x", prk[i]);
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pdprk[i]);
    }
    std::cout << std::endl;

    unsigned char * expectedBytes = (unsigned char *)malloc(32);
    HexToBytes(testhash, expectedBytes);
    bool match = true;
    for (int j = 0; j < SHA256HashSize; j++) {
      if (pdprk[j] != expectedBytes[j]) {
        match = false;
        break;
      }
    }

    if (match) {
      std::cout << "pbkdf2 Test hash matched" << std::endl;
    }

    std::cout << "pbkdf2 Done" << std::endl;


    // The cracking..
    //loadWords();
    testCuda();

    runInParallel();

    return 0;
}

