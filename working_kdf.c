#include<stdio.h>
#include<stdlib.h>
#include<inttypes.h>
#include<limits.h>
#include <assert.h>
#include<string.h>
#include<time.h>
#include<errno.h>
#include "auc.h"


#define NUM_REQUESTS 500000 
#define DEBUG_AUC_KDF 1
#define BILLION 1E9
typedef uint8_t  u8;
typedef uint32_t u32;

/*-------------------- Rijndael round subkeys ---------------------*/
u8 roundKeys[11][4][4];
/*--------------------- Rijndael S box table ----------------------*/
u8 S[256] = {
  99,124,119,123,242,107,111,197, 48, 1,103, 43,254,215,171,118,
  202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
  183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
  4,199, 35,195, 24,150, 5,154, 7, 18,128,226,235, 39,178,117,
  9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
  83,209, 0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
  208,239,170,251, 67, 77, 51,133, 69,249, 2,127, 80, 60,159,168,
  81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
  205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
  96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
  224, 50, 58, 10, 73, 6, 36, 92,194,211,172, 98,145,149,228,121,
  231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174, 8,
  186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
  112, 62,181,102, 72, 3,246, 14, 97, 53, 87,185,134,193, 29,158,
  225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
  140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22,
};
/*------- This array does the multiplication by x in GF(2^8) ------*/
u8 Xtime[256] = {
  0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
  32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62,
  64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
  96, 98,100,102,104,106,108,110,112,114,116,118,120,122,124,126,
  128,130,132,134,136,138,140,142,144,146,148,150,152,154,156,158,
  160,162,164,166,168,170,172,174,176,178,180,182,184,186,188,190,
  192,194,196,198,200,202,204,206,208,210,212,214,216,218,220,222,
  224,226,228,230,232,234,236,238,240,242,244,246,248,250,252,254,
  27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5,
  59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37,
  91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69,
  123,121,127,125,115,113,119,117,107,105,111,109, 99, 97,103,101,
  155,153,159,157,147,145,151,149,139,137,143,141,131,129,135,133,
  187,185,191,189,179,177,183,181,171,169,175,173,163,161,167,165,
  219,217,223,221,211,209,215,213,203,201,207,205,195,193,199,197,
  251,249,255,253,243,241,247,245,235,233,239,237,227,225,231,229
};
/*-------------------------------------------------------------------
 * Rijndael key schedule function. Takes 16-byte key and creates
 * all Rijndael's internal subkeys ready for encryption.
 *-----------------------------------------------------------------*/

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

/* Digest is kept internally as 8 32-bit words. */
#define _SHA256_DIGEST_LENGTH 8
#define NETTLE_MAX_HASH_BLOCK_SIZE 128

struct sha256_ctx
{
  uint32_t state[_SHA256_DIGEST_LENGTH];    /* State variables */
  uint64_t count;                           /* 64-bit block count */
  uint8_t block[SHA256_BLOCK_SIZE];          /* SHA256 data buffer */
  unsigned int index;                       /* index into buffer */
};

//#define HMAC_CTX(type) \
//{ type outer; type inner; type state; }

//struct hmac_sha256_ctx HMAC_CTX(struct sha256_ctx);

struct hmac_sha256_ctx 
{
  struct sha256_ctx outer;
  struct sha256_ctx inner; 
  struct sha256_ctx state;
};


#define HMAC_SET_KEY(ctx, hash, length, key)			\
  hmac_set_key( &(ctx)->outer, &(ctx)->inner, &(ctx)->state,	\
                (hash), (length), (key) )

#define HMAC_DIGEST(ctx, hash, length, digest)			\
  hmac_digest( &(ctx)->outer, &(ctx)->inner, &(ctx)->state,	\
               (hash), (length), (digest) )






//present in sha256.c
static const uint32_t
K[64] =
{
  0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 
  0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 
  0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 
  0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 
  0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 
  0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 
  0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 
  0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL, 
  0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 
  0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL, 
  0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 
  0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 
  0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 
  0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL, 
  0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 
  0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL, 
};

#define COMPRESS(ctx, data) (_nettle_sha256_compress((ctx)->state, (data), K))

/* A block, treated as a sequence of 32-bit words. */
#define SHA256_DATA_LENGTH 16

#define ROTL32(n,x) (((x)<<(n)) | ((x)>>((-(n)&31))))


#define WRITE_UINT64(p, i)			\
do {						\
  (p)[0] = ((i) >> 56) & 0xff;			\
  (p)[1] = ((i) >> 48) & 0xff;			\
  (p)[2] = ((i) >> 40) & 0xff;			\
  (p)[3] = ((i) >> 32) & 0xff;			\
  (p)[4] = ((i) >> 24) & 0xff;			\
  (p)[5] = ((i) >> 16) & 0xff;			\
  (p)[6] = ((i) >> 8) & 0xff;			\
  (p)[7] = (i) & 0xff;				\
} while(0)


/* The SHA256 functions. The Choice function is the same as the SHA1
   function f1, and the majority function is the same as the SHA1 f3
   function. They can be optimized to save one boolean operation each
   - thanks to Rich Schroeppel, rcs@cs.arizona.edu for discovering
   this */

/* #define Choice(x,y,z) ( ( (x) & (y) ) | ( ~(x) & (z) ) ) */
#define Choice(x,y,z)   ( (z) ^ ( (x) & ( (y) ^ (z) ) ) ) 
/* #define Majority(x,y,z) ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) ) */
#define Majority(x,y,z) ( ((x) & (y)) ^ ((z) & ((x) ^ (y))) )

#define S0(x) (ROTL32(30,(x)) ^ ROTL32(19,(x)) ^ ROTL32(10,(x))) 
#define S1(x) (ROTL32(26,(x)) ^ ROTL32(21,(x)) ^ ROTL32(7,(x)))

#define s0(x) (ROTL32(25,(x)) ^ ROTL32(14,(x)) ^ ((x) >> 3))
#define s1(x) (ROTL32(15,(x)) ^ ROTL32(13,(x)) ^ ((x) >> 10))

/* The initial expanding function.  The hash function is defined over an
   64-word expanded input array W, where the first 16 are copies of the input
   data, and the remaining 64 are defined by

        W[ t ] = s1(W[t-2]) + W[t-7] + s0(W[i-15]) + W[i-16]

   This implementation generates these values on the fly in a circular
   buffer - thanks to Colin Plumb, colin@nyx10.cs.du.edu for this
   optimization.
*/

#define EXPAND(W,i) \
( W[(i) & 15 ] += (s1(W[((i)-2) & 15]) + W[((i)-7) & 15] + s0(W[((i)-15) & 15])) )

/* The prototype SHA sub-round.  The fundamental sub-round is:

        T1 = h + S1(e) + Choice(e,f,g) + K[t] + W[t]
	T2 = S0(a) + Majority(a,b,c)
	a' = T1+T2
	b' = a
	c' = b
	d' = c
	e' = d + T1
	f' = e
	g' = f
	h' = g

   but this is implemented by unrolling the loop 8 times and renaming
   the variables
   ( h, a, b, c, d, e, f, g ) = ( a, b, c, d, e, f, g, h ) each
   iteration. */

/* It's crucial that DATA is only used once, as that argument will
 * have side effects. */
#define ROUND(a,b,c,d,e,f,g,h,k,data) do {	\
    h += S1(e) + Choice(e,f,g) + k + data;	\
    d += h;					\
    h += S0(a) + Majority(a,b,c);		\
  } while (0)



/* Reads a 32-bit integer, in network, big-endian, byte order */
#define READ_UINT32(p)				\
(  (((uint32_t) (p)[0]) << 24)			\
 | (((uint32_t) (p)[1]) << 16)			\
 | (((uint32_t) (p)[2]) << 8)			\
 |  ((uint32_t) (p)[3]))

void
_nettle_sha256_compress_c(uint32_t *state, const uint8_t *input, const uint32_t *k);
#define _nettle_sha256_compress _nettle_sha256_compress_c




void
_nettle_sha256_compress(uint32_t *state, const uint8_t *input, const uint32_t *k)
{
  uint32_t data[SHA256_DATA_LENGTH];
  uint32_t A, B, C, D, E, F, G, H;     /* Local vars */
  unsigned i;
  uint32_t *d;

  for (i = 0; i < SHA256_DATA_LENGTH; i++, input+= 4)
    {
      data[i] = READ_UINT32(input);
    }

  /* Set up first buffer and local data buffer */
  A = state[0];
  B = state[1];
  C = state[2];
  D = state[3];
  E = state[4];
  F = state[5];
  G = state[6];
  H = state[7];
  
  /* Heavy mangling */
  /* First 16 subrounds that act on the original data */

  //DEBUG(-1);
  for (i = 0, d = data; i<16; i+=8, k += 8, d+= 8)
    {
      ROUND(A, B, C, D, E, F, G, H, k[0], d[0]); //DEBUG(i);
      ROUND(H, A, B, C, D, E, F, G, k[1], d[1]);// DEBUG(i+1);
      ROUND(G, H, A, B, C, D, E, F, k[2], d[2]);
      ROUND(F, G, H, A, B, C, D, E, k[3], d[3]);
      ROUND(E, F, G, H, A, B, C, D, k[4], d[4]);
      ROUND(D, E, F, G, H, A, B, C, k[5], d[5]);
      ROUND(C, D, E, F, G, H, A, B, k[6], d[6]); //DEBUG(i+6);
      ROUND(B, C, D, E, F, G, H, A, k[7], d[7]);// DEBUG(i+7);
    }
  
  for (; i<64; i += 16, k+= 16)
    {
      ROUND(A, B, C, D, E, F, G, H, k[ 0], EXPAND(data,  0)); //DEBUG(i);
      ROUND(H, A, B, C, D, E, F, G, k[ 1], EXPAND(data,  1)); //DEBUG(i+1);
      ROUND(G, H, A, B, C, D, E, F, k[ 2], EXPAND(data,  2)); //DEBUG(i+2);
      ROUND(F, G, H, A, B, C, D, E, k[ 3], EXPAND(data,  3)); //DEBUG(i+3);
      ROUND(E, F, G, H, A, B, C, D, k[ 4], EXPAND(data,  4)); //DEBUG(i+4);
      ROUND(D, E, F, G, H, A, B, C, k[ 5], EXPAND(data,  5)); //DEBUG(i+5);
      ROUND(C, D, E, F, G, H, A, B, k[ 6], EXPAND(data,  6)); //DEBUG(i+6);
      ROUND(B, C, D, E, F, G, H, A, k[ 7], EXPAND(data,  7)); //DEBUG(i+7);
      ROUND(A, B, C, D, E, F, G, H, k[ 8], EXPAND(data,  8)); //DEBUG(i+8);
      ROUND(H, A, B, C, D, E, F, G, k[ 9], EXPAND(data,  9)); //DEBUG(i+9);
      ROUND(G, H, A, B, C, D, E, F, k[10], EXPAND(data, 10)); //DEBUG(i+10);
      ROUND(F, G, H, A, B, C, D, E, k[11], EXPAND(data, 11)); //DEBUG(i+11);
      ROUND(E, F, G, H, A, B, C, D, k[12], EXPAND(data, 12)); //DEBUG(i+12);
      ROUND(D, E, F, G, H, A, B, C, k[13], EXPAND(data, 13)); //DEBUG(i+13);
      ROUND(C, D, E, F, G, H, A, B, k[14], EXPAND(data, 14)); //DEBUG(i+14);
      ROUND(B, C, D, E, F, G, H, A, k[15], EXPAND(data, 15)); //DEBUG(i+15);
    }

  /* Update state */
  state[0] += A;
  state[1] += B;
  state[2] += C;
  state[3] += D;
  state[4] += E;
  state[5] += F;
  state[6] += G;
  state[7] += H;
#if SHA256_DEBUG
  fprintf(stderr, "99: %8x %8x %8x %8x %8x %8x %8x %8x\n",
	  state[0], state[1], state[2], state[3],
	  state[4], state[5], state[6], state[7]);
#endif
}



/* Initialize the SHA values */

void
sha256_init(struct sha256_ctx *ctx)
{
  /* Initial values, also generated by the shadata program. */
  static const uint32_t H0[_SHA256_DIGEST_LENGTH] =
  {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL, 
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL, 
  };

  memcpy(ctx->state, H0, sizeof(H0));

  /* Initialize bit count */
  ctx->count = 0;
  
  /* Initialize buffer */
  ctx->index = 0;
}



/* Takes the compression function f as argument. NOTE: also clobbers
   length and data. */
#define MD_UPDATE(ctx, length, data, f, incr)				\
  do {									\
    if ((ctx)->index)							\
      {									\
	/* Try to fill partial block */					\
	unsigned __md_left = sizeof((ctx)->block) - (ctx)->index;	\
	if ((length) < __md_left)					\
	  {								\
	    memcpy((ctx)->block + (ctx)->index, (data), (length));	\
	    (ctx)->index += (length);					\
	    goto __md_done; /* Finished */				\
	  }								\
	else								\
	  {								\
	    memcpy((ctx)->block + (ctx)->index, (data), __md_left);	\
									\
	    f((ctx), (ctx)->block);					\
	    (incr);							\
									\
	    (data) += __md_left;					\
	    (length) -= __md_left;					\
	  }								\
      }									\
    while ((length) >= sizeof((ctx)->block))				\
      {									\
	f((ctx), (data));						\
	(incr);								\
									\
	(data) += sizeof((ctx)->block);					\
	(length) -= sizeof((ctx)->block);				\
      }									\
    memcpy ((ctx)->block, (data), (length));				\
    (ctx)->index = (length);						\
  __md_done:								\
    ;									\
  } while (0)





void
sha256_update(struct sha256_ctx *ctx,
	      size_t length, const uint8_t *data)
{
  MD_UPDATE (ctx, length, data, COMPRESS, ctx->count++);
}


/* Pads the block to a block boundary with the bit pattern 1 0*,
   leaving size octets for the length field at the end. If needed,
   compresses the block and starts a new one. */
#define MD_PAD(ctx, size, f)						\
  do {									\
    unsigned __md_i;							\
    __md_i = (ctx)->index;						\
									\
    /* Set the first char of padding to 0x80. This is safe since there	\
       is always at least one byte free */				\
									\
    assert(__md_i < sizeof((ctx)->block));				\
    (ctx)->block[__md_i++] = 0x80;					\
									\
    if (__md_i > (sizeof((ctx)->block) - (size)))			\
      { /* No room for length in this block. Process it and		\
	   pad with another one */					\
	memset((ctx)->block + __md_i, 0, sizeof((ctx)->block) - __md_i); \
									\
	f((ctx), (ctx)->block);						\
	__md_i = 0;							\
      }									\
    memset((ctx)->block + __md_i, 0,					\
	   sizeof((ctx)->block) - (size) - __md_i);			\
									\
  } while (0)



#define WRITE_UINT32(p, i)			\
do {						\
  (p)[0] = ((i) >> 24) & 0xff;			\
  (p)[1] = ((i) >> 16) & 0xff;			\
  (p)[2] = ((i) >> 8) & 0xff;			\
  (p)[3] = (i) & 0xff;				\
} while(0)



void
_nettle_write_be32(size_t length, uint8_t *dst,
		   const uint32_t *src)
{
  size_t i;
  size_t words;
  unsigned leftover;
  
  words = length / 4;
  leftover = length % 4;

  for (i = 0; i < words; i++, dst += 4)
    WRITE_UINT32(dst, src[i]);

  if (leftover)
    {
      uint32_t word;
      unsigned j = leftover;
      
      word = src[i];
      
      switch (leftover)
	{
	default:
	  abort();
	case 3:
	  dst[--j] = (word >> 8) & 0xff;
	  /* Fall through */
	case 2:
	  dst[--j] = (word >> 16) & 0xff;
	  /* Fall through */
	case 1:
	  dst[--j] = (word >> 24) & 0xff;
	}
    }
}



static void
sha256_write_digest(struct sha256_ctx *ctx,
		    size_t length,
		    uint8_t *digest)
{
  uint64_t bit_count;

  assert(length <= SHA256_DIGEST_SIZE);

  MD_PAD(ctx, 8, COMPRESS);

  /* There are 512 = 2^9 bits in one block */  
  bit_count = (ctx->count << 9) | (ctx->index << 3);

  /* This is slightly inefficient, as the numbers are converted to
     big-endian format, and will be converted back by the compression
     function. It's probably not worth the effort to fix this. */
  WRITE_UINT64(ctx->block + (SHA256_BLOCK_SIZE - 8), bit_count);
  COMPRESS(ctx, ctx->block);

  _nettle_write_be32(length, digest, ctx->state);
}

void
sha256_digest(struct sha256_ctx *ctx,
	      size_t length,
	      uint8_t *digest)
{
  sha256_write_digest(ctx, length, digest);
  sha256_init(ctx);
}




//Present in nettle-types.h

typedef void nettle_hash_init_func(void *ctx);
typedef void nettle_hash_update_func(void *ctx,
				     size_t length,
				     const uint8_t *src);
typedef void nettle_hash_digest_func(void *ctx,
				     size_t length, uint8_t *dst);


/*Context size in case of sha256 is size of
  sha256_ctx structure

*/


struct nettle_hash
{
  const char *name;

  /* Size of the context struct */
  unsigned context_size;

  /* Size of digests */
  unsigned digest_size;
  
  /* Internal block size */
  unsigned block_size;

  nettle_hash_init_func *init;
  nettle_hash_update_func *update;
  nettle_hash_digest_func *digest;
};



const struct nettle_hash nettle_sha256;

#if defined(__x86_64__) || defined(__arch64__)
/* Including on M$ windows, where unsigned long is only 32 bits */
typedef uint64_t word_t;
#else
typedef unsigned long int word_t;
#endif

#define ALIGN_OFFSET(p) ((uintptr_t) (p) % sizeof(word_t))

#ifndef WORDS_BIGENDIAN
#define MERGE(w0, sh_1, w1, sh_2) \
  (((w0) >> (sh_1)) | ((w1) << (sh_2)))
#else
#define MERGE(w0, sh_1, w1, sh_2) \
  (((w0) << (sh_1)) | ((w1) >> (sh_2)))
#endif

#ifndef WORDS_BIGENDIAN
#define READ_PARTIAL(r,p,n) do {			\
    word_t _rp_x;					\
    unsigned _rp_i;					\
    for (_rp_i = (n), _rp_x = (p)[--_rp_i]; _rp_i > 0;)	\
      _rp_x = (_rp_x << CHAR_BIT) | (p)[--_rp_i];	\
    (r) = _rp_x;					\
  } while (0)
#else
#define READ_PARTIAL(r,p,n) do {			\
    word_t _rp_x;						\
    unsigned _rp_i;						\
    for (_rp_x = (p)[0], _rp_i = 1; _rp_i < (n); _rp_i++)	\
      _rp_x = (_rp_x << CHAR_BIT) | (p)[_rp_i];			\
    (r) = _rp_x;						\
  } while (0)
#endif

#define ALIGN_OFFSET(p) ((uintptr_t) (p) % sizeof(word_t))

#define WORD_T_THRESH 16

/* XOR word-aligned areas. n is the number of words, not bytes. */
static void
memxor_common_alignment (word_t *dst, const word_t *src, size_t n)
{
  /* FIXME: Require n > 0? */
  /* FIXME: Unroll four times, like memcmp? Probably not worth the
     effort. */

  if (n & 1)
    {
      n--;
      dst[n] ^= src[n];
    }
  while (n >= 2)
    {
      n -= 2;
      dst[n+1] ^= src[n+1];
      dst[n] ^= src[n];
    }
}

/* XOR *un-aligned* src-area onto aligned dst area. n is number of
   words, not bytes. Assumes we can read complete words at the start
   and end of the src operand. */
static void
memxor_different_alignment (word_t *dst, const unsigned char *src, size_t n)
{
  int shl, shr;
  const word_t *src_word;
  unsigned offset = ALIGN_OFFSET (src);
  word_t s0, s1;

  assert (n > 0);
  shl = CHAR_BIT * offset;
  shr = CHAR_BIT * (sizeof(word_t) - offset);

  src_word = (const word_t *) ((uintptr_t) src & -sizeof(word_t));

  /* Read top offset bytes, in native byte order. */
  READ_PARTIAL (s0, (unsigned char *) &src_word[n], offset);
#ifdef WORDS_BIGENDIAN
  s0 <<= shr; /* FIXME: Eliminate this shift? */
#endif

  /* Do n-1 regular iterations */
  if (n & 1)
    s1 = s0;
  else
    {
      n--;
      s1 = src_word[n];
      dst[n] ^= MERGE (s1, shl, s0, shr);
    }

  assert (n & 1);
  while (n > 2)
    {
      n -= 2;
      s0 = src_word[n+1];
      dst[n+1] ^= MERGE(s0, shl, s1, shr);
      s1 = src_word[n]; /* FIXME: Overread on last iteration */
      dst[n] ^= MERGE(s1, shl, s0, shr);
    }
  assert (n == 1);
  /* Read low wordsize - offset bytes */
  READ_PARTIAL (s0, src, sizeof(word_t) - offset);
#ifndef WORDS_BIGENDIAN
  s0 <<= shl; /* FIXME: eliminate shift? */
#endif /* !WORDS_BIGENDIAN */

  dst[0] ^= MERGE(s0, shl, s1, shr);
}

/* Performance, Intel SU1400 (x86_64): 0.25 cycles/byte aligned, 0.45
   cycles/byte unaligned. */

/* XOR LEN bytes starting at SRCADDR onto DESTADDR. Result undefined
   if the source overlaps with the destination. Return DESTADDR. */
void *
memxor(void *dst_in, const void *src_in, size_t n)
{
  unsigned char *dst = dst_in;
  const unsigned char *src = src_in;

  if (n >= WORD_T_THRESH)
    {
      unsigned i;
      unsigned offset;
      size_t nwords;
      /* There are at least some bytes to compare.  No need to test
	 for N == 0 in this alignment loop.  */
      for (i = ALIGN_OFFSET(dst + n); i > 0; i--)
	{
	  n--;
	  dst[n] ^= src[n];
	}
      offset = ALIGN_OFFSET(src + n);
      nwords = n / sizeof (word_t);
      n %= sizeof (word_t);

      if (offset)
	memxor_different_alignment ((word_t *) (dst+n), src+n, nwords);
      else
	memxor_common_alignment ((word_t *) (dst+n),
				 (const word_t *) (src+n), nwords);
    }
  while (n > 0)
    {
      n--;
      dst[n] ^= src[n];
    }

  return dst;
}


# define TMP_DECL(name, type, max) type *name
# define TMP_ALLOC(name, size) (name = alloca(sizeof (*name) * (size)))


#define IPAD 0x36
#define OPAD 0x5c

void
hmac_set_key(void *outer, void *inner, void *state,
	     const struct nettle_hash *hash,
	     size_t key_length, const uint8_t *key)
{
  TMP_DECL(pad, uint8_t, NETTLE_MAX_HASH_BLOCK_SIZE);
  //TMP_ALLOC(pad, hash->block_size);
  TMP_ALLOC(pad, SHA256_BLOCK_SIZE);
  
  //hash->init(outer);  //sha256_init() function
  sha256_init(outer);  //sha256_init() function

  //hash->init(inner);  //sha256_init() function
  sha256_init(inner);  //sha256_init() function
  //if (key_length > hash->block_size)
  if(key_length > SHA256_BLOCK_SIZE)
    {
      /* Reduce key to the algorithm's hash size. Use the area pointed
       * to by state for the temporary state. */

      TMP_DECL(digest, uint8_t, NETTLE_MAX_HASH_DIGEST_SIZE);
     // TMP_ALLOC(digest, hash->digest_size);

      TMP_ALLOC(digest, SHA256_DIGEST_SIZE);
    //  hash->init(state);
      sha256_init(state);
      //hash->update(state, key_length, key);
      sha256_update(state, key_length, key);
      //hash->digest(state, hash->digest_size, digest);
      //hash->digest(state, SHA256_DIGEST_SIZE, digest);
      sha256_digest(state, SHA256_DIGEST_SIZE, digest);

      key = digest;
     // key_length = hash->digest_size;
      key_length = SHA256_DIGEST_SIZE;
    }

  //assert(key_length <= hash->block_size);
  assert(key_length <= SHA256_BLOCK_SIZE);
  
  //memset(pad, OPAD, hash->block_size);
  memset(pad, OPAD, SHA256_BLOCK_SIZE);
  memxor(pad, key, key_length);

  //hash->update(outer, hash->block_size, pad);
  //hash->update(outer, SHA256_BLOCK_SIZE, pad);
  sha256_update(outer, SHA256_BLOCK_SIZE, pad);

  //memset(pad, IPAD, hash->block_size);
  memset(pad, IPAD, SHA256_BLOCK_SIZE);
  memxor(pad, key, key_length);

  //hash->update(inner, hash->block_size, pad);
  //hash->update(inner, SHA256_BLOCK_SIZE, pad);
  sha256_update(inner, SHA256_BLOCK_SIZE, pad);

  //memcpy(state, inner, hash->context_size);
  memcpy(state, inner, sizeof(struct sha256_ctx));
}

void
hmac_digest(const void *outer, const void *inner, void *state,
	    const struct nettle_hash *hash, 	    
	    size_t length, uint8_t *dst)
{
  TMP_DECL(digest, uint8_t, NETTLE_MAX_HASH_DIGEST_SIZE);
  //TMP_ALLOC(digest, hash->digest_size);
  TMP_ALLOC(digest, SHA256_DIGEST_SIZE);

  //hash->digest(state, hash->digest_size, digest);
  sha256_digest(state, SHA256_DIGEST_SIZE, digest);

  //memcpy(state, outer, hash->context_size);
  memcpy(state, outer, sizeof(struct sha256_ctx));
  

  //hash->update(state, hash->digest_size, digest);
  sha256_update(state, SHA256_DIGEST_SIZE, digest);
  //hash->digest(state, length, dst);
  sha256_digest(state, length, dst);

  //printf("%d\n",sizeof(struct sha256_ctx));
  //memcpy(state, inner, hash->context_size);
  memcpy(state, inner, sizeof(struct sha256_ctx));
}








//KDF Calls 3 functions. in the file "hmac-sha256.c"

void
hmac_sha256_set_key(struct hmac_sha256_ctx *ctx,
		    size_t key_length, const uint8_t *key)
{
  HMAC_SET_KEY(ctx, &nettle_sha256, key_length, key);
}

void
hmac_sha256_update(struct hmac_sha256_ctx *ctx,
		   size_t length, const uint8_t *data)
{
  sha256_update(&ctx->state, length, data);
}

void
hmac_sha256_digest(struct hmac_sha256_ctx *ctx,
		   size_t length, uint8_t *digest)
{
  HMAC_DIGEST(ctx, &nettle_sha256, length, digest);
}


inline
void kdf(uint8_t *key, uint16_t key_len, uint8_t *s, uint16_t s_len, uint8_t *out,
         uint16_t out_len)
{
  struct hmac_sha256_ctx ctx;

  memset(&ctx, 0, sizeof(ctx));

  hmac_sha256_set_key(&ctx, key_len, key);
  hmac_sha256_update(&ctx, s_len, s);
  hmac_sha256_digest(&ctx, out_len, out);
}

void RijndaelKeySchedule( const u8 const key[16] )
{
  u8 roundConst;
  int i, j;

  /*printf("RijndaelKeySchedule: K %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
		  key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7],
		  key[8],key[9],key[10],key[11],key[12],key[13],key[14],key[15] );*/
  /* first round key equals key */
  for (i=0; i<16; i++)
    roundKeys[0][i & 0x03][i>>2] = key[i];

  roundConst = 1;

  /* now calculate round keys */
  for (i=1; i<11; i++) {
    roundKeys[i][0][0] = S[roundKeys[i-1][1][3]]
                         ^ roundKeys[i-1][0][0] ^ roundConst;
    roundKeys[i][1][0] = S[roundKeys[i-1][2][3]]
                         ^ roundKeys[i-1][1][0];
    roundKeys[i][2][0] = S[roundKeys[i-1][3][3]]
                         ^ roundKeys[i-1][2][0];
    roundKeys[i][3][0] = S[roundKeys[i-1][0][3]]
                         ^ roundKeys[i-1][3][0];

    for (j=0; j<4; j++) {
      roundKeys[i][j][1] = roundKeys[i-1][j][1] ^ roundKeys[i][j][0];
      roundKeys[i][j][2] = roundKeys[i-1][j][2] ^ roundKeys[i][j][1];
      roundKeys[i][j][3] = roundKeys[i-1][j][3] ^ roundKeys[i][j][2];
    }

    /* update round constant */
    roundConst = Xtime[roundConst];
  }

  return;
} /* end of function RijndaelKeySchedule */
/* Round key addition function */
void KeyAdd(u8 state[4][4], u8 roundKeys[11][4][4], int round)
{
  int i, j;

  for (i=0; i<4; i++)
    for (j=0; j<4; j++)
      state[i][j] ^= roundKeys[round][i][j];

  return;
}
/* Byte substitution transformation */
int ByteSub(u8 state[4][4])
{
  int i, j;

  for (i=0; i<4; i++)
    for (j=0; j<4; j++)
      state[i][j] = S[state[i][j]];

  return 0;
}
/* Row shift transformation */
void ShiftRow(u8 state[4][4])
{
  u8 temp;
  /* left rotate row 1 by 1 */
  temp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = temp;
  /* left rotate row 2 by 2 */
  temp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = temp;
  temp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = temp;
  /* left rotate row 3 by 3 */
  temp = state[3][0];
  state[3][0] = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = temp;
  return;
}
/* MixColumn transformation*/
void MixColumn(u8 state[4][4])
{
  u8 temp, tmp, tmp0;
  int i;

  /* do one column at a time */
  for (i=0; i<4; i++) {
    temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
    tmp0 = state[0][i];
    /* Xtime array does multiply by x in GF2^8 */
    tmp = Xtime[state[0][i] ^ state[1][i]];
    state[0][i] ^= temp ^ tmp;
    tmp = Xtime[state[1][i] ^ state[2][i]];
    state[1][i] ^= temp ^ tmp;
    tmp = Xtime[state[2][i] ^ state[3][i]];
    state[2][i] ^= temp ^ tmp;
    tmp = Xtime[state[3][i] ^ tmp0];
    state[3][i] ^= temp ^ tmp;
  }

  return;
}
/*-------------------------------------------------------------------
 * Rijndael encryption function. Takes 16-byte input and creates
 * 16-byte output (using round keys already derived from 16-byte
 * key).
 *-----------------------------------------------------------------*/
void RijndaelEncrypt( const u8 const input[16], u8 output[16] )
{
  u8 state[4][4];
  int i, r;

  /* initialise state array from input byte string */
  for (i=0; i<16; i++)
    state[i & 0x3][i>>2] = input[i];

  /* add first round_key */
  KeyAdd(state, roundKeys, 0);

  /* do lots of full rounds */
  for (r=1; r<=9; r++) {
    ByteSub(state);
    ShiftRow(state);
    MixColumn(state);
    KeyAdd(state, roundKeys, r);
  }

  /* final round */
  ByteSub(state);
  ShiftRow(state);
  KeyAdd(state, roundKeys, r);

  /* produce output byte string from state array */
  for (i=0; i<16; i++) {
    output[i] = state[i & 0x3][i>>2];
  }

  return;
} /* end of function RijndaelEncrypt */

void generate_autn(const uint8_t const sqn[6], const uint8_t const ak[6], const uint8_t const amf[2], const uint8_t const mac_a[8], uint8_t autn[16])
{
  int i;

  for (i = 0; i < 6; i++) {
    autn[i] = sqn[i] ^ ak[i];
  }

  memcpy(&autn[6], amf, 2);
  memcpy(&autn[8], mac_a, 8);
}

/*-------------------------------------------------------------------
 * Algorithm f1
 *-------------------------------------------------------------------
 *
 * Computes network authentication code MAC-A from key K, random
 * challenge RAND, sequence number SQN and authentication management
 * field AMF.
 *
 *-----------------------------------------------------------------*/




void f1 ( const uint8_t const opc[16], const uint8_t const k[16], const uint8_t const _rand[16], const uint8_t const sqn[6], const uint8_t const amf[2],
          uint8_t mac_a[8] )
{
  uint8_t temp[16];
  uint8_t in1[16];
  uint8_t out1[16];
  uint8_t rijndaelInput[16];
  uint8_t i;
  RijndaelKeySchedule( k );

  for (i=0; i<16; i++)
    rijndaelInput[i] = _rand[i] ^ opc[i];

  RijndaelEncrypt( rijndaelInput, temp );

  for (i=0; i<6; i++) {
    in1[i] = sqn[i];
    in1[i+8] = sqn[i];
  }

  for (i=0; i<2; i++) {
    in1[i+6] = amf[i];
    in1[i+14] = amf[i];
  }

  /* XOR op_c and in1, rotate by r1=64, and XOR *
   * on the constant c1 (which is all zeroes) */
  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = in1[i] ^ opc[i];

  /* XOR on the value temp computed before */
  for (i=0; i<16; i++)
    rijndaelInput[i] ^= temp[i];

  RijndaelEncrypt( rijndaelInput, out1 );

  for (i=0; i<16; i++)
    out1[i] ^= opc[i];

  for (i=0; i<8; i++)
    mac_a[i] = out1[i];

  return;
} /* end of function f1 */



/*-------------------------------------------------------------------
 * Algorithms f2-f5
 *-------------------------------------------------------------------
 *
 * Takes key K and random challenge RAND, and returns response RES,
 * confidentiality key CK, integrity key IK and anonymity key AK.
 *
 *-----------------------------------------------------------------*/
void f2345 ( const uint8_t const opc[16], const uint8_t const k[16], const uint8_t const _rand[16],
             uint8_t res[8], uint8_t ck[16], uint8_t ik[16], uint8_t ak[6] )
{
  uint8_t temp[16];
  uint8_t out[16];
  uint8_t rijndaelInput[16];
  uint8_t i;
  RijndaelKeySchedule( k );

  for (i=0; i<16; i++)
    rijndaelInput[i] = _rand[i] ^ opc[i];

  RijndaelEncrypt( rijndaelInput, temp );

  /* To obtain output block OUT2: XOR OPc and TEMP, *
   * rotate by r2=0, and XOR on the constant c2 (which *
   * is all zeroes except that the last bit is 1). */
  for (i=0; i<16; i++)
    rijndaelInput[i] = temp[i] ^ opc[i];

  rijndaelInput[15] ^= 1;
  RijndaelEncrypt( rijndaelInput, out );

  for (i=0; i<16; i++)
    out[i] ^= opc[i];

  for (i=0; i<8; i++)
    res[i] = out[i+8];

  for (i=0; i<6; i++)
    ak[i] = out[i];

  /* To obtain output block OUT3: XOR OPc and TEMP, *
   * rotate by r3=32, and XOR on the constant c3 (which *
   * is all zeroes except that the next to last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+12) % 16] = temp[i] ^ opc[i];

  rijndaelInput[15] ^= 2;
  RijndaelEncrypt( rijndaelInput, out );

  for (i=0; i<16; i++)
    out[i] ^= opc[i];

  for (i=0; i<16; i++)
    ck[i] = out[i];

  /* To obtain output block OUT4: XOR OPc and TEMP, *
   * rotate by r4=64, and XOR on the constant c4 (which *
   * is all zeroes except that the 2nd from last bit is 1). */
  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = temp[i] ^ opc[i];

  rijndaelInput[15] ^= 4;
  RijndaelEncrypt( rijndaelInput, out );

  for (i=0; i<16; i++)
    out[i] ^= opc[i];

  for (i=0; i<16; i++)
    ik[i] = out[i];

  return;
} /* end of function f2345 */	


inline
void derive_kasme(uint8_t ck[16], uint8_t ik[16], uint8_t plmn[3], uint8_t sqn[6],
                  uint8_t ak[6], uint8_t *kasme)
{
  uint8_t s[14];
  int i;
  uint8_t key[32];

  /* The input key is equal to the concatenation of CK and IK */
  memcpy(&key[0], ck, 16);
  memcpy(&key[16], ik, 16);

  /*if (hss_config.valid_opc == 0) {
    SetOP(hss_config.operator_key);
  }*/

  /* FC */
  s[0] = 0x10;

  /* SN id is composed of MCC and MNC
   * Octets:
   *   1      MCC digit 2 | MCC digit 1
   *   2      MNC digit 3 | MCC digit 3
   *   3      MNC digit 2 | MNC digit 1
   */
  memcpy(&s[1], plmn, 3);

  /* L0 */
  s[4] = 0x00;
  s[5] = 0x03;

  /* P1 */
  for (i = 0; i < 6; i++) {
    s[6 + i] = sqn[i] ^ ak[i];
  }

  /* L1 */
  s[12] = 0x00;
  s[13] = 0x06;
/*
#if defined(DEBUG_AUC_KDF)

  for (i = 0; i < 32; i++)
    printf("0x%02x ", key[i]);

  printf("\n");

  for (i = 0; i < 14; i++)
    printf("0x%02x ", s[i]);

  printf("\n");
#endif
*/
  kdf(key, 32, s, 14, kasme, 32);
}


int generate_vector(const uint8_t const opc[16], uint64_t imsi, uint8_t key[16], uint8_t plmn[3],
                    uint8_t sqn[6], auc_vector_t *vector)
{
  /* in E-UTRAN an authentication vector is composed of:
   * - RAND
   * - XRES
   * - AUTN
   * - KASME
   */

  uint8_t amf[] = { 0x80, 0x00 };
  uint8_t mac_a[8];
  uint8_t ck[16];
  uint8_t ik[16];
  uint8_t ak[6];

  if (vector == NULL) {
    return EINVAL;
  }

  /* Compute MAC */
  f1(opc, key, vector->rand, sqn, amf, mac_a);

  //print_buffer("MAC_A   : ", mac_a, 8);
  //print_buffer("SQN     : ", sqn, 6);
  //print_buffer("RAND    : ", vector->rand, 16);

  /* Compute XRES, CK, IK, AK */
  f2345(opc, key, vector->rand, vector->xres, ck, ik, ak);
  //print_buffer("AK      : ", ak, 6);
  //print_buffer("CK      : ", ck, 16);
  //print_buffer("IK      : ", ik, 16);
  //print_buffer("XRES    : ", vector->xres, 8);

  /* AUTN = SQN ^ AK || AMF || MAC */
  generate_autn(sqn, ak, amf, mac_a, vector->autn);

  //print_buffer("AUTN    : ", vector->autn, 16);

  derive_kasme(ck, ik, plmn, sqn, ak, vector->kasme);
  //print_buffer("KASME   : ", vector->kasme, 32);

  return 0;
}

typedef struct {

  uint8_t opc_in[16];//128 bit
  uint64_t imsi_in;
  uint8_t key_in[16]; //128 bit
  uint8_t plmn_in[3];
  uint8_t sqn_in[6];
  auc_vector_t* auc_vector_in;
  
} input_request;


void init_auc_vector(auc_vector_t *auc_vector_in)
{
  int i=0;
  auc_vector_in->rand_new=100;
  for(i=0;i<8;i++)
    auc_vector_in->xres[i]=i;
  for(i=0;i<16;i++)
  {
    auc_vector_in->rand[i]=i;
    auc_vector_in->autn[i]=i;
  }
  for(i=0;i<16;i++)
    auc_vector_in->kasme[i]=i;

}

void init_input(input_request *input,int offset) {
  int i=0;
  input->imsi_in=12345678;
  for(i=0;i<16;i++)
  {
    input->opc_in[i]=i+1;	   
    input->key_in[i]=(i+1+offset)%16;
    
  }
  for(i=0;i<3;i++)
    input->plmn_in[i]=i+1;    
  for(i=0;i<6;i++)
    input->sqn_in[i]=i+1; 
  input->auc_vector_in=(auc_vector_t*)malloc(sizeof(auc_vector_t));
  init_auc_vector(input->auc_vector_in);
 
}
double get_time_difference(struct timespec start, struct timespec stop) {
  
  double time_diff=0.0;
  time_diff= (stop.tv_sec - start.tv_sec)*1000 + (double)((stop.tv_nsec - start.tv_nsec)*1000)/BILLION; 	
  return time_diff;
   
}

int main (int argc, char **argv)
{
/*
  const uint8_t const opc_in[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16} ;//128 bit
  uint64_t imsi_in = 12345678;
  uint8_t key_in[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; //128 bit
  uint8_t plmn_in[3]={1,2,3};
  uint8_t sqn_in[6]={1,2,3,4,5,6};
*/  
  struct timespec start, stop;
  double elapsed_time=0.0;
  int i=0;
  //auc_vector_t* auc_vector_in;
  //auc_vector_in = (auc_vector_t*)malloc(sizeof(auc_vector_t));
  //init_auc_vector(auc_vector_in);
  input_request *input = (input_request*)malloc(NUM_REQUESTS*sizeof(input_request));
  for(i=0;i<NUM_REQUESTS;i++)
    init_input(&input[i],i);
  clock_gettime(CLOCK_MONOTONIC,&start);

  for(i=0;i<NUM_REQUESTS;i++)
    generate_vector(input[i].opc_in, input[i].imsi_in, input[i].key_in,input[i].plmn_in,input[i].sqn_in, input[i].auc_vector_in);

  clock_gettime(CLOCK_MONOTONIC,&stop);
  elapsed_time=get_time_difference(start,stop);
/*
  for(i=0;i<NUM_REQUESTS;i++)
  {
    printf("AUC_VECTOR_RAND %u\n",input[i].auc_vector_in->rand_new);
    print_buffer("XRES    : ", input[i].auc_vector_in->xres, 8);
    print_buffer("AUTN    : ", input[i].auc_vector_in->autn, 16);
    print_buffer("KASME    : ", input[i].auc_vector_in->kasme, 16);
  }
*/

  printf("Elapsed time in milli seconds %lf\n",elapsed_time);
  //generate_vector();		
  return 0;	

}

