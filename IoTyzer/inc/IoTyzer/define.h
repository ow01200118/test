#ifndef _IOTZ_DEFINE_H_
#define _IOTZ_DEFINE_H_


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif


#ifdef _MSC_VER
#define PREFIX_FILE_PATH        "..\\testvector\\"
#else
#define PREFIX_FILE_PATH        "../testvector/"
#endif

#define FILE_NAME_SIZE          256
#define BUF_SIZE                1024

#define IOTYZER_SERVER_IP       "127.0.0.1"
#define IOTYZER_SERVER_PORT     9000

#define MAX_KEY_SIZE            32  // Byte length
#define BLOCK_BYTE_SIZE         16  // Byte length
#define BLOCK_WORD_SIZE         4   // Word length
#define ROUNDKEY_MAXLEN         200

#ifdef _MSC_VER
    #define iotz_fprintf fprintf_s
#else
    #define iotz_fprintf fprintf
#endif

typedef void            IOTZ_VOID;
typedef char            IOTZ_CHAR;
typedef int             IOTZ_INT;
typedef unsigned char   IOTZ_UCHAR;
typedef unsigned int    IOTZ_UINT;

typedef float           IOTZ_FLOAT;
typedef double          IOTZ_DOUBLE;

typedef int8_t          IOTZ_BYTE;
typedef int16_t         IOTZ_DBYTE;
typedef int32_t         IOTZ_WORD;
typedef int64_t         IOTZ_DWORD;
typedef uint8_t         IOTZ_UBYTE;
typedef uint16_t        IOTZ_UDBYTE;
typedef uint32_t        IOTZ_UWORD;
typedef uint64_t        IOTZ_UDWORD;

typedef IOTZ_INT        IOTZ_RETURN;

typedef FILE            IOTZ_FILE;

typedef enum _IOTZ_BLOCK_ENC_DEC
{
    IOTZ_ENC = 0,
    IOTZ_DEC = 1
} IOTZ_BLOCK_ENC_DEC;

typedef enum _IOTZ_BLOCK_CIPHER_ALG
{
    IOTZ_ARIA = 0,
    IOTZ_SEED,
    IOTZ_LEA,
    IOTZ_AES,
} IOTZ_BLOCK_CIPHER_ALG;

typedef enum _IOTZ_BLOCK_CIPHER_KEY_SIZE
{
    IOTZ_128BIT_KEY = 128,
    IOTZ_192BIT_KEY = 192,
    IOTZ_256BIT_KEY = 256,
} IOTZ_BLOCK_CIPHER_KEY_SIZE;

typedef enum _IOTZ_BLOCK_CIPHER_MODE_OPERATION
{
    IOTZ_ECB = 0,
    IOTZ_CBC,
    IOTZ_CFB1,
    IOTZ_CFB8,
    IOTZ_CFB32,
    IOTZ_CFB64,
    IOTZ_CFB128,
    IOTZ_OFB,
    IOTZ_CTR,
} IOTZ_BLOCK_CIPHER_MODE_OPERATION;

typedef struct _IOTZ_BLOCK_CIPHER_TEST_SET
{
    IOTZ_BLOCK_CIPHER_ALG alg;
    IOTZ_BLOCK_CIPHER_KEY_SIZE keySize;
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode;
}IOTZ_BLOCK_CIPHER_TEST_SET;

typedef struct _IOTZ_MAC_TEST_SET
{

}IOTZ_MAC_TEST_SET;

typedef enum _IOTZ_HASH_ALG
{
    IOTZ_SHA2_224 = 0,
    IOTZ_SHA2_256,
    IOTZ_SHA2_384,
    IOTZ_SHA2_512,
    IOTZ_LSH_256_224,
    IOTZ_LSH_256_256,
    IOTZ_LSH_512_224,
    IOTZ_LSH_512_256,
    IOTZ_LSH_512_384,
    IOTZ_LSH_512_512,
    IOTZ_SHA3_224,
    IOTZ_SHA3_256,
    IOTZ_SHA3_384,
    IOTZ_SHA3_512,
} IOTZ_HASH_ALG;

typedef struct _IOTZ_HASH_TEST_SET
{
    IOTZ_HASH_ALG alg;
}IOTZ_HASH_TEST_SET;

typedef enum _IOTZ_MAC_ALG
{
    IOTZ_HMAC = 0,
    IOTZ_CMAC,
    IOTZ_CCM,
    IOTZ_GCM,
} IOTZ_MAC_ALG;

typedef enum _IOTZ_CAVP_VER
{
    IOTZ_CAVP_KR = 0,
    IOTZ_CAVP_US = 1,
    IOTZ_ACVP = 2,
} IOTZ_CAVP_VER;



#else

#endif
