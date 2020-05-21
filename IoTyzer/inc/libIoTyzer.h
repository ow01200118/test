#ifndef _IOTZ_LIB_IOTYZER_H_
#define _IOTZ_LIB_IOTYZER_H_


#define IOTZ_DEV_INFO_FIELD_SIZE            200

#define IOTZ_TAG_ERROR         0x00000001
#define IOTZ_FRAME_CIPHER_CODE_ERROR        0x00000002

#define IOTZ_BLOCK_CIPHER_ALGORITHM_ERROR   0x00000101
#define IOTZ_BLOCK_CIPHER_MODE_ERROR        0x00000102
#define IOTZ_BLOCK_CIPHER_ENCDEC_ERROR      0x00000103

#define IOTZ_HASH_ALGORITHM_ERROR           0x00000201

typedef struct _IOTZ_DEV_INFO
{
    IOTZ_CHAR dev_vender[IOTZ_DEV_INFO_FIELD_SIZE];
    IOTZ_CHAR dev_model_num[IOTZ_DEV_INFO_FIELD_SIZE];
    IOTZ_CHAR dev_serial_num[IOTZ_DEV_INFO_FIELD_SIZE];
} IOTZ_DEV_INFO;


#ifdef _MSC_VER
__declspec(dllexport)
#endif
IOTZ_RETURN initialize_target();

#ifdef _MSC_VER
__declspec(dllexport)
#endif
IOTZ_RETURN iotz_get_iotyzer_dev_info(IOTZ_DEV_INFO* devInfo);

#ifdef _MSC_VER
__declspec(dllexport)
#endif
IOTZ_RETURN query_blockcipher_enc(
    IOTZ_UBYTE* out,                                // Byte array(Ciphertext)
    IOTZ_INT* outLen,                               // Length is byte length
    const IOTZ_UBYTE* in,                           // Byte array(Plaintext)
    const IOTZ_INT inLen,                           // Length is byte length
    const IOTZ_UBYTE* iv,                           // Byte array(IV or Nonce for CBC, CFB, OFB, CCM/GCM, if not NULL)
    const IOTZ_INT ivLen,                           // Length is byte length
    const IOTZ_UBYTE* key,                          // Byte array(Key)
    const IOTZ_INT keyLen,                          // Length is bit length, ex) 128, 192, 256
    const IOTZ_BLOCK_CIPHER_MODE_OPERATION mode,    // ECB, CBC, CFB1, CFB8, CFB32, CFB64, CFB128, OFB, CCM, GCM
    const IOTZ_BLOCK_CIPHER_ALG alg                 // ARIA, SEED, LEA
);
#ifdef _MSC_VER
__declspec(dllexport)
#endif
IOTZ_RETURN query_blockcipher_dec(
    IOTZ_BYTE* out,                                 // Byte array(Plaintext)
    IOTZ_INT* outLen,                               // Length is byte length
    const IOTZ_UBYTE* in,                           // Byte array(Ciphertext)
    const IOTZ_INT inLen,                           // Length is byte length
    const IOTZ_UBYTE* iv,                           // Byte array(IV or Nonce for CBC, CFB, OFB, CCM/GCM, if not NULL)
    const IOTZ_INT ivLen,                           // Length is byte length
    const IOTZ_UBYTE* key,                          // Byte array(Key)
    const IOTZ_INT keyLen,                          // Length is bit length, ex) 128, 192, 256
    const IOTZ_BLOCK_CIPHER_MODE_OPERATION mode,    // ECB, CBC, CFB1, CFB8, CFB32, CFB64, CFB128, OFB, CCM, GCM
    const IOTZ_BLOCK_CIPHER_ALG alg                 // ARIA, SEED, LEA
);



#else

#endif
