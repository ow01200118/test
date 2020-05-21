#ifndef _IOTZ_KOR_MCT_TEST_H_
#define _IOTZ_KOR_MCT_TEST_H_


#define IOTZ_MCT_ALGORITHM_NOT_SET          1
#define IOTZ_MCT_MODE_OPERATION_NOT_SET     1
#define IOTZ_MCT_FILE_OPEN_ERROR            1
#define IOTZ_MCT_FILE_READ_ERROR            1

#define IOTZ_MCT_TEST_COUNT                 100
#define IOTZ_MCT_TEST_ROUND                 1000


IOTZ_RETURN iotz_gen_fax_req_blockcipher_korea_mct_test(
    const IOTZ_CHAR* fName,                 // File Name
    IOTZ_BLOCK_CIPHER_ALG alg,              // ARIA, SEED, LEA
    IOTZ_BLOCK_CIPHER_KEY_SIZE keySize,     // 128, 192, 256(if block cipher is SEED, then key size fixed 128bit
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode   // ECB, CBC, CFB1, CFB8, CFB32, CFB64, CFB128, OFB, CTR
);
IOTZ_RETURN iotz_gen_rsp_blockcipher_korea_mct_test(
    const IOTZ_CHAR* fName,                 // File Name
    IOTZ_BLOCK_CIPHER_ALG alg,              // ARIA, SEED, LEA
    IOTZ_BLOCK_CIPHER_KEY_SIZE keySize,     // 128, 192, 256(if block cipher is SEED, then key size fixed 128bit
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode   // ECB, CBC, CFB1, CFB8, CFB32, CFB64, CFB128, OFB, CTR
);



#else

#endif
