#ifndef _IOTZ_MODE_OF_OPERATE_
#define _IOTZ_MODE_OF_OPERATE_


#define IOTZ_ALGORITHM_SELECT_ERROR     1

#define INCREASE_CTR(x) ((x)[15] == 0xFF) ? (((x)[14] == 0xFF) ? ((x)[13]++, (x)[14] = 0, (x)[15] = 0) : (x)[14]++, (x)[15] = 0) : ((x)[15]++);


IOTZ_RETURN blockcipher_ecb_enc(
    IOTZ_UBYTE* out,
    IOTZ_INT* outLen,
    IOTZ_UBYTE* in,
    IOTZ_INT inLen,
    IOTZ_UBYTE* key,
    IOTZ_BLOCK_CIPHER_KEY_SIZE keyLen,
    IOTZ_BLOCK_CIPHER_ALG alg
);
IOTZ_RETURN blockcipher_ecb_dec(
    IOTZ_UBYTE* out,
    IOTZ_INT* outLen,
    IOTZ_UBYTE* in,
    IOTZ_INT inLen,
    IOTZ_UBYTE* key,
    IOTZ_BLOCK_CIPHER_KEY_SIZE keyLen,
    IOTZ_BLOCK_CIPHER_ALG alg
);



#else

#endif
