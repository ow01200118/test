#ifndef _IOTZ_SEED_H_
#define _IOTZ_SEED_H_


IOTZ_RETURN expand_key_seed(
    IOTZ_UWORD* rk,
    const IOTZ_UWORD* key,
    const IOTZ_INT keyLen
);
IOTZ_RETURN crypt_seed(
    IOTZ_UWORD* output,
    const IOTZ_UWORD* input,
    const IOTZ_INT keyLen,
    const IOTZ_BLOCK_ENC_DEC sit,
    const IOTZ_UWORD* rk
);



#else

#endif
