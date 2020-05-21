#ifndef _IOTZ_LEA_H_
#define _IOTZ_LEA_H_


IOTZ_RETURN expand_key_lea(
    IOTZ_UWORD* rk,
    const IOTZ_UWORD* key,
    const IOTZ_INT keyLen
);
IOTZ_RETURN crypt_lea(
    IOTZ_UWORD* output,
    const IOTZ_UWORD* input,
    const IOTZ_INT keyLen,
    const IOTZ_BLOCK_ENC_DEC sit,
    const IOTZ_UWORD* rk
);



#else

#endif
