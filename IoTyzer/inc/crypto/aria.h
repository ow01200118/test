#ifndef _IOTZ_ARIA_H_
#define _IOTZ_ARIA_H_


IOTZ_RETURN expand_enckey_aria(
    IOTZ_UWORD* rk,
    const IOTZ_UWORD* key,
    const IOTZ_INT keyLen
);
IOTZ_RETURN expand_deckey_aria(
    IOTZ_UWORD* rk,
    const IOTZ_UWORD* key,
    const IOTZ_INT keyLen
);
IOTZ_RETURN crypt_aria(
    IOTZ_UWORD* output,
    const IOTZ_UWORD* input,
    const IOTZ_INT keyLen,
    const IOTZ_BLOCK_ENC_DEC sit,
    const IOTZ_UWORD* rk
);



#else

#endif
