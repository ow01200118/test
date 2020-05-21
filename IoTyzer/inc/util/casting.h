#ifndef _IOTZ_CASTING_H_
#define _IOTZ_CASTING_H_


IOTZ_VOID byte_to_dword(IOTZ_UDWORD* out, const IOTZ_UBYTE* in, IOTZ_INT byteLen);
IOTZ_VOID byte_to_word(IOTZ_UWORD* out, const IOTZ_UBYTE* in, IOTZ_INT byteLen);
IOTZ_VOID dword_to_byte(IOTZ_UBYTE* out, const IOTZ_UDWORD* in, IOTZ_INT byteLen);
IOTZ_VOID word_to_byte(IOTZ_UBYTE* out, const IOTZ_UWORD* in, IOTZ_INT byteLen);
IOTZ_VOID asc_to_byte(IOTZ_UBYTE* hex, const IOTZ_CHAR* asc, IOTZ_INT len);



#else

#endif
