#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <util/casting.h>


IOTZ_VOID byte_to_dword(IOTZ_UDWORD* out, const IOTZ_UBYTE* in, IOTZ_INT byteLen)
{
    IOTZ_INT len = (byteLen + 7) >> 3, i = 0;

    for (i = 0; i < len; i++)
        out[i] = 0;

    for (i = 0; i < byteLen; i++)
    {
        switch (i & 7)
        {
        case 0:
            out[i >> 3] |= (IOTZ_UDWORD)in[i] << 56;
            break;
        case 1:
            out[i >> 3] |= (IOTZ_UDWORD)in[i] << 48;
            break;
        case 2:
            out[i >> 3] |= (IOTZ_UDWORD)in[i] << 40;
            break;
        case 3:
            out[i >> 3] |= (IOTZ_UDWORD)in[i] << 32;
            break;
        case 4:
            out[i >> 3] |= (IOTZ_UDWORD)in[i] << 24;
            break;
        case 5:
            out[i >> 3] |= (IOTZ_UDWORD)in[i] << 16;
            break;
        case 6:
            out[i >> 3] |= (IOTZ_UDWORD)in[i] << 8;
            break;
        case 7:
            out[i >> 3] |= (IOTZ_UDWORD)in[i];
            break;
        }
    }
}

IOTZ_VOID byte_to_word(IOTZ_UWORD* out, const IOTZ_UBYTE* in, IOTZ_INT byteLen)
{
    IOTZ_INT len = (byteLen + 3) >> 2, i = 0;

    for (i = 0; i < len; i++)
        out[i] = 0;

    for (i = 0; i < byteLen; i++)
    {
        switch (i & 3)
        {
        case 0:
            out[i >> 2] |= (IOTZ_UWORD)in[i] << 24;
            break;
        case 1:
            out[i >> 2] |= (IOTZ_UWORD)in[i] << 16;
            break;
        case 2:
            out[i >> 2] |= (IOTZ_UWORD)in[i] << 8;
            break;
        case 3:
            out[i >> 2] |= (IOTZ_UWORD)in[i];
            break;
        }
    }
}

IOTZ_VOID dword_to_byte(IOTZ_UBYTE* out, const IOTZ_UDWORD* in, IOTZ_INT byteLen)
{
    IOTZ_INT i = 0;

    for (i = 0; i < byteLen; i++)
        out[i] = 0;

    for (i = 0; i < byteLen; i++)
    {
        switch (i & 7)
        {
        case 0:
            out[i] = (IOTZ_UBYTE)((in[i >> 3] >> 56) & 0xFF);
            break;
        case 1:
            out[i] = (IOTZ_UBYTE)((in[i >> 3] >> 48) & 0xFF);
            break;
        case 2:
            out[i] = (IOTZ_UBYTE)((in[i >> 3] >> 40) & 0xFF);
            break;
        case 3:
            out[i] = (IOTZ_UBYTE)((in[i >> 3] >> 32) & 0xFF);
            break;
        case 4:
            out[i] = (IOTZ_UBYTE)((in[i >> 3] >> 24) & 0xFF);
            break;
        case 5:
            out[i] = (IOTZ_UBYTE)((in[i >> 3] >> 16) & 0xFF);
            break;
        case 6:
            out[i] = (IOTZ_UBYTE)((in[i >> 3] >> 8) & 0xFF);
            break;
        case 7:
            out[i] = (IOTZ_UBYTE)((in[i >> 3]) & 0xFF);
            break;
        }
    }
}

IOTZ_VOID word_to_byte(IOTZ_UBYTE* out, const IOTZ_UWORD* in, IOTZ_INT byteLen)
{
    IOTZ_INT i = 0;

    for (i = 0; i < byteLen; i++)
        out[i] = 0;

    for (i = 0; i < byteLen; i++)
    {
        switch (i & 3)
        {
        case 0:
            out[i] = (IOTZ_UBYTE)((in[i >> 2] >> 24) & 0xFF);
            break;
        case 1:
            out[i] = (IOTZ_UBYTE)((in[i >> 2] >> 16) & 0xFF);
            break;
        case 2:
            out[i] = (IOTZ_UBYTE)((in[i >> 2] >> 8) & 0xFF);
            break;
        case 3:
            out[i] = (IOTZ_UBYTE)((in[i >> 2]) & 0xFF);
            break;
        }
    }
}

IOTZ_VOID asc_to_byte(IOTZ_UBYTE* hex, const IOTZ_CHAR* asc, IOTZ_INT len)
{
    IOTZ_UBYTE tmp;
    IOTZ_INT i = 0;

    for (i = 0; i < len; i++)
    {
        if ((asc[i] >= '0') && (asc[i] <= '9'))
            tmp = (uint8_t)(asc[i] - '0');
        else if ((asc[i] >= 'A') && (asc[i] <= 'F'))
            tmp = (uint8_t)(asc[i] - 'A' + 10);
        else if ((asc[i] >= 'a') && (asc[i] <= 'f'))
            tmp = (uint8_t)(asc[i] - 'a' + 10);
        else
            tmp = 0;

        if (i & 1)
            hex[i >> 1] |= (tmp & 0x0F);
        else
            hex[i >> 1] = (tmp & 0x0F) << 4;
    }
}

