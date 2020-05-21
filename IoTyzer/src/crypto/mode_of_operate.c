#include <string.h>

#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <crypto/aria.h>
#include <crypto/seed.h>
#include <crypto/lea.h>

#include <util/casting.h>
#include <util/print.h>

#include <crypto/mode_of_operate.h>


IOTZ_RETURN blockcipher_ecb_enc(
    IOTZ_UBYTE* out,
    IOTZ_INT* outLen,
    IOTZ_UBYTE* in,
    IOTZ_INT inLen,
    IOTZ_UBYTE* key,
    IOTZ_BLOCK_CIPHER_KEY_SIZE keyLen,
    IOTZ_BLOCK_CIPHER_ALG alg
)
{
    IOTZ_RETURN(*keygen)(
        IOTZ_UWORD * rk,
        const IOTZ_UWORD * key,
        const IOTZ_INT keyLen
        ) = NULL;
    IOTZ_RETURN(*encdec)(
        IOTZ_UWORD * output,
        const IOTZ_UWORD * input,
        const IOTZ_INT keyLen,
        const IOTZ_BLOCK_ENC_DEC sit,
        const IOTZ_UWORD * rk
        ) = NULL;
    IOTZ_UWORD temp[BLOCK_WORD_SIZE << 1] = { 0, };
    IOTZ_UWORD rk[ROUNDKEY_MAXLEN] = { 0, };
    IOTZ_INT rnd = (inLen + 15) / BLOCK_BYTE_SIZE;
    IOTZ_INT i = 0;

    switch (alg)
    {
    case IOTZ_ARIA:
        keygen = expand_enckey_aria;
        encdec = crypt_aria;
        break;
    case IOTZ_SEED:
        keygen = expand_key_seed;
        encdec = crypt_seed;
        break;
    case IOTZ_LEA:
        keygen = expand_key_lea;
        encdec = crypt_lea;
        break;
    default:
        print_log("    [Mode of Operate] Algorithm select error");
        return IOTZ_ALGORITHM_SELECT_ERROR;
    }

    byte_to_word(temp, key, keyLen >> 3);
    keygen(rk, temp, keyLen / 32);

    for (i = 0; i < rnd; i++)
    {
        memset(temp, 0, BLOCK_WORD_SIZE);
        byte_to_word(temp, in + (i * BLOCK_BYTE_SIZE), BLOCK_BYTE_SIZE);
        encdec(temp, temp, keyLen >> 5, IOTZ_ENC, rk);
        word_to_byte(out + (i * BLOCK_BYTE_SIZE), temp, BLOCK_BYTE_SIZE);
    }

    *outLen = inLen;

    return IOTZ_OK;
}

IOTZ_RETURN blockcipher_ecb_dec(
    IOTZ_UBYTE* out,
    IOTZ_INT* outLen,
    IOTZ_UBYTE* in,
    IOTZ_INT inLen,
    IOTZ_UBYTE* key,
    IOTZ_BLOCK_CIPHER_KEY_SIZE keyLen,
    IOTZ_BLOCK_CIPHER_ALG alg
)
{
    IOTZ_RETURN(*keygen)(
        IOTZ_UWORD * rk,
        const IOTZ_UWORD * key,
        const IOTZ_INT keyLen
        ) = NULL;
    IOTZ_RETURN(*encdec)(
        IOTZ_UWORD * output,
        const IOTZ_UWORD * input,
        const IOTZ_INT keyLen,
        const IOTZ_BLOCK_ENC_DEC sit,
        const IOTZ_UWORD * rk
        ) = NULL;
    IOTZ_UWORD temp[BLOCK_WORD_SIZE << 1] = { 0, };
    IOTZ_UWORD rk[ROUNDKEY_MAXLEN] = { 0, };
    IOTZ_INT rnd = (inLen + 15) / BLOCK_BYTE_SIZE;
    IOTZ_INT i = 0;

    switch (alg)
    {
    case IOTZ_ARIA:
        keygen = expand_deckey_aria;
        encdec = crypt_aria;
        break;
    case IOTZ_SEED:
        keygen = expand_key_seed;
        encdec = crypt_seed;
        break;
    case IOTZ_LEA:
        keygen = expand_key_lea;
        encdec = crypt_lea;
        break;
    default:
        print_log("    [Mode of Operate] Algorithm select error");
        return IOTZ_ALGORITHM_SELECT_ERROR;
    }

    byte_to_word(temp, key, keyLen >> 3);
    keygen(rk, temp, keyLen / 32);

    for (i = 0; i < rnd; i++)
    {
        memset(temp, 0, BLOCK_WORD_SIZE);
        byte_to_word(temp, in + (i * BLOCK_BYTE_SIZE), BLOCK_BYTE_SIZE);
        encdec(temp, temp, keyLen >> 5, IOTZ_DEC, rk);
        word_to_byte(out + (i * BLOCK_BYTE_SIZE), temp, BLOCK_BYTE_SIZE);
    }

    *outLen = inLen;

    return IOTZ_OK;
}
