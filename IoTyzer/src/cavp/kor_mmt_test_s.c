#include <string.h>

#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <crypto/rand.h>
#include <crypto/mode_of_operate.h>

#include <util/casting.h>
#include <util/print.h>

#include <cavp/kor_mmt_test.h>


IOTZ_RETURN iotz_write_mmt_req(
    IOTZ_FILE* fp,
    IOTZ_UBYTE* key,
    IOTZ_INT keyLen,
    IOTZ_UBYTE* iv,
    IOTZ_INT ivLen,
    IOTZ_UBYTE* pt,
    IOTZ_INT ptLen,
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode
)
{
    IOTZ_INT i = 0;

#ifdef _MSC_VER
    fprintf_s(fp, "KEY = ");
#else
    fprintf(fp, "KEY = ");
#endif
    for (i = 0; i < keyLen; i++)
    {
#ifdef _MSC_VER
        fprintf_s(fp, "%02X", key[i]);
#else
        fprintf(fp, "%02X", key[i]);
#endif
    }
#ifdef _MSC_VER
    fprintf_s(fp, "\n");
#else
    fprintf(fp, "\n");
#endif

    if (mode != IOTZ_ECB)
    {
#ifdef _MSC_VER
        fprintf_s(fp, "IV = ");
#else
        fprintf(fp, "IV = ");
#endif
        for (i = 0; i < BLOCK_BYTE_SIZE; i++)
        {
#ifdef _MSC_VER
            fprintf_s(fp, "%02X", iv[i]);
#else
            fprintf(fp, "%02X", iv[i]);
#endif
        }
#ifdef _MSC_VER
        fprintf_s(fp, "\n");
#else
        fprintf(fp, "\n");
#endif
    }

#ifdef _MSC_VER
    fprintf_s(fp, "PT = ");
#else
    fprintf(fp, "PT = ");
#endif
    if (mode == IOTZ_CFB1)
    {
#ifdef _MSC_VER
        fprintf_s(fp, "%1d", pt[0] >> 7);
#else
        fprintf(fp, "%1d", pt[0] >> 7);
#endif
    }
    else
    {
        for (i = 0; i < ptLen; i++)
        {
#ifdef _MSC_VER
            fprintf_s(fp, "%02X", pt[i]);
#else
            fprintf(fp, "%02X", pt[i]);
#endif
        }
    }
#ifdef _MSC_VER
    fprintf_s(fp, "\n\n");
#else
    fprintf(fp, "\n\n");
#endif

    return IOTZ_OK;
}

IOTZ_RETURN iotz_write_mmt_fax(
    IOTZ_FILE* fp,
    IOTZ_UBYTE* key,
    IOTZ_INT keyLen,
    IOTZ_UBYTE* iv,
    IOTZ_INT ivLen,
    IOTZ_UBYTE* pt,
    IOTZ_INT ptLen,
    IOTZ_UBYTE* ct,
    IOTZ_INT ctLen,
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode
)
{
    IOTZ_INT i = 0;

#ifdef _MSC_VER
    fprintf_s(fp, "KEY = ");
#else
    fprintf(fp, "KEY = ");
#endif
    for (i = 0; i < keyLen; i++)
    {
#ifdef _MSC_VER
        fprintf_s(fp, "%02X", key[i]);
#else
        fprintf(fp, "%02X", key[i]);
#endif
    }
#ifdef _MSC_VER
    fprintf_s(fp, "\n");
#else
    fprintf(fp, "\n");
#endif

    if (mode != IOTZ_ECB)
    {
#ifdef _MSC_VER
        fprintf_s(fp, "IV = ");
#else
        fprintf(fp, "IV = ");
#endif
        for (i = 0; i < BLOCK_BYTE_SIZE; i++)
        {
#ifdef _MSC_VER
            fprintf_s(fp, "%02X", iv[i]);
#else
            fprintf(fp, "%02X", iv[i]);
#endif
        }
#ifdef _MSC_VER
        fprintf_s(fp, "\n");
#else
        fprintf(fp, "\n");
#endif
    }

#ifdef _MSC_VER
    fprintf_s(fp, "PT = ");
#else
    fprintf(fp, "PT = ");
#endif
    if (mode == IOTZ_CFB1)
    {
#ifdef _MSC_VER
        fprintf_s(fp, "%1d", pt[0] >> 7);
#else
        fprintf(fp, "%1d", pt[0] >> 7);
#endif
    }
    else
    {
        for (i = 0; i < ptLen; i++)
        {
#ifdef _MSC_VER
            fprintf_s(fp, "%02X", pt[i]);
#else
            fprintf(fp, "%02X", pt[i]);
#endif
        }
    }
#ifdef _MSC_VER
    fprintf_s(fp, "\n");
#else
    fprintf(fp, "\n");
#endif

#ifdef _MSC_VER
    fprintf_s(fp, "CT = ");
#else
    fprintf(fp, "CT = ");
#endif
    if (mode == IOTZ_CFB1)
    {
#ifdef _MSC_VER
        fprintf_s(fp, "%1d", ct[0] >> 7);
#else
        fprintf(fp, "%1d", ct[0] >> 7);
#endif
    }
    else
    {
        for (i = 0; i < ctLen; i++)
        {
#ifdef _MSC_VER
            fprintf_s(fp, "%02X", ct[i]);
#else
            fprintf(fp, "%02X", ct[i]);
#endif
        }
    }
#ifdef _MSC_VER
    fprintf_s(fp, "\n\n");
#else
    fprintf(fp, "\n\n");
#endif

    return IOTZ_OK;
}

IOTZ_RETURN iotz_gen_fax_req_blockcipher_korea_mmt_test(
    const IOTZ_CHAR* fName,                 // File Name
    IOTZ_BLOCK_CIPHER_ALG alg,              // ARIA, SEED, LEA
    IOTZ_BLOCK_CIPHER_KEY_SIZE keySize,     // 128, 192, 256(if block cipher is SEED, then key size fixed 128bit
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode   // ECB, CBC, CFB1, CFB8, CFB32, CFB64, CFB128, OFB, CTR
)
{
    IOTZ_CHAR fileName[FILE_NAME_SIZE] = "";
    IOTZ_UBYTE key[MAX_KEY_SIZE] = { 0x00, };
    IOTZ_UBYTE iv[BLOCK_BYTE_SIZE] = { 0x00, };
    IOTZ_UBYTE pt[BLOCK_BYTE_SIZE * IOTZ_MMT_TEST_COUNT] = { 0x00, };
    IOTZ_UBYTE ct[BLOCK_BYTE_SIZE * IOTZ_MMT_TEST_COUNT] = { 0x00, };
    IOTZ_INT ctLen = 0, ptLen = 0, ivLen = BLOCK_BYTE_SIZE, keyLen = keySize >> 3;
    IOTZ_FILE* fp1 = NULL, * fp2 = NULL;
    IOTZ_INT i = 0;

#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMMT.req", PREFIX_FILE_PATH, fName);
    fopen_s(&fp1, fileName, "wt");
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMMT.fax", PREFIX_FILE_PATH, fName);
    fopen_s(&fp2, fileName, "wt");
#else
    sprintf(fileName, "%s%sMMT.req", PREFIX_FILE_PATH, fName);
    fp1 = fopen(fileName, "wt");
    sprintf(fileName, "%s%sMMT.fax", PREFIX_FILE_PATH, fName);
    fp2 = fopen(fileName, "wt");
#endif

    if ((fp1 == NULL) || (fp2 == NULL))
    {
        print_error_msg("    MMT file open fail");

        return IOTZ_MMT_FILE_OPEN_ERROR;
    }

    for (i = 0; i < IOTZ_MMT_TEST_COUNT; i++)
    {
        memset(key, 0x00, MAX_KEY_SIZE);
        memset(iv, 0x00, BLOCK_BYTE_SIZE);
        memset(pt, 0x00, BLOCK_BYTE_SIZE * IOTZ_MMT_TEST_COUNT);
        memset(ct, 0x00, BLOCK_BYTE_SIZE * IOTZ_MMT_TEST_COUNT);

        if (mode == IOTZ_CFB1)
            ptLen = ((1 * (i + 1)) + 7) >> 3;
        else if (mode == IOTZ_CFB8)
            ptLen = 1 * (i + 1);
        else if (mode == IOTZ_CFB32)
            ptLen = 4 * (i + 1);
        else if (mode == IOTZ_CFB64)
            ptLen = 8 * (i + 1);
        else
            ptLen = BLOCK_BYTE_SIZE * (i + 1);

        generate_rand(key, keyLen);
        generate_rand(pt, ptLen);

        if (mode != IOTZ_ECB)
            generate_rand(iv, BLOCK_BYTE_SIZE);

        iotz_write_mmt_req(fp1, key, keyLen, iv, ivLen, pt, ptLen, mode);

        switch (mode)
        {
        case IOTZ_ECB:
            blockcipher_ecb_enc(ct, &ctLen, pt, ptLen, key, keySize, alg);
            break;
        case IOTZ_CBC:
            break;
        case IOTZ_CFB1:
            break;
        case IOTZ_CFB8:
            break;
        case IOTZ_CFB32:
            break;
        case IOTZ_CFB64:
            break;
        case IOTZ_CFB128:
            break;
        case IOTZ_OFB:
            break;
        case IOTZ_CTR:
            break;
        default:
            break;
        }

        iotz_write_mmt_fax(fp2, key, keyLen, iv, ivLen, pt, ptLen, ct, ctLen, mode);
    }

    fclose(fp1);
    fclose(fp2);

    print_log("    Generate MMT Request \'%sMMT.req\' \'%sMMT.fax\' done", fName, fName);

    return IOTZ_OK;
}
