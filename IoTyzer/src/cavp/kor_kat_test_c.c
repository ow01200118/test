#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <libIoTyzer.h>

#include <util/casting.h>
#include <util/print.h>

#include <cavp/kor_kat_test.h>


IOTZ_RETURN iotz_read_kat_req(
    IOTZ_FILE* fp,
    IOTZ_UBYTE* key,
    IOTZ_INT* keyLen,
    IOTZ_UBYTE* iv,
    IOTZ_INT* ivLen,
    IOTZ_UBYTE* pt,
    IOTZ_INT* ptLen,
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode
)
{
    IOTZ_CHAR buf[BUF_SIZE] = "";

    memset(buf, 0x00, BUF_SIZE);
#ifdef _MSC_VER
    if (fscanf_s(fp, "KEY = %s\n", buf, BUF_SIZE) <= 0)
		return IOTZ_KAT_FILE_READ_ERROR;
#else
    if (fscanf(fp, "KEY = %s\n", buf) <= 0)
        return IOTZ_KAT_FILE_READ_ERROR;
#endif
    asc_to_byte(key, buf, (IOTZ_INT)strlen(buf));
    *keyLen = (IOTZ_INT)(strlen(buf) >> 1);

    if (mode != IOTZ_ECB)
    {
        memset(buf, 0x00, BUF_SIZE);
#ifdef _MSC_VER
        if (fscanf_s(fp, "IV = %s\n", buf, BUF_SIZE) <= 0)
			return IOTZ_KAT_FILE_READ_ERROR;
#else
        if (fscanf(fp, "IV = %s\n", buf) <= 0)
            return IOTZ_KAT_FILE_READ_ERROR;
#endif
        asc_to_byte(iv, buf, (IOTZ_INT)strlen(buf));
        *ivLen = (IOTZ_INT)(strlen(buf) >> 1);
    }

    memset(buf, 0x00, BUF_SIZE);
#ifdef _MSC_VER
    if (fscanf_s(fp, "PT = %s\n\n", buf, BUF_SIZE) <= 0)
		return IOTZ_KAT_FILE_READ_ERROR;
#else
    if (fscanf(fp, "PT = %s\n\n", buf) <= 0)
        return IOTZ_KAT_FILE_READ_ERROR;
#endif
    asc_to_byte(pt, buf, (IOTZ_INT)strlen(buf));
    *ptLen = (IOTZ_INT)(strlen(buf) >> 1);

    return IOTZ_OK;
}

IOTZ_RETURN iotz_write_kat_rsp(
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
        for (i = 0; i < ivLen; i++)
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

IOTZ_RETURN iotz_gen_rsp_blockcipher_korea_kat_test(
    const IOTZ_CHAR* fName,                 // File Name
    IOTZ_BLOCK_CIPHER_ALG alg,              // ARIA, SEED, LEA
    IOTZ_BLOCK_CIPHER_KEY_SIZE keySize,     // 128, 192, 256(if block cipher is SEED, then key size fixed 128bit
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode   // ECB, CBC, CFB1, CFB8, CFB32, CFB64, CFB128, OFB, CTR
)
{
    IOTZ_CHAR fileName[FILE_NAME_SIZE] = "";
    IOTZ_UBYTE key[MAX_KEY_SIZE] = { 0x00, };
    IOTZ_UBYTE iv[BLOCK_BYTE_SIZE] = { 0x00, };
    IOTZ_UBYTE pt[BLOCK_BYTE_SIZE] = { 0x00, };
    IOTZ_UBYTE ct[BLOCK_BYTE_SIZE] = { 0x00, };
    IOTZ_INT ctLen = BLOCK_BYTE_SIZE, ptLen = BLOCK_BYTE_SIZE, ivLen = BLOCK_BYTE_SIZE, keyLen = keySize >> 3;
    IOTZ_FILE* fp1 = NULL, * fp2 = NULL;

#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sKAT.req", PREFIX_FILE_PATH, fName);
    fopen_s(&fp1, fileName, "rt");
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sKAT.rsp", PREFIX_FILE_PATH, fName);
    fopen_s(&fp2, fileName, "wt");
#else
    sprintf(fileName, "%s%sKAT.req", PREFIX_FILE_PATH, fName);
    fp1 = fopen(fileName, "rt");
    sprintf(fileName, "%s%sKAT.rsp", PREFIX_FILE_PATH, fName);
    fp2 = fopen(fileName, "wt");
#endif

    if ((fp1 == NULL) || (fp2 == NULL))
    {
        print_error_msg("    KAT file open fail");

        return IOTZ_KAT_FILE_OPEN_ERROR;
    }

    while (!feof(fp1))
    {
        memset(key, 0x00, MAX_KEY_SIZE);
        memset(iv, 0x00, BLOCK_BYTE_SIZE);
        memset(pt, 0x00, BLOCK_BYTE_SIZE);
        memset(ct, 0x00, BLOCK_BYTE_SIZE);

        iotz_read_kat_req(fp1, key, &keyLen, iv, &ivLen, pt, &ptLen, mode);

        query_blockcipher_enc(ct, &ctLen, pt, ptLen, iv, ivLen, key, keyLen, mode, alg);

        iotz_write_kat_rsp(fp2, key, keyLen, iv, ivLen, pt, ptLen, ct, ctLen, mode);
    }

    fclose(fp1);
    fclose(fp2);

    print_log("    Generate KAT respnse file \'%sKAT.rsp\' done", fName);

    return IOTZ_OK;
}
