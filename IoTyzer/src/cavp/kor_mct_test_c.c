#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <libIoTyzer.h>

#include <util/casting.h>
#include <util/print.h>

#include <cavp/kor_mct_test.h>


IOTZ_RETURN iotz_read_mct_req(
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
		return IOTZ_MCT_FILE_READ_ERROR;
#else
    if (fscanf(fp, "KEY = %s\n", buf) <= 0)
        return IOTZ_MCT_FILE_READ_ERROR;
#endif
    asc_to_byte(key, buf, (IOTZ_INT)strlen(buf));
    *keyLen = (IOTZ_INT)(strlen(buf) >> 1);

    if (mode != IOTZ_ECB)
    {
        memset(buf, 0x00, BUF_SIZE);
#ifdef _MSC_VER
        if (fscanf_s(fp, "IV = %s\n", buf, BUF_SIZE) <= 0)
			return IOTZ_MCT_FILE_READ_ERROR;
#else
        if (fscanf(fp, "IV = %s\n", buf) <= 0)
            return IOTZ_MCT_FILE_READ_ERROR;
#endif
        asc_to_byte(iv, buf, (IOTZ_INT)strlen(buf));
        *ivLen = (IOTZ_INT)(strlen(buf) >> 1);
    }

    memset(buf, 0x00, BUF_SIZE);
#ifdef _MSC_VER
    if (fscanf_s(fp, "PT = %s\n\n", buf, BUF_SIZE) <= 0)
		return IOTZ_MCT_FILE_READ_ERROR;
#else
    if (fscanf(fp, "PT = %s\n\n", buf) <= 0)
        return IOTZ_MCT_FILE_READ_ERROR;
#endif
    asc_to_byte(pt, buf, (IOTZ_INT)strlen(buf));
    *ptLen = (IOTZ_INT)(strlen(buf) >> 1);

    return IOTZ_OK;
}

IOTZ_RETURN iotz_write_mct_rsp(
    IOTZ_FILE* fp,
    IOTZ_UBYTE* key,
    IOTZ_INT keyLen,
    IOTZ_UBYTE* iv,
    IOTZ_INT ivLen,
    IOTZ_UBYTE* pt,
    IOTZ_INT ptLen,
    IOTZ_UBYTE* ct,
    IOTZ_INT ctLen,
    IOTZ_BLOCK_CIPHER_MODE_OPERATION mode,
    IOTZ_INT count
)
{
    IOTZ_INT i = 0;

#ifdef _MSC_VER
    fprintf_s(fp, "COUNT = %d\n", count);
#else
    fprintf(fp, "KEY = %d\n", count);
#endif

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

IOTZ_RETURN iotz_mct_ecb_rsp(
    IOTZ_FILE* fp,
    IOTZ_UBYTE* key,
    IOTZ_INT keyLen,
    IOTZ_UBYTE* pt,
    IOTZ_INT ptLen,
    IOTZ_BLOCK_CIPHER_ALG alg
)
{
    IOTZ_UBYTE tKey[MAX_KEY_SIZE] = { 0x00, };
    IOTZ_UBYTE tPt[BLOCK_BYTE_SIZE] = { 0x00, };
    IOTZ_UBYTE ct[BLOCK_BYTE_SIZE] = { 0x00, };
    IOTZ_UBYTE temp[MAX_KEY_SIZE] = { 0x00, };
    IOTZ_INT ctLen = 0, offset = 0;
    IOTZ_INT i = 0, j = 0;

#ifdef _MSC_VER
    memcpy_s(tKey, MAX_KEY_SIZE, key, keyLen >> 3);
    memcpy_s(tPt, BLOCK_BYTE_SIZE, pt, ptLen);
#else
    memcpy(tKey, key, keyLen >> 3);
    memcpy(tPt, pt, ptLen);
#endif

    for (i = 0; i < IOTZ_MCT_TEST_COUNT; i++)
    {
        offset = 0;

        for (j = 0; j < IOTZ_MCT_TEST_ROUND - 1; j++)
        {
			query_blockcipher_enc(ct, &ctLen, tPt, ptLen, NULL, 0, tKey, keyLen >> 3, IOTZ_ECB, alg);

#ifdef _MSC_VER
            memcpy_s(tPt, BLOCK_BYTE_SIZE, ct, ctLen);
#else
            memcpy(tPt, ct, ctLen);
#endif
        }

        if (keyLen == IOTZ_192BIT_KEY)
        {
#ifdef _MSC_VER
            memcpy_s(temp, MAX_KEY_SIZE, tPt, BLOCK_BYTE_SIZE >> 1);
#else
            memcpy(temp, tPt, BLOCK_BYTE_SIZE >> 1);
#endif
            offset += BLOCK_BYTE_SIZE >> 1;
        }
        else if (keyLen == IOTZ_256BIT_KEY)
        {
#ifdef _MSC_VER
            memcpy_s(temp, MAX_KEY_SIZE, tPt, BLOCK_BYTE_SIZE);
#else
            memcpy(temp, tPt, BLOCK_BYTE_SIZE);
#endif
            offset += BLOCK_BYTE_SIZE;
        }

		query_blockcipher_enc(ct, &ctLen, tPt, ptLen, NULL, 0, tKey, keyLen >> 3, IOTZ_ECB, alg);

        iotz_write_mct_rsp(fp, tKey, keyLen >> 3, NULL, 0, tPt, ptLen, ct, ctLen, IOTZ_ECB, i);

#ifdef _MSC_VER
        memcpy_s(temp + offset, MAX_KEY_SIZE, ct, BLOCK_BYTE_SIZE);
        memcpy_s(tKey, MAX_KEY_SIZE, temp, keyLen >> 3);

        memcpy_s(tPt, BLOCK_BYTE_SIZE, ct, ctLen);
#else
        memcpy(temp + offset, ct, BLOCK_BYTE_SIZE);
        memcpy(tKey, temp, keyLen >> 3);

        memcpy(tPt, ct, ctLen);
#endif
        print_process(i + 1, IOTZ_MCT_TEST_COUNT);
    }

    return IOTZ_OK;
}

IOTZ_RETURN iotz_gen_rsp_blockcipher_korea_mct_test(
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
    IOTZ_INT ptLen = BLOCK_BYTE_SIZE, ivLen = BLOCK_BYTE_SIZE, keyLen = keySize >> 3;
    IOTZ_FILE* fp1 = NULL, * fp2 = NULL;

#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMCT.req", PREFIX_FILE_PATH, fName);
    fopen_s(&fp1, fileName, "rt");
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMCT.rsp", PREFIX_FILE_PATH, fName);
    fopen_s(&fp2, fileName, "wt");
#else
    sprintf(fileName, "%s%sMCT.req", PREFIX_FILE_PATH, fName);
    fp1 = fopen(fileName, "rt");
    sprintf(fileName, "%s%sMCT.rsp", PREFIX_FILE_PATH, fName);
    fp2 = fopen(fileName, "wt");
#endif

    if ((fp1 == NULL) || (fp2 == NULL))
    {
        print_error_msg("    MCT file open fail");

        return IOTZ_MCT_FILE_OPEN_ERROR;
    }

    memset(key, 0x00, MAX_KEY_SIZE);
    memset(iv, 0x00, BLOCK_BYTE_SIZE);
    memset(pt, 0x00, BLOCK_BYTE_SIZE);

    iotz_read_mct_req(fp1, key, &keyLen, iv, &ivLen, pt, &ptLen, mode);

    fclose(fp1);

    switch (mode)
    {
    case IOTZ_ECB:
        iotz_mct_ecb_rsp(fp2, key, keySize, pt, ptLen, alg);
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

    fclose(fp2);

    print_log("    Generate MCT Request \'%sMCT.rsp\' done", fName);

    return IOTZ_OK;
}
