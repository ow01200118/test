#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <libIoTyzer.h>

#include <util/casting.h>
#include <util/print.h>

#include <cavp/kor_hash_short_test.h>

IOTZ_RETURN iotz_read_hash_short_req(
    IOTZ_FILE *fp,
    IOTZ_UBYTE *msg,
    IOTZ_INT *msg_len
)
{
    IOTZ_CHAR buf[BUF_SIZE * 2] = "";
    char tmp;
    /*  skip L = 28, L = 32, L = 48, L = 64     */

    while (tmp != ' ')
        fread(&tmp, 1, 1, fp);
    while (tmp != '\n')
        fread(&tmp, 1, 1, fp);

    while (tmp != ' ')
        fread(&tmp, 1, 1, fp);
    while (tmp != '\n')
        fread(&tmp, 1, 1, fp);


///////////////////////////////////////////////////////
    memset(buf, 0x00, BUF_SIZE);
#ifdef _MSC_VER
    if (fscanf_s(fp, "Msg = %s\n", buf, BUF_SIZE) <= 0)
		return IOTZ_HASH_SHORT_FILE_READ_ERROR;
#else
    if (fscanf(fp, "Msg = %s\n", buf) <= 0)
        return IOTZ_HASH_SHORT_FILE_READ_ERROR;
#endif
    asc_to_byte(msg, buf, (IOTZ_INT)strlen(buf));
    *msg_len = (IOTZ_INT)(strlen(buf) >> 1);
////////////////////////////////////////////////////////

    return IOTZ_OK;
}

IOTZ_RETURN iotz_write_hash_short_rsp(
    IOTZ_FILE *fp,
    IOTZ_UBYTE *msg,
    IOTZ_UBYTE msg_len,
    IOTZ_UBYTE *hash,
    IOTZ_HASH_ALG alg
)
{
    IOTZ_INT i = 0;

    iotz_fprintf(fp, "L = ");

    switch (alg) {
        case IOTZ_SHA2_224:
            iotz_fprintf(fp, "28\n\n");
            iotz_fprintf(fp, "Len = %d\n", msg_len * 8);
            iotz_fprintf(fp, "Msg = ");
            for (i=0; i<msg_len; i++) {
                iotz_fprintf(fp, "%02X", msg[i]);
                
                if (i == (msg_len - 1))
                    iotz_fprintf(fp, "\n");
            }
            iotz_fprintf(fp, "MD = ");
            for (i=0; i<28; i++) {
                iotz_fprintf(fp, "%02X", hash[i]);

                if (i == 27)
                    iotz_fprintf(fp, "\n");
            }
            break;
        case IOTZ_SHA2_256: 
            iotz_fprintf(fp, "32\n\n");
            iotz_fprintf(fp, "Len = %d\n", msg_len * 8);
            for (i=0; i<msg_len; i++) {
                iotz_fprintf(fp, "%02X", msg[i]);
                
                if (i == (msg_len - 1))
                    iotz_fprintf(fp, "\n");
            }
            iotz_fprintf(fp, "MD = ");
            for (i=0; i<32; i++) {
                iotz_fprintf(fp, "%02X", hash[i]);

                if (i == 31)
                    iotz_fprintf(fp, "\n");
            }            
            break;
        case IOTZ_SHA2_384: 
            iotz_fprintf(fp, "48\n\n");
            iotz_fprintf(fp, "Len = %d\n", msg_len * 8);
            for (i=0; i<msg_len; i++) {
                iotz_fprintf(fp, "%02X", msg[i]);
                
                if (i == (msg_len - 1))
                    iotz_fprintf(fp, "\n");
            }
            iotz_fprintf(fp, "MD = ");
            for (i=0; i<48; i++) {
                iotz_fprintf(fp, "%02X", hash[i]);

                if (i == 47)
                    iotz_fprintf(fp, "\n");
            }            
            break;
        case IOTZ_SHA2_512: 
            iotz_fprintf(fp, "64\n\n");
            iotz_fprintf(fp, "Len = %d\n", msg_len * 8);
            for (i=0; i<msg_len; i++) {
                iotz_fprintf(fp, "%02X", msg[i]);
                
                if (i == (msg_len - 1))
                    iotz_fprintf(fp, "\n");
            }
            iotz_fprintf(fp, "MD = ");
            for (i=0; i<64; i++) {
                iotz_fprintf(fp, "%02X", hash[i]);

                if (i == 63)
                    iotz_fprintf(fp, "\n");
            }            
            break;
        default : 
            iotz_fprintf(stdout, "ERROR : INVALID HASH ALGORITHM");
            return IOTZ_HASH_SHORT_INVALID_ALG;
    }

    return IOTZ_OK;
}

IOTZ_RETURN iotz_gen_rsp_hash_korea_short_test(
    const IOTZ_CHAR* file_name,
    IOTZ_HASH_ALG alg
)
{
    IOTZ_CHAR name[FILE_NAME_SIZE] = {0x00, };
    IOTZ_UBYTE msg[BUF_SIZE * 2] = {0x00, };
    IOTZ_UBYTE hash[512] = {0x00, };
    IOTZ_INT msg_len, hash_len;
    IOTZ_FILE *fp1 = NULL, *fp2 = NULL;

    sprintf(name, "%s%sShortMsg.req", PREFIX_FILE_PATH, file_name);
    fp1 = fopen(name, "rt");
    sprintf(name, "%s%sShortMsg.rsp", PREFIX_FILE_PATH, file_name);
    fp2 = fopen(name, "wt");

    if ((fp1 == NULL) || (fp2 == NULL)) {
        print_error_msg("   KAT file open fail");

        return IOTZ_HASH_SHORT_FILE_OPEN_ERROR;
    }

    while (!feof(fp1)) {
        memset(msg, 0x00, BUF_SIZE * 2);

        iotz_read_hash_short_req(fp1, msg, &msg_len);

        query_hash(hash, &hash_len, msg, msg_len, alg);
        
        iotyz_write_hash_short_rsp(fp2, msg, msg_len, hash, alg);
    }

    fclose(fp1);
    fclose(fp2);

    print_log("     Generate Hash response file \'%sKAT.rsp\' done", file_name);

    return IOTZ_OK;
}