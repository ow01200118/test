#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <libIoTyzer.h>

#include <util/casting.h>
#include <util/print.h>

#include <cavp/kor_hash_short_test.h>

void skip_param(FILE **fp)
{
    char tmp;

    while(*(*fp)->_ptr != ' ')
        fread(&tmp, 1, 1, *fp);
    
    while(*(*fp)->_ptr != '\n')
        fread(&tmp, 1, 1, *fp);

    /*  skip \n     */
    fread(&tmp, 1, 1, *fp);
}

IOTZ_RETURN iotz_read_hash_short_req(
    IOTZ_FILE *fp,
    IOTZ_UBYTE *msg,
    IOTZ_INT *msg_len
)
{
    IOTZ_CHAR buf[BUF_SIZE * 2] = "";

    /*  skip L = 28, L = 32, L = 48, L = 64     */
    skip_param(&fp);
    skip_param(&fp);

///////////////////////////////////////////////////////
    memset(buf, 0x00, BUF_SIZE);
#ifdef _MSC_VER
    if (fscanf_s(fp, "Msg = %s\n", buf, BUF_SIZE) <= 0)
		return IOTZ_HASH_SHORT_FILE_READ_ERROR;
#else
    if (fscanf(fp, "Msg = %s\n", buf) <= 0)
        return IOTZ_HASH_SHORT_FILE_READ_ERROR;
#endif
    asc_to_byte(msg_len, buf, (IOTZ_INT)strlen(buf));
    *msg_len = (IOTZ_INT)(strlen(buf) >> 1);
////////////////////////////////////////////////////////

    return IOTZ_OK;
}

IOTZ_RETURN iotz_write_hash_short_rsp(
    IOTZ_FILE *fp,
    IOTZ_UBYTE *msg,
    IOTZ_UBYTE msg_len,
    IOTZ_UBYTE *hash,
    IOTZ_HASH_ALG alg,
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
    IOTZ_HASH_ALG alg,
)
{
    IOTZ_CHAR name[FILE_NAME_SIZE] = {0x00, };
    IOTZ_UBYTE msg[BUF_SIZE * 2] = {0x00, };

    
}