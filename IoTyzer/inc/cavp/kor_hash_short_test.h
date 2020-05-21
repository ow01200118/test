#ifndef _IOTZ_KOR_HASH_SHORT_TEST_H_
#define _IOTZ_KOR_HASH_SHORT_TEST_H_

#define IOTZ_HASH_SHORT_ALGORITHM_NOT_SET   1
#define IOTZ_HASH_SHORT_FILE_OPEN_ERROR     1
#define IOTZ_HASH_SHORT_FILE_READ_ERROR     1
#define IOTZ_HASH_SHORT_INVALID_ALG         1

IOTZ_RETURN iotz_gen_fax_req_hash_korea_short_test(
    const IOTZ_CHAR* file_name,     //file name
    IOTZ_HASH_ALG alg               // SHA2 - 224, 256, 384, 512
);

IOTZ_RETURN iotz_gen_rsp_hash_korea_short_test(
    const IOTZ_CHAR* file_name,
    IOTZ_HASH_ALG alg
);

#endif /*   _IOTZ_KOR_HASH_SHORT_TEST_H_    */
