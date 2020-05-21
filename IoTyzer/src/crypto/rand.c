#ifdef _MSC_VER
#include <windows.h>
#include <wincrypt.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <util/print.h>
#include <crypto/rand.h>


IOTZ_RETURN generate_rand(IOTZ_UBYTE* buf, IOTZ_INT bufLen)
{
#ifdef _MSC_VER
    HCRYPTPROV hCryptProv;

    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == 0)
    {
        print_error_msg("    Windows crypt initialize error[%X]", GetLastError());

        return IOTZ_RANDOM_NUMBER_INIT_FAIL;
    }

    if (CryptGenRandom(hCryptProv, bufLen, buf) == 0)
    {
        print_error_msg("    Random number generate[%X]", GetLastError());

        return IOTZ_RANDOM_NUMBER_GEN_FAIL;
    }

    if (CryptReleaseContext(hCryptProv, 0) == 0)
    {
        print_error_msg("    Windows crpyt Release error[%X]", GetLastError());

        return IOTZ_RANDOM_NUMBER_FINAL_FAIL;
    }
#else
    IOTZ_INT fd;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        print_error_msg("    Linux urandom open error");

        return IOTZ_RANDOM_NUMBER_INIT_FAIL;
    }

    if (read(fd, buf, bufLen) != bufLen)
    {
        print_error_msg("    Random number generate");

        return IOTZ_RANDOM_NUMBER_GEN_FAIL;
    }

    if (close(fd))
    {
        print_error_msg("    Linux urandom close error");

        return IOTZ_RANDOM_NUMBER_FINAL_FAIL;
    }
#endif

    return IOTZ_OK;
}
