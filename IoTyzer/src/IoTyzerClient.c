#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <cavp/kor_kat_test.h>
#include <cavp/kor_mmt_test.h>
#include <cavp/kor_mct_test.h>

#include <cavp/cavp.h>

#include <libIoTyzer.h>

#include <util/print.h>

#include <IoTyzerClient.h>


static IOTZ_RETURN test_dev_info();
static IOTZ_RETURN test_iotz_request_cavp(IOTZ_CAVP_TEST_CODE code);
static IOTZ_RETURN test_iotz_request_test(IOTZ_CAVP_TEST_CODE code);
static IOTZ_RETURN test_iotz_request_submit(IOTZ_CAVP_TEST_CODE code);


IOTZ_RETURN main()
{
    IOTZ_CAVP_TEST_CODE code;
    IOTZ_RETURN ret = IOTZ_OK;

    set_print_log_file_path("client");

    print_title("IoTyzer Client!");

    initialize_target();

    test_dev_info();

    code = IOTZ_SHA_224;

    print_msg("IoTyzer Client request test");
    ret = test_iotz_request_test(code);
    print_return_msg(ret, "return msg(request test to target)");    

#ifdef _MSC_VER
    system("pause");
#endif

    return IOTZ_OK;
}

IOTZ_RETURN test_dev_info()
{
    IOTZ_DEV_INFO dev_info = { 0, };

    print_msg("IoTyzer Client get device info");

    iotz_get_iotyzer_dev_info(&dev_info);

    print_log("  IoTyzer Device Info");
    print_log("    Vendor        : %s", dev_info.dev_vender);
    print_log("    Model Name    : %s", dev_info.dev_model_num);
    print_log("    Serial Number : %s", dev_info.dev_serial_num);

    return IOTZ_OK;
}

IOTZ_RETURN test_iotz_request_cavp(IOTZ_CAVP_TEST_CODE code)
{
    IOTZ_CHAR str[FILE_NAME_SIZE] = "";
    IOTZ_RETURN ret = IOTZ_OK;

#ifdef _MSC_VER
    sprintf_s(str, FILE_NAME_SIZE, "%s", iotz_get_file_name(code));
#else
    sprintf(str, "%s", iotz_get_file_name(code));
#endif

    print_msg("  [Request CAVP] Request %s CAVP test file", str);
    ret = iotz_request_testvector(code);
    print_return_msg(ret, "  [Request CAVP] Request %s CAVP test file", str);
    if (ret != IOTZ_OK)
        return IOTZ_SERVER_RES_CAVP_ERROR;

    return IOTZ_OK;
}

IOTZ_RETURN test_iotz_request_test(IOTZ_CAVP_TEST_CODE code)
{
    IOTZ_CHAR str[FILE_NAME_SIZE] = "";
    IOTZ_RETURN ret = IOTZ_OK;

#ifdef _MSC_VER
    sprintf_s(str, FILE_NAME_SIZE, "%s", iotz_get_file_name(code));
#else
    sprintf(str, "%s", iotz_get_file_name(code));
#endif

    print_msg("  [Request CAVP] Request %s CAVP test to target", str);
    ret = iotz_request_bc_test(code);
    print_return_msg(ret, "  [Request CAVP] Request %s CAVP test to target", str);
    if (ret != IOTZ_OK)
        return IOTZ_SERVER_RES_SUBMIT_ERROR;

    return IOTZ_OK;

}

IOTZ_RETURN test_iotz_request_submit(IOTZ_CAVP_TEST_CODE code)
{
    IOTZ_CHAR str[FILE_NAME_SIZE] = "";
    IOTZ_RETURN ret = IOTZ_OK;

#ifdef _MSC_VER
    sprintf_s(str, FILE_NAME_SIZE, "%s", iotz_get_file_name(code));
#else
    sprintf(str, "%s", iotz_get_file_name(code));
#endif

    print_msg("  [Request CAVP] Request %s CAVP test submission", str);
    ret = iotz_request_submit(code);
    print_return_msg(ret, "  [Request CAVP] Request %s CAVP test submission", str);
    if (ret != IOTZ_OK)
        return IOTZ_SERVER_RES_SUBMIT_ERROR;

    return IOTZ_OK;
}
