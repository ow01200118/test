#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <cavp/kor_kat_test.h>
#include <cavp/kor_mmt_test.h>
#include <cavp/kor_mct_test.h>

#include <cavp/cavp.h>

#include <util/print.h>

#include <IoTyzerServer.h>


static IOTZ_RETURN test_socket_server();


IOTZ_RETURN main()
{
    set_print_log_file_path("server");

    print_title("IoTyzer Server!");

    test_socket_server();

#ifdef _MSC_VER
    system("pause");
#endif

    return IOTZ_OK;
}


IOTZ_RETURN test_socket_server()
{
    IOTZ_SOCKET lSocket;
    IOTZ_RETURN ret = IOTZ_OK;

    print_msg("IoTyzer Server initialize");
    ret = iotz_cavp_server_init(&lSocket);
    if (ret != IOTZ_OK)
    {
        print_return_msg(ret, "IoTyzer Server open error");

        return 1;
    }
    
    print_msg("IoTyzer Server service");
    ret = iotz_cavp_server_service(&lSocket);
    print_return_msg(ret, "IoTyzer Server service");

    return IOTZ_OK;
}
