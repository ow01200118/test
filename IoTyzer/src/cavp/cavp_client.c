#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <cavp/kor_kat_test.h>
#include <cavp/kor_mmt_test.h>
#include <cavp/kor_mct_test.h>

#include <util/print.h>

#include <cavp/cavp.h>


IOTZ_RETURN iotz_cavp_server_connect(IOTZ_SOCKET* cSocket)
{
    IOTZ_SOCKET tmpSocket;
    IOTZ_RETURN ret = IOTZ_OK;

    ret = client_socket_open(&tmpSocket);

    if (ret != IOTZ_OK)
    {
        print_return_msg(ret, "  Client socket open error");

        return IOTZ_CLIENT_SOCKET_OPEN_ERROR;
    }

    *cSocket = tmpSocket;

    return IOTZ_OK;
}

IOTZ_RETURN iotz_request_cavp(IOTZ_CAVP_TEST_CODE code)
{
    IOTZ_UBYTE buf[IOTZ_SOCKET_BUF_SIZE] = { 0x00, };
    IOTZ_CAVP_FRAME* pFrame = (IOTZ_CAVP_FRAME*)buf;
    IOTZ_CHAR str[FILE_NAME_SIZE] = "", fileName[FILE_NAME_SIZE] = "";
    IOTZ_SOCKET cSocket;
    IOTZ_RETURN ret = IOTZ_OK;

#ifdef _MSC_VER
    sprintf_s(str, FILE_NAME_SIZE, "%s", iotz_get_file_name(code));
#else
    sprintf(str, "%s", iotz_get_file_name(code));
#endif
    ret = iotz_cavp_server_connect(&cSocket);
    if (ret != IOTZ_OK)
    {
        print_return_msg(ret, "    [Request CAVP] Connect to server error");

        return IOTZ_CONNECT_SERVER_ERROR;
    }

    pFrame->code = IOTZ_CAVP_REQ_CAVP;
    pFrame->data = code;

    send(cSocket, buf, sizeof(IOTZ_CAVP_FRAME), 0);

    if (code >= IOTZ_ARIA_128_ECB && code <= IOTZ_LEA_256_CTR) {
        // KAT recv req file
#ifdef _MSC_VER
        sprintf_s(fileName, FILE_NAME_SIZE, "%s%sKAT.req", PREFIX_FILE_PATH, str);
#else
        sprintf(fileName, "%s%sKAT.req", PREFIX_FILE_PATH, str);
#endif
        ret = iotz_recv_test_file(fileName, cSocket);
        print_return_msg(ret, "    [Request CAVP] Recv %sKAT.req file", str);
        if (ret != IOTZ_OK)
        {
            return IOTZ_SERVER_REQ_CAVP_ERROR;
        }

        // MMT recv req file
#ifdef _MSC_VER
        sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMMT.req", PREFIX_FILE_PATH, str);
#else
        sprintf(fileName, "%s%sMMT.req", PREFIX_FILE_PATH, str);
#endif
        ret = iotz_recv_test_file(fileName, cSocket);
        print_return_msg(ret, "    [Request CAVP] Recv %sMMT.req file", str);
        if (ret != IOTZ_OK)
        {
            return IOTZ_SERVER_REQ_CAVP_ERROR;
        }
        
        // MCT recv req file
#ifdef _MSC_VER
        sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMCT.req", PREFIX_FILE_PATH, str);
#else
        sprintf(fileName, "%s%sMCT.req", PREFIX_FILE_PATH, str);
#endif
        ret = iotz_recv_test_file(fileName, cSocket);
        print_return_msg(ret, "    [Request CAVP] Recv %sMCT.req file", str);
        if (ret != IOTZ_OK)
        {
            return IOTZ_SERVER_REQ_CAVP_ERROR;
        }
    } else if (code >= IOTZ_SHA_224 && code <= IOTZ_SHA_512) {
        // "Short" recv req file
#ifdef _MSC_VER
        sprintf_s(fileName, FILE_NAME_SIZE, "%s%sShortMsg.req", PREFIX_FILE_PATH, str);
#else
        sprintf(fileName, "%s%sShortMsg.req", PREFIX_FILE_PATH, str);
#endif
        ret = iotz_recv_test_file(fileName, cSocket);
        print_return_msg(ret, "    [Request CAVP] Recv %sShortMsg.req file", str);
        if (ret != IOTZ_OK)
        {
            return IOTZ_SERVER_REQ_CAVP_ERROR;
        }

        // "Long" recv req file
#ifdef _MSC_VER
        sprintf_s(fileName, FILE_NAME_SIZE, "%s%sLongMsg.req", PREFIX_FILE_PATH, str);
#else
        sprintf(fileName, "%s%sLongMsg.req", PREFIX_FILE_PATH, str);
#endif
        ret = iotz_recv_test_file(fileName, cSocket);
        print_return_msg(ret, "    [Request CAVP] Recv %sLongMsg.req file", str);
        if (ret != IOTZ_OK)
        {
            return IOTZ_SERVER_REQ_CAVP_ERROR;
        }

        // "MCT" recv req file
#ifdef _MSC_VER
        sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMonte.req", PREFIX_FILE_PATH, str);
#else
        sprintf(fileName, "%s%sLongMsg.req", PREFIX_FILE_PATH, str);
#endif
        ret = iotz_recv_test_file(fileName, cSocket);
        print_return_msg(ret, "    [Request CAVP] Recv %sMonte.req file", str);
        if (ret != IOTZ_OK)
        {
            return IOTZ_SERVER_REQ_CAVP_ERROR;
        }           
    }


    ret = close_socket(&cSocket);
    if (ret != IOTZ_OK)
    {
        print_return_msg(ret, "    [Request CAVP] Disconnect to server error");

        return IOTZ_DISCONNECT_SERVER_ERROR;
    }

    return IOTZ_OK;
}

IOTZ_RETURN iotz_request_test(IOTZ_CAVP_TEST_CODE code)
{
    IOTZ_CHAR str[FILE_NAME_SIZE] = "";
    IOTZ_BLOCK_CIPHER_TEST_SET bcSet;
    IOTZ_RETURN ret = IOTZ_OK;

    iotz_get_block_cipher_set(code, &bcSet);

#ifdef _MSC_VER
    sprintf_s(str, FILE_NAME_SIZE, "%s", iotz_get_file_name(code));
#else
    sprintf(str, "%s", iotz_get_file_name(code));
#endif

    // KAT generate rsp file
    ret = iotz_gen_rsp_blockcipher_korea_kat_test(str, bcSet.alg, bcSet.keySize, bcSet.mode);
    print_return_msg(ret, "    [Request CAVP] Request %sKAT.rsp file", str);

    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_REQ_TEST_ERROR;
    }

    // MMT generate rsp file
    ret = iotz_gen_rsp_blockcipher_korea_mmt_test(str, bcSet.alg, bcSet.keySize, bcSet.mode);
    print_return_msg(ret, "    [Request CAVP] Request %sMMT.rsp file", str);

    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_REQ_TEST_ERROR;
    }

    // MCT generate rsp file
    ret = iotz_gen_rsp_blockcipher_korea_mct_test(str, bcSet.alg, bcSet.keySize, bcSet.mode);
    print_return_msg(ret, "    [Request CAVP] Request %sMCT.rsp file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_REQ_TEST_ERROR;
    }

    

    return IOTZ_OK;
}



IOTZ_RETURN iotz_request_submit(IOTZ_CAVP_TEST_CODE code)
{
    IOTZ_CHAR str[FILE_NAME_SIZE] = "", fileName[FILE_NAME_SIZE] = "";
    IOTZ_UBYTE buf[IOTZ_SOCKET_BUF_SIZE] = { 0x00, };
    IOTZ_CAVP_FRAME* pFrame = (IOTZ_CAVP_FRAME*)buf;
    IOTZ_SOCKET cSocket;
    IOTZ_RETURN ret = IOTZ_OK;

#ifdef _MSC_VER
    sprintf_s(str, FILE_NAME_SIZE, "%s", iotz_get_file_name(code));
#else
    sprintf(str, "%s", iotz_get_file_name(code));
#endif

    ret = iotz_cavp_server_connect(&cSocket);
    if (ret != IOTZ_OK)
    {
        print_return_msg(ret, "    [Request submit] Connect to server error");

        return IOTZ_CONNECT_SERVER_ERROR;
    }

    pFrame->code = IOTZ_CAVP_REQ_SUBMIT;
    pFrame->data = code;

    send(cSocket, buf, sizeof(IOTZ_CAVP_FRAME), 0);

    // KAT send rsp file
#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sKAT.rsp", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sKAT.rsp", PREFIX_FILE_PATH, str);
#endif
    ret = iotz_send_test_file(fileName, cSocket);
    print_return_msg(ret, "    [Request submit] Send %sKAT.rsp file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }

    // KAT recv result
    if (recv(cSocket, buf, IOTZ_SOCKET_BUF_SIZE, 0) <= 0)
    {
        print_error_msg("    [Request submit] Recv %sKAT result error", str);

        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }

    if ((pFrame->code != IOTZ_CAVP_RES_SUBMIT) || (pFrame->data != IOTZ_CAVP_SUCCESS))
    {
        print_error_msg("    [Request submit] Recv %sKAT result error", str);

        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }
    
    print_return_msg(pFrame->data, "    [Request submit] %sKAT CAVP result", str);

    // MMT send rsp file
#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMMT.rsp", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sMMT.rsp", PREFIX_FILE_PATH, str);
#endif
    ret = iotz_send_test_file(fileName, cSocket);
    print_return_msg(ret, "    [Request submit] Send %sMMT.rsp file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }

    // MMT recv result
    if (recv(cSocket, buf, IOTZ_SOCKET_BUF_SIZE, 0) <= 0)
    {
        print_error_msg("    [Request submit] Recv %sMMT result error", str);

        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }

    if ((pFrame->code != IOTZ_CAVP_RES_SUBMIT) || (pFrame->data != IOTZ_CAVP_SUCCESS))
    {
        print_error_msg("    [Request submit] Recv %sMMT result error", str);

        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }

    print_return_msg(pFrame->data, "    [Request submit] %sMMT CAVP result", str);


    // MCT send rsp file
#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMCT.rsp", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sMCT.rsp", PREFIX_FILE_PATH, str);
#endif
    ret = iotz_send_test_file(fileName, cSocket);
    print_return_msg(ret, "    [Request submit] Send %sMCT.rsp file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }

    // MCT recv result
    if (recv(cSocket, buf, IOTZ_SOCKET_BUF_SIZE, 0) <= 0)
    {
        print_error_msg("    [Request submit] Recv %sMCT result error", str);

        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }

    if ((pFrame->code != IOTZ_CAVP_RES_SUBMIT) || (pFrame->data != IOTZ_CAVP_SUCCESS))
    {
        print_error_msg("    [Request submit] Recv %sMCT result error", str);

        return IOTZ_SERVER_REQ_SUBMIT_ERROR;
    }

    print_return_msg(pFrame->data, "    [Request submit] %sMCT CAVP result", str);

    ret = close_socket(&cSocket);
    if (ret != IOTZ_OK)
    {
        print_return_msg(ret, "    [Request submit] Disconnect to server error");

        return IOTZ_DISCONNECT_SERVER_ERROR;
    }

    return IOTZ_OK;
}
