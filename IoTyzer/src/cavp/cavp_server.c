#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <cavp/kor_kat_test.h>
#include <cavp/kor_mmt_test.h>
#include <cavp/kor_mct_test.h>

#include <util/print.h>

#include <cavp/cavp.h>


IOTZ_RETURN iotz_cavp_server_init(IOTZ_SOCKET* sSocket)
{
    IOTZ_SOCKET tmpSocket;
    IOTZ_RETURN ret = IOTZ_OK;

    ret = server_socket_open(&tmpSocket);
    print_return_msg(ret, "  Server socket open");
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_SOCKET_OPEN_ERROR;
    }

    *sSocket = tmpSocket;

    return IOTZ_OK;
}

IOTZ_RETURN iotz_accept_client(IOTZ_SOCKET* sSocket, IOTZ_SOCKET* cSocket)
{
    IOTZ_SOCKET tmpSocket;
    IOTZ_SOCKADDR_IN clientAddr;
    IOTZ_CHAR ipStr[INET_ADDRSTRLEN] = "";
    IOTZ_SOCKLEN len = sizeof(clientAddr);

    tmpSocket = accept(*sSocket, (IOTZ_SOCKADDR*)&clientAddr, &len);

    if (tmpSocket == -1)
    {
#ifdef _MSC_VER
        print_error_msg("  Accept client error[%d]", WSAGetLastError());
#else
        print_error_msg("  Accept client error");
#endif

        close_socket(sSocket);

        return IOTZ_SOCKET_BIND_ERROR;
    }

    print_log("  Client info");
    inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
    print_log("    Client IP Address : %s", ipStr);
    print_log("    Client Port : %d", ntohs(clientAddr.sin_port));

    *cSocket = tmpSocket;

    return IOTZ_OK;
}

IOTZ_RETURN iotz_response_cavp(IOTZ_SOCKET* cSocket, IOTZ_CAVP_TEST_CODE code)
{
    IOTZ_CHAR str[FILE_NAME_SIZE] = "", fileName[FILE_NAME_SIZE] = "";
    IOTZ_BLOCK_CIPHER_TEST_SET bcSet;
    IOTZ_RETURN ret = IOTZ_OK;

    iotz_get_block_cipher_set(code, &bcSet);

#ifdef _MSC_VER
    sprintf_s(str, FILE_NAME_SIZE, "%s", iotz_get_file_name(code));
#else
    sprintf(str, "%s", iotz_get_file_name(code));
#endif

    // KAT generate fax/req file and send req file
    print_msg("    [Response CAVP] Generate %sKAT req/fax file", str);
    iotz_gen_fax_req_blockcipher_korea_kat_test(str, bcSet.alg, bcSet.keySize, bcSet.mode);

#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sKAT.req", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sKAT.req", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_send_test_file(fileName, *cSocket);
    print_return_msg(ret, "    [Response CAVP] Send %sKAT.req file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_RES_CAVP_ERROR;
    }

    // MMT generate fax/req file and send req file
    print_msg("    [Response CAVP] Generate %sMMT req/fax file", str);
    iotz_gen_fax_req_blockcipher_korea_mmt_test(str, bcSet.alg, bcSet.keySize, bcSet.mode);

#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMMT.req", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sMMT.req", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_send_test_file(fileName, *cSocket);
    print_return_msg(ret, "    [Response CAVP] Send %sMMT.req file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_RES_CAVP_ERROR;
    }

    // MCT generate fax/req file and send req file
    print_msg("    [Response CAVP] Generate %sMCT req/fax file", str);
    iotz_gen_fax_req_blockcipher_korea_mct_test(str, bcSet.alg, bcSet.keySize, bcSet.mode);

#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMCT.req", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sMCT.req", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_send_test_file(fileName, *cSocket);
    print_return_msg(ret, "    [Response CAVP] Send %sMCT.req file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_RES_CAVP_ERROR;
    }

    ret = disconnect_client(cSocket);
    if (ret != IOTZ_OK)
    {
        print_return_msg(ret, "    [Response CAVP] Disconnect from client error");

        return IOTZ_DISCONNECT_CLIENT_ERROR;
    }

    return IOTZ_OK;
}

IOTZ_RETURN iotz_response_submit(IOTZ_SOCKET* cSocket, IOTZ_CAVP_TEST_CODE code)
{
    IOTZ_CHAR str[FILE_NAME_SIZE] = "", fileName[FILE_NAME_SIZE] = "";
    IOTZ_UBYTE buf[IOTZ_SOCKET_BUF_SIZE] = { 0x00, };
    IOTZ_CAVP_FRAME* pFrame = (IOTZ_CAVP_FRAME*)buf;
    IOTZ_CHAR file1[FILE_NAME_SIZE] = "", file2[FILE_NAME_SIZE] = "";
    IOTZ_RETURN ret = IOTZ_OK;

#ifdef _MSC_VER
    sprintf_s(str, FILE_NAME_SIZE, "%s", iotz_get_file_name(code));
#else
    sprintf(str, "%s", iotz_get_file_name(code));
#endif

    // KAT recv rsp file
#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sKAT.rsp", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sKAT.rsp", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_recv_test_file(fileName, *cSocket);
    print_return_msg(ret, "    [Response submit] Recv %sKAT.rsp file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_RES_SUBMIT_ERROR;
    }

    // KAT compare rsp/fax file
#ifdef _MSC_VER
    sprintf_s(file1, FILE_NAME_SIZE, "%s%sKAT.rsp", PREFIX_FILE_PATH, str);
    sprintf_s(file2, FILE_NAME_SIZE, "%s%sKAT.fax", PREFIX_FILE_PATH, str);
#else
    sprintf(file1, "%s%sKAT.rsp", PREFIX_FILE_PATH, str);
    sprintf(file2, "%s%sKAT.fax", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_comp_test_file(file1, file2);
    print_return_msg(ret, "    [Response submit] Compare %sKAT rsp/fax file", str);
    if (ret != IOTZ_OK)
    {
        pFrame->code = IOTZ_CAVP_RES_SUBMIT;
        pFrame->data = IOTZ_CAVP_FAILURE;

        send(*cSocket, buf, sizeof(IOTZ_CAVP_FRAME), 0);
    }
    else
    {
        pFrame->code = IOTZ_CAVP_RES_SUBMIT;
        pFrame->data = IOTZ_CAVP_SUCCESS;

        send(*cSocket, buf, sizeof(IOTZ_CAVP_FRAME), 0);
    }

    // MMT recv rsp file
#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMMT.rsp", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sMMT.rsp", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_recv_test_file(fileName, *cSocket);
    print_return_msg(ret, "    [Response submit] Recv %sMMT.rsp file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_RES_SUBMIT_ERROR;
    }

    // MMT compare rsp/fax file
#ifdef _MSC_VER
    sprintf_s(file1, FILE_NAME_SIZE, "%s%sMMT.rsp", PREFIX_FILE_PATH, str);
    sprintf_s(file2, FILE_NAME_SIZE, "%s%sMMT.fax", PREFIX_FILE_PATH, str);
#else
    sprintf(file1, "%s%sMMT.rsp", PREFIX_FILE_PATH, str);
    sprintf(file2, "%s%sMMT.fax", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_comp_test_file(file1, file2);
    print_return_msg(ret, "    [Response submit] Compare %sMMT rsp/fax file", str);
    if (ret != IOTZ_OK)
    {
        pFrame->code = IOTZ_CAVP_RES_SUBMIT;
        pFrame->data = IOTZ_CAVP_FAILURE;

        send(*cSocket, buf, sizeof(IOTZ_CAVP_FRAME), 0);
    }
    else
    {
        pFrame->code = IOTZ_CAVP_RES_SUBMIT;
        pFrame->data = IOTZ_CAVP_SUCCESS;

        send(*cSocket, buf, sizeof(IOTZ_CAVP_FRAME), 0);
    }

    // MCT recv rsp file
#ifdef _MSC_VER
    sprintf_s(fileName, FILE_NAME_SIZE, "%s%sMCT.rsp", PREFIX_FILE_PATH, str);
#else
    sprintf(fileName, "%s%sMCT.rsp", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_recv_test_file(fileName, *cSocket);
    print_return_msg(ret, "    [Response submit] Recv %sMCT.rsp file", str);
    if (ret != IOTZ_OK)
    {
        return IOTZ_SERVER_RES_SUBMIT_ERROR;
    }

    // MCT compare rsp/fax file
#ifdef _MSC_VER
    sprintf_s(file1, FILE_NAME_SIZE, "%s%sMCT.rsp", PREFIX_FILE_PATH, str);
    sprintf_s(file2, FILE_NAME_SIZE, "%s%sMCT.fax", PREFIX_FILE_PATH, str);
#else
    sprintf(file1, "%s%sMCT.rsp", PREFIX_FILE_PATH, str);
    sprintf(file2, "%s%sMCT.fax", PREFIX_FILE_PATH, str);
#endif

    ret = iotz_comp_test_file(file1, file2);
    print_return_msg(ret, "    [Response submit] Compare %sMCT rsp/fax file", str);
    if (ret != IOTZ_OK)
    {
        pFrame->code = IOTZ_CAVP_RES_SUBMIT;
        pFrame->data = IOTZ_CAVP_FAILURE;

        send(*cSocket, buf, sizeof(IOTZ_CAVP_FRAME), 0);
    }
    else
    {
        pFrame->code = IOTZ_CAVP_RES_SUBMIT;
        pFrame->data = IOTZ_CAVP_SUCCESS;

        send(*cSocket, buf, sizeof(IOTZ_CAVP_FRAME), 0);
    }

    ret = disconnect_client(cSocket);
    if (ret != IOTZ_OK)
    {
        print_return_msg(ret, "    [Response submit] Disconnect from client error");

        return IOTZ_DISCONNECT_CLIENT_ERROR;
    }

    return IOTZ_OK;
}

static IOTZ_RETURN iotz_select_service(IOTZ_SOCKET* cSocket)
{
    IOTZ_UBYTE buf[IOTZ_SOCKET_BUF_SIZE] = { 0x00, };
    IOTZ_CAVP_FRAME* pFrame = (IOTZ_CAVP_FRAME*)buf;
    IOTZ_RETURN ret = IOTZ_OK;

    recv(*cSocket, buf, IOTZ_SOCKET_BUF_SIZE, 0);

    switch (pFrame->code)
    {
    case IOTZ_CAVP_REQ_CAVP:
        print_msg("  IoTyzer Server response CAVP");
        ret = iotz_response_cavp(cSocket, (IOTZ_CAVP_TEST_CODE)pFrame->data);
        print_return_msg(ret, "  IoTyzer Server response CAVP");
        break;
    case IOTZ_CAVP_REQ_SUBMIT:
        print_msg("  IoTyzer Server response submit");
        ret = iotz_response_submit(cSocket, (IOTZ_CAVP_TEST_CODE)pFrame->data);
        print_return_msg(ret, "  IoTyzer Server response submit");
        break;
    default:
        break;
    }

    return IOTZ_OK;
}

IOTZ_RETURN iotz_cavp_server_service(IOTZ_SOCKET* lSocket)
{
    IOTZ_SOCKET cSocket;
    IOTZ_RETURN ret = IOTZ_OK;

    while (1)
    {
        print_msg("IoTyzer Server wait client");

        ret = iotz_accept_client(lSocket, &cSocket);
        print_return_msg(ret, "IoTyzer Server accept client");
        if (ret != IOTZ_OK)
        {
            return IOTZ_SERVER_ACCEPT_ERROR;
        }

        iotz_select_service(&cSocket);
    }

    return IOTZ_OK;
}