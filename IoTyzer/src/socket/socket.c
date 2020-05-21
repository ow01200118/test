#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _MSC_VER
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#endif

#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <util/print.h>
#include <socket/socket.h>


typedef struct _IOTZ_FILE_INFO
{
    IOTZ_INT fLen;
} IOTZ_FILE_INFO;

typedef enum _IOTZ_FILE_TRANS_CODE
{
    FILE_TRANS_OK = 0,
    FILE_TRANS_FAIL,
}IOTZ_FILE_TRANS_CODE;


IOTZ_RETURN server_socket_open(IOTZ_SOCKET* sSocket)
{
    IOTZ_SOCKET tmpSocket;
    IOTZ_SOCKADDR_IN tmpAddr;
#ifdef _MSC_VER
    IOTZ_CHAR opt = 1;
#else
    IOTZ_INT opt = 1;
#endif

#ifdef _MSC_VER
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        print_error_msg("    Socket wsastartup error[%d]", WSAGetLastError());

        return IOTZ_SOCKET_WSA_ERROR;
    }
#endif

    tmpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (tmpSocket == 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket open error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket open error");
#endif

#ifdef _MSC_VER
        WSACleanup();
#endif

        return IOTZ_SOCKET_OPEN_ERROR;
    }

    memset(&tmpAddr, 0x00, sizeof(tmpAddr));

    tmpAddr.sin_family = PF_INET;
    tmpAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    tmpAddr.sin_port = htons(IOTYZER_SERVER_PORT);

    opt = 1;
    if (setsockopt(tmpSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket REUSEADDR error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket REUSEADDR error");
#endif

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
    
    opt = 1;
    if (setsockopt(tmpSocket, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket TCP KEEPALIVE error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket TCP KEEPALIVE error");
#endif

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#ifndef _MSC_VER
    opt = 10;
    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPIDLE, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPIDLE error");

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 20;

    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPCNT, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPCNT error");

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 10;

    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPINTVL error");

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#endif
    if (bind(tmpSocket, (IOTZ_SOCKADDR*)& tmpAddr, sizeof(tmpAddr)) != 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket bind error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket bind error");
#endif

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_BIND_ERROR;
    }

    if (listen(tmpSocket, 5) != 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket listen error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket listen error");
#endif

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_LISTEN_ERROR;
    }

    *sSocket = tmpSocket;

    print_log("    Server socket open success");

    return IOTZ_OK;
}

IOTZ_RETURN client_socket_open(IOTZ_SOCKET* cSocket)
{
    IOTZ_SOCKET tmpSocket;
    IOTZ_SOCKADDR_IN tmpAddr;
    IOTZ_CHAR ipStr[INET_ADDRSTRLEN] = "";
#ifdef _MSC_VER
    IOTZ_CHAR opt = 1;
#else
    IOTZ_INT opt = 1;
#endif

#ifdef _MSC_VER
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        print_error_msg("    Socket wsastartup error[%d]", WSAGetLastError());

        return IOTZ_SOCKET_WSA_ERROR;
    }
#endif

    tmpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (tmpSocket == 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket open error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket open error");
#endif

#ifdef _MSC_VER
        WSACleanup();
#endif

        return IOTZ_SOCKET_OPEN_ERROR;
    }

    memset(&tmpAddr, 0x00, sizeof(tmpAddr));

    tmpAddr.sin_family = PF_INET;
    inet_pton(AF_INET, IOTYZER_SERVER_IP, &tmpAddr.sin_addr.s_addr);
    tmpAddr.sin_port = htons(IOTYZER_SERVER_PORT);

    opt = 1;
    if (setsockopt(tmpSocket, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket TCP KEEPALIVE fail[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket TCP KEEPALIVE fail");
#endif

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#ifndef _MSC_VER
    opt = 10;
    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPIDLE, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPIDLE fail");

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 20;

    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPCNT, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPCNT fail");

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 10;

    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPINTVL fail");

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#endif
    if (connect(tmpSocket, (IOTZ_SOCKADDR*)&tmpAddr, sizeof(tmpAddr)) != 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Connect to server fail[%d]", WSAGetLastError());
#else
        print_error_msg("    Connect to server fail");
#endif

        close_socket(&tmpSocket);

        return IOTZ_SOCKET_CONNECT_ERROR;
    }

    print_log("  Server info");
    inet_ntop(AF_INET, &tmpAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
    print_log("    Server IP Address : %s", ipStr);
    print_log("    Server Port : %d", ntohs(tmpAddr.sin_port));

    *cSocket = tmpSocket;

    print_log("    Connect server success");

    return IOTZ_OK;
}

IOTZ_RETURN file_send(IOTZ_FILE* fp, const IOTZ_SOCKET fSocket)
{
    IOTZ_UBYTE buf[IOTZ_SOCKET_BUF_SIZE] = { 0x00, };
    IOTZ_FILE_INFO* fInfo = (IOTZ_FILE_INFO*)buf;
    IOTZ_INT fSize = 0, len = 0, total = 0;

    if (fp == NULL)
    {
        print_error_msg("    Socket file pointer NULL");

        return IOTZ_SOCKET_FILE_OPEN_ERROR;
    }

    fseek(fp, 0, SEEK_END);
    fSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    len += sizeof(IOTZ_INT);
    fInfo->fLen = fSize;

    if (send(fSocket, buf, len, 0) != len)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket file send error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket file send error");
#endif

        return IOTZ_SOCKET_FILE_SEND_FAILURE;
    }

    while ((len = (IOTZ_INT)fread(buf, sizeof(IOTZ_UBYTE), BUF_SIZE, fp)) > 0)
    {   
        if (send(fSocket, buf, len, 0) != len)
        {
#ifdef _MSC_VER
            print_error_msg("    Socket file send error[%d]", WSAGetLastError());
#else
            print_error_msg("    Socket file send error");
#endif

            return IOTZ_SOCKET_FILE_SEND_FAILURE;
        }

        memset(buf, 0, IOTZ_SOCKET_BUF_SIZE);

        total += len;

        print_process(total, fSize);
    }

    if (recv(fSocket, buf, IOTZ_SOCKET_BUF_SIZE, 0) <= 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket file ACK error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket file ACK error");
#endif

        return IOTZ_SOCKET_FILE_SEND_FAILURE;
    }

    if (buf[0] != FILE_TRANS_OK)
        return IOTZ_SOCKET_FILE_SEND_FAILURE;
    else
        return IOTZ_OK;
}

IOTZ_RETURN file_recv(IOTZ_FILE* fp, const IOTZ_SOCKET fSocket)
{
    IOTZ_UBYTE buf[IOTZ_SOCKET_BUF_SIZE] = { 0x00, };
    IOTZ_FILE_INFO* fInfo = (IOTZ_FILE_INFO*)buf;
    IOTZ_INT fSize = 0, len = 0, total = 0;

    if (fp == NULL)
    {
        print_error_msg("    Socket file pointer NULL");

        return IOTZ_SOCKET_FILE_OPEN_ERROR;
    }

    if (recv(fSocket, buf, IOTZ_SOCKET_BUF_SIZE, 0) <= 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket file Info error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket file Info error");
#endif

        return IOTZ_SOCKET_FILE_RECV_FAILURE;
    }

    fSize = fInfo->fLen;

    while (total < fSize)
    {
        memset(buf, 0, IOTZ_SOCKET_BUF_SIZE);

        len = recv(fSocket, buf, IOTZ_SOCKET_BUF_SIZE, 0);
        if (len <= 0)
        {
#ifdef _MSC_VER
            print_error_msg("    Socket file Info error[%d]", WSAGetLastError());
#else
            print_error_msg("    Socket file Info error");
#endif

            return IOTZ_SOCKET_FILE_RECV_FAILURE;
        }

        fwrite(buf, sizeof(IOTZ_UBYTE), len, fp);

        total += len;

        print_process(total, fSize);
    }

    buf[0] = FILE_TRANS_OK;
    if (send(fSocket, buf, sizeof(IOTZ_UBYTE), 0) != sizeof(IOTZ_UBYTE))
    {
#ifdef _MSC_VER
        print_error_msg("    Socket ACK send error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket ACK send error");
#endif

        return IOTZ_SOCKET_FILE_SEND_FAILURE;
    }

    return IOTZ_OK;
}

IOTZ_RETURN disconnect_client(IOTZ_SOCKET *socket)
{
#ifdef _MSC_VER
    closesocket(*socket);
#else
    close(*socket);
#endif
    print_log("    Client Socket closed");

    return IOTZ_OK;
}

IOTZ_RETURN close_socket(IOTZ_SOCKET* socket)
{
#ifdef _MSC_VER
    closesocket(*socket);

    WSACleanup();
#else
    close(*socket);
#endif
    print_log("    Socket closed");

    return IOTZ_OK;
}
