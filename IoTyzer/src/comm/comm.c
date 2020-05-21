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

#include <comm/comm.h>


IOTZ_RETURN target_local_socket_open(IOTZ_SOCKET* sSocket)
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
        print_error_msg("  Socket wsastartup error[%d]", WSAGetLastError());

        return IOTZ_SOCKET_WSA_ERROR;
    }
#endif

    tmpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (tmpSocket == 0)
    {
#ifdef _MSC_VER
        print_error_msg("  Socket open error[%d]", WSAGetLastError());
#else
        print_error_msg("  Socket open error");
#endif

#ifdef _MSC_VER
        WSACleanup();
#endif

        return IOTZ_SOCKET_OPEN_ERROR;
    }

    memset(&tmpAddr, 0x00, sizeof(tmpAddr));

    tmpAddr.sin_family = PF_INET;
    tmpAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    tmpAddr.sin_port = htons(IOTZ_TARGET_SOCKET_PORT);

    opt = 1;
    if (setsockopt(tmpSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
#ifdef _MSC_VER
        print_error_msg("  Socket REUSEADDR error[%d]", WSAGetLastError());
#else
        print_error_msg("  Socket REUSEADDR error");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 1;
    if (setsockopt(tmpSocket, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
    {
#ifdef _MSC_VER
        print_error_msg("  Socket TCP KEEPALIVE error[%d]", WSAGetLastError());
#else
        print_error_msg("  Socket TCP KEEPALIVE error");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#ifndef _MSC_VER
    opt = 10;
    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPIDLE, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("  Socket TCP KEEPIDLE error");

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 20;

    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPCNT, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("  Socket TCP KEEPCNT error");

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 10;

    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("  Socket TCP KEEPINTVL error");

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#endif

    if (bind(tmpSocket, (IOTZ_SOCKADDR*)& tmpAddr, sizeof(tmpAddr)) != 0)
    {
#ifdef _MSC_VER
        print_error_msg("  Socket bind error[%d]", WSAGetLastError());
#else
        print_error_msg("  Socket bind error");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_BIND_ERROR;
    }

    if (listen(tmpSocket, 5) != 0)
    {
#ifdef _MSC_VER
        print_error_msg("  Socket listen error[%d]", WSAGetLastError());
#else
        print_error_msg("  Socket listen error");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_LISTEN_ERROR;
    }

    *sSocket = tmpSocket;

    print_log("  Server socket open success");

    return IOTZ_OK;
}

IOTZ_RETURN target_accept_client(IOTZ_SOCKET* sSocket, IOTZ_SOCKET* cSocket)
{
    IOTZ_SOCKET tmpSocket;
    IOTZ_SOCKADDR_IN clientAddr;
    // IOTZ_CHAR ipStr[INET_ADDRSTRLEN] = "";
    IOTZ_SOCKLEN len = sizeof(clientAddr);

    tmpSocket = accept(*sSocket, (IOTZ_SOCKADDR*)& clientAddr, &len);

    if (tmpSocket == -1)
    {
#ifdef _MSC_VER
        print_error_msg("  Accept client error[%d]", WSAGetLastError());
#else
        print_error_msg("  Accept client error");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_BIND_ERROR;
    }

    // print_log("  Client info");
    // inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
    // print_log("    Client IP Address : %s", ipStr);
    // print_log("    Client Port : %d", ntohs(clientAddr.sin_port));

    *cSocket = tmpSocket;

    return IOTZ_OK;
}

IOTZ_RETURN connect_target(IOTZ_SOCKET* cSocket)
{
    IOTZ_SOCKET tmpSocket;
    IOTZ_SOCKADDR_IN tmpAddr;
#ifdef _MSC_VER
    LINGER lng = { 1, 0 };
    IOTZ_CHAR opt = 1;
#else
    struct linger lng;
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
    inet_pton(AF_INET, IOTZ_TARGET_IP, &tmpAddr.sin_addr.s_addr);
    tmpAddr.sin_port = htons(IOTZ_CLIENT_SOCKET_PORT);

    opt = 1;
    if (setsockopt(tmpSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket REUSEADDR error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket REUSEADDR error");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

#ifdef _MSC_VER
    if (setsockopt(tmpSocket, SOL_SOCKET, SO_LINGER, (char*)&lng, sizeof(lng)) < 0)
    {
        print_error_msg("    Socket LINGER error[%d]", WSAGetLastError());

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#else
    lng.l_onoff = 1;
    lng.l_linger = 0;

    if (setsockopt(tmpSocket, SOL_SOCKET, SO_LINGER, &lng, sizeof(lng)) < 0)
    {
        print_error_msg("    Socket LINGER error");

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#endif

    opt = 1;
    if (setsockopt(tmpSocket, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket TCP KEEPALIVE fail[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket TCP KEEPALIVE fail");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

#ifndef _MSC_VER
    opt = 10;
    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPIDLE, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPIDLE fail");

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 20;

    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPCNT, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPCNT fail");

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }

    opt = 10;

    if (setsockopt(tmpSocket, SOL_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)) < 0)
    {
        print_error_msg("    Socket TCP KEEPINTVL fail");

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_OPTION_ERROR;
    }
#endif

    if (bind(tmpSocket, (IOTZ_SOCKADDR*)&tmpAddr, sizeof(tmpAddr)) != 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Socket bind error[%d]", WSAGetLastError());
#else
        print_error_msg("    Socket bind error");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_BIND_ERROR;
    }

    tmpAddr.sin_port = htons(IOTZ_TARGET_SOCKET_PORT);

    if (connect(tmpSocket, (IOTZ_SOCKADDR*)& tmpAddr, sizeof(tmpAddr)) != 0)
    {
#ifdef _MSC_VER
        print_error_msg("    Connect to target fail[%d]", WSAGetLastError());
#else
        print_error_msg("    Connect to target fail");
#endif

        close_local_socket(&tmpSocket);

        return IOTZ_SOCKET_CONNECT_ERROR;
    }

    *cSocket = tmpSocket;

    //print_log("    Connect target success");

    return IOTZ_OK;
}

IOTZ_RETURN disconnect_local_socket(IOTZ_SOCKET* socket)
{
#ifdef _MSC_VER
    closesocket(*socket);
#else
    close(*socket);
#endif
    //print_log("    Client Socket closed");

    return IOTZ_OK;
}

IOTZ_RETURN close_local_socket(IOTZ_SOCKET* socket)
{
#ifdef _MSC_VER
    closesocket(*socket);

    WSACleanup();
#else
    close(*socket);
#endif
    //print_log("    Socket closed");

    return IOTZ_OK;
}
