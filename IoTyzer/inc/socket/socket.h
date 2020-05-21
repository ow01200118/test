#ifndef _IOTZ_SOCKET_H_
#define _IOTZ_SOCKET_H_


#ifdef _MSC_VER
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif


#define IOTZ_SOCKET_WSA_ERROR			1
#define IOTZ_SOCKET_OPEN_ERROR			2
#define IOTZ_SOCKET_OPTION_ERROR		3
#define IOTZ_SOCKET_BIND_ERROR			4
#define IOTZ_SOCKET_LISTEN_ERROR		5
#define IOTZ_SOCKET_ACCEPT_ERROR		6
#define IOTZ_SOCKET_CONNECT_ERROR		7
#define IOTZ_SOCKET_FILE_OPEN_ERROR		8
#define IOTZ_SOCKET_FILE_SEND_FAILURE	8
#define IOTZ_SOCKET_FILE_RECV_FAILURE	8

#define IOTZ_SOCKET_BUF_SIZE			5 * 1460

#if !defined(INET_ADDRSTRLEN)
#define INET_ADDRSTRLEN             22
#endif


#ifdef _MSC_VER
typedef SOCKET              IOTZ_SOCKET;
#else
typedef int                 IOTZ_SOCKET;
#endif
typedef socklen_t           IOTZ_SOCKLEN;

typedef struct sockaddr_in  IOTZ_SOCKADDR_IN;
typedef struct sockaddr     IOTZ_SOCKADDR;


IOTZ_RETURN server_socket_open(IOTZ_SOCKET* sSocket);
IOTZ_RETURN client_socket_open(IOTZ_SOCKET* cSocket);

IOTZ_RETURN file_send(IOTZ_FILE* fp, const IOTZ_SOCKET fSocket);
IOTZ_RETURN file_recv(IOTZ_FILE* fp, const IOTZ_SOCKET fSocket);

IOTZ_RETURN disconnect_client(IOTZ_SOCKET* socket);
IOTZ_RETURN close_socket(IOTZ_SOCKET* socket);



#else

#endif
