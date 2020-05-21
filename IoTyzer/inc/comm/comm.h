#ifndef _IOTZ_COMM_H_
#define _IOTZ_COMM_H_


#include <socket/socket.h>


#define IOTZ_TARGET_IP     "127.0.0.1"
#define IOTZ_TARGET_SOCKET_PORT   9010
#define IOTZ_CLIENT_SOCKET_PORT   9020

#define IOTZ_TARGET_FRAME_HEADER_SIZE           4
#define IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE    4
#define IOTZ_TARGET_HASH_HEADER_SIZE			3
#define IOTZ_TARGET_TLV_HEADER_SIZE             3


typedef struct _IOTZ_TARGET_FRAME
{
	IOTZ_UDBYTE cipher;
    IOTZ_UDBYTE len;
}IOTZ_TARGET_FRAME;

typedef struct _IOTZ_TARGET_BLOCK_CIPHER
{
	IOTZ_UBYTE alg;
	IOTZ_UBYTE mode : 7;
	IOTZ_UBYTE encdec : 1;
	IOTZ_UDBYTE len;
} IOTZ_TARGET_BLOCK_CIPHER;

typedef struct _IOTZ_TARGET_HASH
{
	IOTZ_UBYTE alg;
	IOTZ_UDBYTE len;
} IOTZ_TARGET_HASH;

typedef struct _IOTZ_TARGET_TLV
{
    IOTZ_UBYTE tag;
	IOTZ_UDBYTE len;
}IOTZ_TARGET_TLV;

typedef enum _IOTZ_TARGET_CIPHER_CODE
{
	IOTZ_TARGET_CODE_BLOCK_CIPHER = 0,
	IOTZ_TARGET_CODE_HASH,
	IOTZ_TARGET_CODE_RSA,
	IOTZ_TARGET_CODE_ECC,
}_IOTZ_TARGET_CIPHER_CODE;

typedef enum _IOTZ_TARGET_TLV_TAG
{
    IOTZ_TAG_KEY = 1,
    IOTZ_TAG_IV,
    IOTZ_TAG_INPUT,
    IOTZ_TAG_OUTPUT,
    IOTZ_TAG_ERROR = 0xFF
}IOTZ_TARGET_TLV_TAG;


IOTZ_RETURN target_local_socket_open(IOTZ_SOCKET* sSocket);
IOTZ_RETURN target_accept_client(IOTZ_SOCKET* sSocket, IOTZ_SOCKET* cSocket);
IOTZ_RETURN connect_target(IOTZ_SOCKET* cSocket);
IOTZ_RETURN disconnect_local_socket(IOTZ_SOCKET* socket);
IOTZ_RETURN close_local_socket(IOTZ_SOCKET* socket);



#else

#endif
