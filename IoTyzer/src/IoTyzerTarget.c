#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <crypto/mode_of_operate.h>

#include <socket/socket.h>
#include <comm/comm.h>

#include <util/print.h>

#include <IoTyzerTarget.h>


static IOTZ_RETURN service_cmvp();
IOTZ_RETURN do_crypto_module(IOTZ_SOCKET cSocket);
IOTZ_RETURN block_cipher(IOTZ_UBYTE* buf);
IOTZ_RETURN hash(IOTZ_UBYTE* buf);

IOTZ_RETURN main()
{
    set_print_log_file_path("target");

    print_title("IoTyzer Target!");

    service_cmvp();

#ifdef _MSC_VER
    system("pause");
#endif

    return IOTZ_OK;
}

IOTZ_RETURN service_cmvp()
{
    IOTZ_SOCKET tSocket, cSocket;
    IOTZ_SOCKET tmpSocket;
    IOTZ_RETURN ret = IOTZ_OK;

    print_msg("IoTyzer Target open");
    ret = target_local_socket_open(&tSocket);
    print_return_msg(ret, "IoTyzer Target open");
    if (ret != IOTZ_OK)
        return IOTZ_TARGET_OPEN_ERROR;

    while (1)
    {
        ret = target_accept_client(&tSocket, &tmpSocket);
        if (ret != IOTZ_OK)
            return IOTZ_TARGET_ACCEPT_ERROR;

        cSocket = tmpSocket;

        do_crypto_module(cSocket);

        disconnect_local_socket(&cSocket);
    }

    close_local_socket(&tSocket);

    return IOTZ_OK;
}

IOTZ_RETURN do_crypto_module(IOTZ_SOCKET cSocket)
{
    IOTZ_UBYTE buf[IOTZ_SOCKET_BUF_SIZE] = { 0x00, };
    IOTZ_TARGET_FRAME* pFrame = (IOTZ_TARGET_FRAME*)buf;

    recv(cSocket, buf, IOTZ_SOCKET_BUF_SIZE, 0);

    if (pFrame->cipher == IOTZ_TARGET_CODE_BLOCK_CIPHER)
    {
        IOTZ_TARGET_BLOCK_CIPHER* pInfo = (IOTZ_TARGET_BLOCK_CIPHER*)(buf + IOTZ_TARGET_FRAME_HEADER_SIZE);

        block_cipher(buf);

        pFrame->len = IOTZ_TARGET_FRAME_HEADER_SIZE + pInfo->len;
    } else if (pFrame->cipher == IOTZ_TARGET_CODE_HASH) {
        IOTZ_TARGET_HASH* pInfo = (IOTZ_TARGET_HASH*)(buf + IOTZ_TARGET_FRAME_HEADER_SIZE);

        hash(buf);

        pFrame->len = IOTZ_TARGET_FRAME_HEADER_SIZE + pInfo->len;
    }

    send(cSocket, buf, pFrame->len, 0);

    return IOTZ_OK;
}

IOTZ_RETURN	byte_to_short(IOTZ_UDBYTE* dst, const IOTZ_UBYTE* src)
{
	*dst = (src[0] << 8) | (src[1] & 0xFF);

	return IOTZ_OK;
}

IOTZ_RETURN short_to_byte(IOTZ_UBYTE* dst, const IOTZ_UDBYTE src)
{
	dst[0] = src >> 8;
	dst[1] = src & 0x00FF;

	return IOTZ_OK;
}

IOTZ_RETURN set_tlv(IOTZ_UBYTE* buf, IOTZ_UBYTE tag, IOTZ_UDBYTE len, const IOTZ_UBYTE* value)
{
	IOTZ_UBYTE* pbuf = buf + IOTZ_TARGET_TLV_HEADER_SIZE;
	IOTZ_UDBYTE i = 0;

	buf[0] = tag;
	short_to_byte(&buf[1], len);

	for (i = 0; i < len; i++)
		pbuf[i] = value[i];

	return IOTZ_OK;
}

IOTZ_UBYTE* get_tlv(IOTZ_UBYTE* buf, IOTZ_UBYTE* tag, IOTZ_UDBYTE* len)
{
	*tag = buf[0];
	byte_to_short(len, &buf[1]);

	return buf + IOTZ_TARGET_TLV_HEADER_SIZE;
}

IOTZ_RETURN block_cipher(IOTZ_UBYTE *buf)
{
    IOTZ_TARGET_BLOCK_CIPHER* pInfo = (IOTZ_TARGET_BLOCK_CIPHER*)(buf + IOTZ_TARGET_FRAME_HEADER_SIZE);
	IOTZ_UBYTE temp[BUF_SIZE] = { 0x00, };
    IOTZ_UBYTE* pKey = NULL, * pInput = NULL, * pOutput = buf + IOTZ_TARGET_FRAME_HEADER_SIZE + IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE, tag = 0;
    IOTZ_INT keyLen = 0, inLen = 0, outLen = 0;
    IOTZ_INT offset = IOTZ_TARGET_FRAME_HEADER_SIZE + IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE;
	
    if (pInfo->mode == IOTZ_ECB)
    {
		pKey = get_tlv(buf + offset, &tag, (IOTZ_UDBYTE*)&keyLen);
		offset += IOTZ_TARGET_TLV_HEADER_SIZE + keyLen;

        if (tag != IOTZ_TAG_KEY)
        {
			set_tlv(pOutput, IOTZ_TAG_ERROR, 0, NULL);

            pInfo->len = IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE + IOTZ_TARGET_TLV_HEADER_SIZE;

            return IOTZ_TARGET_BLOCKCIPHER_PARAMETER_ERROR;
        }

		pInput = get_tlv(buf + offset, &tag, (IOTZ_UDBYTE*)&inLen);
		offset += IOTZ_TARGET_TLV_HEADER_SIZE + inLen;

        if (tag != IOTZ_TAG_INPUT)
        {
			set_tlv(pOutput, IOTZ_TAG_ERROR, 0, NULL);

            pInfo->len = IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE + IOTZ_TARGET_TLV_HEADER_SIZE;

            return IOTZ_TARGET_BLOCKCIPHER_PARAMETER_ERROR;
        }

        if (pInfo->encdec == IOTZ_ENC)
        {
            blockcipher_ecb_enc(
				temp, &outLen,
                pInput, inLen,
                pKey, keyLen << 3,
                pInfo->alg
            );
        }
        else
        {
            blockcipher_ecb_dec(
				temp, &outLen,
                pInput, inLen,
                pKey, keyLen << 3,
                pInfo->alg
            );
        }

		set_tlv(pOutput, IOTZ_TAG_OUTPUT, outLen, temp);
    }

    pInfo->len = IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE + IOTZ_TARGET_TLV_HEADER_SIZE + outLen;

    return IOTZ_OK;
}

IOTZ_RETURN hash(IOTZ_UBYTE *buf)
{
    IOTZ_TARGET_HASH *info = (IOTZ_TARGET_HASH*)(buf + IOTZ_TARGET_FRAME_HEADER_SIZE);
    IOTZ_UBYTE temp[BUF_SIZE] = {0x00, };
    IOTZ_UBYTE *input = NULL, *output = buf + IOTZ_TARGET_FRAME_HEADER_SIZE + IOTZ_TARGET_HASH_HEADER_SIZE, tag = 0;
    IOTZ_UBYTE key_len = 0, input_len = 0, output_len = 0;
    IOTZ_INT offset = IOTZ_TARGET_FRAME_HEADER_SIZE + IOTZ_TARGET_HASH_HEADER_SIZE;

    input = get_tlv(buf + offset, &tag, (IOTZ_UDBYTE*)&input_len);
    offset += IOTZ_TARGET_TLV_HEADER_SIZE + input_len;

    if (tag != IOTZ_TAG_INPUT) {
        set_tlv(output, IOTZ_TAG_ERROR, 0, NULL);
        info->len = IOTZ_TARGET_HASH_HEADER_SIZE + IOTZ_TARGET_TLV_HEADER_SIZE;

        return IOTZ_TARGET_HASH_PARAMETER_ERROR;
    }

    if (info->alg == IOTZ_SHA2_224)
        sha2(temp, input, input_len, 28);
    else if (info->alg == IOTZ_SHA2_256)
        sha2(temp, input, input_len, 32);
    else if (info->alg == IOTZ_SHA2_384)
        sha2(temp, input, input_len, 48);
    else if (info->alg == IOTZ_SHA2_512)
        sha2(temp, input, input_len, 64);

    set_tlv(output, IOTZ_TAG_OUTPUT, output_len, temp);

    info->len = IOTZ_TARGET_HASH_HEADER_SIZE + IOTZ_TARGET_TLV_HEADER_SIZE + output_len;

    return IOTZ_OK;
}