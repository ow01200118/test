#include <string.h>

#ifndef IOTZ_SOCKET_USE
#define IOTZ_SOCKET_USE
#endif

#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <comm/comm.h>

#include <util/print.h>

#include <libIoTyzer.h>


IOTZ_RETURN initialize_target()
{
    set_print_log_file_path("client");

    // Initialize Crypto Module

    return IOTZ_OK;
}

IOTZ_RETURN iotz_get_iotyzer_dev_info(IOTZ_DEV_INFO *devInfo)
{
    IOTZ_DEV_INFO dev_info = 
    {
        "Kookmin University",
        "IOTYZER-T001",
        "000000001"
    };

    memcpy(devInfo->dev_vender, dev_info.dev_vender, strlen(dev_info.dev_vender));
    memcpy(devInfo->dev_model_num, dev_info.dev_model_num, strlen(dev_info.dev_model_num));
    memcpy(devInfo->dev_serial_num, dev_info.dev_serial_num, strlen(dev_info.dev_serial_num));

    return IOTZ_OK;
}

IOTZ_RETURN	byte_to_short(IOTZ_UDBYTE *dst, const IOTZ_UBYTE *src)
{
	*dst = (src[0] << 8) | (src[1] & 0xFF);

	return IOTZ_OK;
}

IOTZ_RETURN short_to_byte(IOTZ_UBYTE *dst, const IOTZ_UDBYTE src)
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

IOTZ_RETURN get_tlv(IOTZ_UBYTE* buf, IOTZ_UBYTE *tag, IOTZ_UDBYTE *len, IOTZ_UBYTE* value)
{
	IOTZ_UBYTE* pbuf = buf + IOTZ_TARGET_TLV_HEADER_SIZE;
	IOTZ_UDBYTE i = 0;

	*tag = buf[0];
	byte_to_short(len, &buf[1]);

	for (i = 0; i < *len; i++)
		value[i] = pbuf[i];

	return IOTZ_OK;
}

IOTZ_RETURN query_blockcipher_enc(
    IOTZ_UBYTE* out,                                // Byte array(Ciphertext)
    IOTZ_INT* outLen,                               // Length is byte length
    const IOTZ_UBYTE* in,                           // Byte array(Plaintext)
    const IOTZ_INT inLen,                           // Length is byte length
    const IOTZ_UBYTE* iv,                           // Byte array(IV or Nonce for CBC, CFB, OFB, CCM/GCM, if not NULL)
    const IOTZ_INT ivLen,                           // Length is byte length
    const IOTZ_UBYTE* key,                          // Byte array(Key)
    const IOTZ_INT keyLen,                          // Length is bit length, ex) 128, 192, 256
    const IOTZ_BLOCK_CIPHER_MODE_OPERATION mode,    // ECB, CBC, CFB1, CFB8, CFB32, CFB64, CFB128, OFB, CCM, GCM
    const IOTZ_BLOCK_CIPHER_ALG alg                 // ARIA, SEED, LEA
)
{
    IOTZ_UBYTE buf[BUF_SIZE] = { 0x00, }, tag = 0;
    IOTZ_TARGET_FRAME* pFrame = (IOTZ_TARGET_FRAME*)buf;
    IOTZ_TARGET_BLOCK_CIPHER* pInfo = (IOTZ_TARGET_BLOCK_CIPHER*)(buf + IOTZ_TARGET_FRAME_HEADER_SIZE);
    IOTZ_SOCKET tSocket;
    IOTZ_INT offset = IOTZ_TARGET_FRAME_HEADER_SIZE + IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE;

    pFrame->cipher = IOTZ_TARGET_CODE_BLOCK_CIPHER;

    pInfo->alg = (IOTZ_UBYTE)alg;
    pInfo->mode = (IOTZ_UBYTE)mode;
    pInfo->encdec = IOTZ_ENC;

	set_tlv(buf + offset, IOTZ_TAG_KEY, keyLen, key);
    offset += IOTZ_TARGET_TLV_HEADER_SIZE + keyLen;

    if (mode != IOTZ_ECB)
    {
		set_tlv(buf + offset, IOTZ_TAG_IV, ivLen, iv);
		offset += IOTZ_TARGET_TLV_HEADER_SIZE + ivLen;
    }

	set_tlv(buf + offset, IOTZ_TAG_INPUT, inLen, in);
	offset += IOTZ_TARGET_TLV_HEADER_SIZE + inLen;

    pInfo->len = IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE + offset;

    pFrame->len = IOTZ_TARGET_FRAME_HEADER_SIZE + pInfo->len;
    
    connect_target(&tSocket);

    send(tSocket, buf, pFrame->len, 0);

    recv(tSocket, buf, BUF_SIZE, 0);

    if (pFrame->cipher != IOTZ_TARGET_CODE_BLOCK_CIPHER)
    {
        return IOTZ_FRAME_CIPHER_CODE_ERROR;
    }

    if (pInfo->alg != alg)
    {
        return IOTZ_BLOCK_CIPHER_ALGORITHM_ERROR;
    }

    if (pInfo->mode != mode)
    {
        return IOTZ_BLOCK_CIPHER_MODE_ERROR;
    }

    if (pInfo->encdec != IOTZ_ENC)
    {
        return IOTZ_BLOCK_CIPHER_ENCDEC_ERROR;
    }

	offset = IOTZ_TARGET_FRAME_HEADER_SIZE + IOTZ_TARGET_BLOCK_CIPHER_HEADER_SIZE;
	get_tlv(buf + offset, &tag, (IOTZ_UDBYTE *)outLen, out);

	if (tag != IOTZ_TAG_OUTPUT)
		return IOTZ_BLOCK_CIPHER_TAG_ERROR;

    close_local_socket(&tSocket);

    return IOTZ_OK;
}

IOTZ_RETURN query_blockcipher_dec(
    IOTZ_BYTE* out,                                 // Byte array(Plaintext)
    IOTZ_INT* outLen,                               // Length is byte length
    const IOTZ_UBYTE* in,                           // Byte array(Ciphertext)
    const IOTZ_INT inLen,                           // Length is byte length
    const IOTZ_UBYTE* iv,                           // Byte array(IV or Nonce for CBC, CFB, OFB, CCM/GCM, if not NULL)
    const IOTZ_INT ivLen,                           // Length is byte length
    const IOTZ_UBYTE* key,                          // Byte array(Key)
    const IOTZ_INT keyLen,                          // Length is bit length, ex) 128, 192, 256
    const IOTZ_BLOCK_CIPHER_MODE_OPERATION mode,    // ECB, CBC, CFB1, CFB8, CFB32, CFB64, CFB128, OFB, CCM, GCM
    const IOTZ_BLOCK_CIPHER_ALG alg                 // ARIA, SEED, LEA
)
{

    return IOTZ_OK;
}