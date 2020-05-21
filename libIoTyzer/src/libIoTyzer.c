#include <string.h>

#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <libIoTyzer.h>


IOTZ_RETURN initialize_target()
{
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