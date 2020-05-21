#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <socket/socket.h>

#include <util/print.h>

#include <cavp/cavp.h>


IOTZ_CHAR* iotz_get_file_name(IOTZ_CAVP_TEST_CODE code)
{
	switch (code)
	{
	case IOTZ_ARIA_128_ECB:
		return "ARIA128(ECB)";
	case IOTZ_ARIA_128_CBC:
		return "ARIA128(CBC)";
	case IOTZ_ARIA_128_CTR:
		return "ARIA128(CTR)";
	case IOTZ_ARIA_192_ECB:
		return "ARIA192(ECB)";
	case IOTZ_ARIA_192_CBC:
		return "ARIA192(CBC)";
	case IOTZ_ARIA_192_CTR:
		return "ARIA192(CTR)";
	case IOTZ_ARIA_256_ECB:
		return "ARIA256(ECB)";
	case IOTZ_ARIA_256_CBC:
		return "ARIA256(CBC)";
	case IOTZ_ARIA_256_CTR:
		return "ARIA256(CTR)";
	case IOTZ_SEED_ECB:
		return "SEED(ECB)";
	case IOTZ_SEED_CBC:
		return "SEED(CBC)";
	case IOTZ_SEED_CTR:
		return "SEED(CTR)";
	case IOTZ_LEA_128_ECB:
		return "LEA128(ECB)";
	case IOTZ_LEA_128_CBC:
		return "LEA128(CBC)";
	case IOTZ_LEA_128_CTR:
		return "LEA128(CTR)";
	case IOTZ_LEA_192_ECB:
		return "LEA192(ECB)";
	case IOTZ_LEA_192_CBC:
		return "LEA192(CBC)";
	case IOTZ_LEA_192_CTR:
		return "LEA192(CTR)";
	case IOTZ_LEA_256_ECB:
		return "LEA256(ECB)";
	case IOTZ_LEA_256_CBC:
		return "LEA256(CBC)";
	case IOTZ_LEA_256_CTR:
		return "LEA256(CTR)";
	case IOTZ_SHA_224:
		return "SHA2(224)";
	case IOTZ_SHA_256:
		return "SHA2(256)";
	case IOTZ_SHA_384:
		return "SHA2(384)";
	case IOTZ_SHA_512:
		return "SHA2(512)";
	default:
		return NULL;
	}
}

IOTZ_RETURN iotz_get_block_cipher_set(IOTZ_CAVP_TEST_CODE code, IOTZ_BLOCK_CIPHER_TEST_SET *set)
{
	switch (code)
	{
	case IOTZ_ARIA_128_ECB:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_ECB;
		break;
	case IOTZ_ARIA_128_CBC:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_CBC;
		break;
	case IOTZ_ARIA_128_CTR:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_CTR;
		break;
	case IOTZ_ARIA_192_ECB:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_192BIT_KEY;
		set->mode = IOTZ_ECB;
		break;
	case IOTZ_ARIA_192_CBC:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_192BIT_KEY;
		set->mode = IOTZ_CBC;
		break;
	case IOTZ_ARIA_192_CTR:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_192BIT_KEY;
		set->mode = IOTZ_CTR;
		break;
	case IOTZ_ARIA_256_ECB:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_256BIT_KEY;
		set->mode = IOTZ_ECB;
		break;
	case IOTZ_ARIA_256_CBC:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_256BIT_KEY;
		set->mode = IOTZ_CBC;
		break;
	case IOTZ_ARIA_256_CTR:
		set->alg = IOTZ_ARIA;
		set->keySize = IOTZ_256BIT_KEY;
		set->mode = IOTZ_CTR;
		break;
	case IOTZ_SEED_ECB:
		set->alg = IOTZ_SEED;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_ECB;
		break;
	case IOTZ_SEED_CBC:
		set->alg = IOTZ_SEED;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_CBC;
		break;
	case IOTZ_SEED_CTR:
		set->alg = IOTZ_SEED;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_CTR;
		break;
	case IOTZ_LEA_128_ECB:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_ECB;
		break;
	case IOTZ_LEA_128_CBC:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_CBC;
		break;
	case IOTZ_LEA_128_CTR:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_128BIT_KEY;
		set->mode = IOTZ_CTR;
		break;
	case IOTZ_LEA_192_ECB:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_192BIT_KEY;
		set->mode = IOTZ_ECB;
		break;
	case IOTZ_LEA_192_CBC:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_192BIT_KEY;
		set->mode = IOTZ_CBC;
		break;
	case IOTZ_LEA_192_CTR:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_192BIT_KEY;
		set->mode = IOTZ_CTR;
		break;
	case IOTZ_LEA_256_ECB:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_256BIT_KEY;
		set->mode = IOTZ_ECB;
		break;
	case IOTZ_LEA_256_CBC:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_256BIT_KEY;
		set->mode = IOTZ_CBC;
		break;
	case IOTZ_LEA_256_CTR:
		set->alg = IOTZ_LEA;
		set->keySize = IOTZ_256BIT_KEY;
		set->mode = IOTZ_CTR;
		break;
	default:
		set->alg = 0;
		set->keySize = 0;
		set->mode = 0;
		break;
	}

	return IOTZ_OK;
}

IOTZ_RETURN iotz_get_hash_set(IOTZ_CAVP_TEST_CODE code, IOTZ_HASH_TEST_SET *set)
{
	switch (code)
	{
	case IOTZ_SHA_224:
		set->alg = IOTZ_SHA2_224;
	case IOTZ_SHA_256:
		set->alg = IOTZ_SHA2_256;
	case IOTZ_SHA_384:
		set->alg = IOTZ_SHA2_384;
	case IOTZ_SHA_512:
		set->alg = IOTZ_SHA2_512;
	default:
		set->alg = 0;
		break;
	}

	return IOTZ_OK;
}

IOTZ_RETURN iotz_send_test_file(const IOTZ_CHAR* fileName, const IOTZ_SOCKET fSocket)
{
	IOTZ_FILE* fp = NULL;
	IOTZ_RETURN ret = IOTZ_OK;

#ifdef _MSC_VER
	fopen_s(&fp, fileName, "rb");
#else
	fp = fopen(fileName, "rb");
#endif

	if (fp == NULL)
	{
		print_error_msg("    File pointer NULL");

		return IOTZ_FILE_OPEN_ERROR;
	}

#ifdef _MSC_VER
	Sleep(IOTZ_FILE_TRANS_DELAY);
#else
	usleep(IOTZ_FILE_TRANS_DELAY);
#endif

	ret = file_send(fp, fSocket);
	if (ret != IOTZ_OK)
	{
#ifdef _MSC_VER
		print_return_msg(ret, "    File send error[%d]", WSAGetLastError());
#else
		print_return_msg(ret, "    File send error");
#endif

		return IOTZ_FILE_SEND_ERROR;
	}

	fclose(fp);

	return IOTZ_OK;
}

IOTZ_RETURN iotz_recv_test_file(const IOTZ_CHAR* fileName, const IOTZ_SOCKET fSocket)
{
	IOTZ_FILE* fp = NULL;
	IOTZ_RETURN ret = IOTZ_OK;

#ifdef _MSC_VER
	fopen_s(&fp, fileName, "wb");
#else
	fp = fopen(fileName, "wb");
#endif

	if (fp == NULL)
	{
		print_error_msg("    File pointer NULL");

		return IOTZ_FILE_OPEN_ERROR;
	}

	ret = file_recv(fp, fSocket);
	if (ret != IOTZ_OK)
	{
#ifdef _MSC_VER
		print_return_msg(ret, "    File recv error[%d]", WSAGetLastError());
#else
		print_return_msg(ret, "    File recv error");
#endif

		return IOTZ_FILE_RECV_ERROR;
	}

	fclose(fp);

	return IOTZ_OK;
}

IOTZ_RETURN iotz_comp_test_file(const IOTZ_CHAR* fileName1, const IOTZ_CHAR* fileName2)
{
	IOTZ_CHAR buf1[BUF_SIZE] = "", buf2[BUF_SIZE] = "";
	IOTZ_FILE* fp1 = NULL, * fp2 = NULL;

#ifdef _MSC_VER
	fopen_s(&fp1, fileName1, "rt");
	fopen_s(&fp2, fileName2, "rt");
#else
	fp1 = fopen(fileName1, "rt");
	fp2 = fopen(fileName2, "rt");
#endif

	if ((fp1 == NULL) || (fp2 == NULL))
	{
		print_error_msg("    File pointer NULL");

		return IOTZ_FILE_OPEN_ERROR;
	}

	while ((!feof(fp1)) && (!feof(fp2)))
	{
#ifdef _MSC_VER
		if (fscanf_s(fp1, "%s\n", buf1, BUF_SIZE) <= 0)
			return IOTZ_FILE_COMP_ERROR;

		if (fscanf_s(fp2, "%s\n", buf2, BUF_SIZE) <= 0)
			return IOTZ_FILE_COMP_ERROR;
#else
		if (fscanf(fp1, "%s\n", buf1) <= 0)
			return IOTZ_FILE_COMP_ERROR;

		if (fscanf(fp2, "%s\n", buf2) <= 0)
			return IOTZ_FILE_COMP_ERROR;
#endif

		if (strcmp(buf1, buf2))
		{
			print_log("[RSP] %s", buf1);
			print_log("[FAX] %s", buf2);

			return IOTZ_FILE_COMP_ERROR;
		}
	}

	fclose(fp1);
	fclose(fp2);

	return IOTZ_OK;
}
